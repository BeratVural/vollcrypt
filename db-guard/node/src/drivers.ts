import { dbGuardError } from './errors';
import { decryptWithSecurity, registerKeysForZeroization, encryptValue, decryptValue } from './security';
import { normalizeKeys } from './keys';
import type { CommonDbGuardSecurityOptions } from './contract';

export interface DbGuardDriverOptions extends CommonDbGuardSecurityOptions {
  key: Buffer | Record<string, Buffer>;
  activeKeyVersion?: string;
  entities: Record<string, string[]>; // table/entity -> encrypted columns
}

function cleanIdentifier(identifier: string): string {
  if (!identifier) return identifier;
  let cleaned = identifier.trim();
  if (
    (cleaned.startsWith('"') && cleaned.endsWith('"')) ||
    (cleaned.startsWith('`') && cleaned.endsWith('`')) ||
    (cleaned.startsWith('[') && cleaned.endsWith(']'))
  ) {
    cleaned = cleaned.slice(1, -1);
  }
  return cleaned.trim();
}

function getParamColumns(sql: string): { table: string; columns: string[]; assignments?: Record<string, string> } | null {
  const sqlClean = sql.replace(/\s+/g, ' ').trim();
  
  // Match INSERT INTO table (col1, col2) VALUES (?, ?) ...
  const insertMatch = sqlClean.match(/INSERT\s+INTO\s+([a-zA-Z0-9_"`[\]]+)\s*\(([^)]+)\)(?:\s+VALUES\s*\(([^)]*)\))?/i);
  if (insertMatch) {
    const table = cleanIdentifier(insertMatch[1]);
    const columns = insertMatch[2].split(',').map(c => cleanIdentifier(c));
    const assignments: Record<string, string> = {};
    if (insertMatch[3] !== undefined) {
      const values = insertMatch[3].split(',').map(v => v.trim());
      columns.forEach((column, index) => {
        if (values[index] !== undefined) {
          assignments[column] = values[index];
        }
      });
    }
    return { table, columns, assignments };
  }
  
  // Match UPDATE table SET col1 = ?, col2 = ? ...
  const updateMatch = sqlClean.match(/UPDATE\s+([a-zA-Z0-9_"`[\]]+)\s+SET\s+([\s\S]+?)(?:\s+WHERE|$)/i);
  if (updateMatch) {
    const table = cleanIdentifier(updateMatch[1]);
    const setParts = updateMatch[2].split(',');
    const columns: string[] = [];
    const assignments: Record<string, string> = {};
    for (const part of setParts) {
      const match = part.match(/([a-zA-Z0-9_"`[\]]+)\s*=\s*([\s\S]+)/);
      if (match) {
        const col = cleanIdentifier(match[1]);
        columns.push(col);
        assignments[col] = match[2].trim();
      }
    }
    return { table, columns, assignments };
  }
  
  return null;
}

function hasEncryptedTargets(options: DbGuardDriverOptions): boolean {
  return Object.values(options.entities).some(fields => fields.length > 0);
}

function isSqlParameterExpression(expr: string | undefined): boolean {
  if (!expr) return false;
  return /^(\?|\$\d+|[:@$][a-zA-Z0-9_]+)$/i.test(expr.trim());
}

function assertEncryptedWritesUseParameters(
  sql: string,
  parsed: { table: string; columns: string[]; assignments?: Record<string, string> } | null,
  options: DbGuardDriverOptions
): void {
  if (!parsed || !/\b(insert|update)\b/i.test(sql)) return;
  const fieldsToEncrypt = options.entities[parsed.table] || [];
  if (fieldsToEncrypt.length === 0) return;

  if (parsed.assignments) {
    for (const field of fieldsToEncrypt) {
      if (parsed.assignments[field] !== undefined && !isSqlParameterExpression(parsed.assignments[field])) {
        throw dbGuardError(`Vollcrypt DbGuard: encrypted field ${parsed.table}.${field} must be written using a bind parameter, not a SQL literal or expression.`);
      }
    }
  }
}

function decryptRow(
  row: any,
  table: string,
  keys: Record<string, Buffer>,
  options: DbGuardDriverOptions
): any {
  if (!row) return row;

  if (typeof row === 'object') {
    const cloned = Array.isArray(row) ? [...row] : { ...row };
    
    if (Array.isArray(row)) {
      // Array format (index-based)
      for (let i = 0; i < row.length; i++) {
        const val = row[i];
        if (typeof val === 'string' && val.startsWith('VOLLVALT:')) {
          try {
            cloned[i] = decryptWithSecurity(
              val,
              (v) => decryptValue(v, keys),
              table,
              `column_${i}`,
              undefined,
              options
            );
          } catch (err) {
            throw err;
          }
        }
      }
    } else {
      // Object format (key-value)
      const fields = options.entities[table] || [];
      for (const [key, val] of Object.entries(row)) {
        if (typeof val === 'string' && val.startsWith('VOLLVALT:')) {
          try {
            cloned[key] = decryptWithSecurity(
              val,
              (v) => decryptValue(v, keys),
              table,
              key,
              row.id || row._id,
              options
            );
          } catch (err) {
            throw err;
          }
        }
      }
    }
    return cloned;
  }
  return row;
}

/**
 * Wraps a SQLite-compatible database and enforces parameterized encrypted writes.
 */
export function wrapSqliteDatabase(db: any, options: DbGuardDriverOptions): any {
  const { keys, activeVersion, activeKey } = normalizeKeys(options.key, options.activeKeyVersion);
  registerKeysForZeroization(keys);

  const originalPrepare = db.prepare;
  db.prepare = function (sql: string, ...args: any[]) {
    const statement = originalPrepare.call(this, sql, ...args);
    const parsed = getParamColumns(sql);
    if (!parsed && hasEncryptedTargets(options) && /\b(insert|update)\b/i.test(sql)) {
      throw dbGuardError('Vollcrypt DbGuard: SQL write statement could not be parsed for encrypted fields. Refusing plaintext write.');
    }
    assertEncryptedWritesUseParameters(sql, parsed, options);

    // Helper to encrypt query input parameters
    const encryptParams = (params: any[]) => {
      if (!parsed) return params;
      const table = parsed.table;
      const columns = parsed.columns;
      const fieldsToEncrypt = options.entities[table] || [];
      if (fieldsToEncrypt.length === 0) return params;

      // Case 1: single array parameter, e.g., stmt.run([val1, val2])
      if (params.length === 1 && Array.isArray(params[0])) {
        const arrayParams = params[0].map((param, index) => {
          const colName = columns[index];
          if (colName && fieldsToEncrypt.includes(colName)) {
            return encryptValue(param, activeKey, activeVersion);
          }
          return param;
        });
        return [arrayParams];
      }

      // Case 2: single object parameter for named binds, e.g., stmt.run({ col1: val1 })
      if (params.length === 1 && params[0] && typeof params[0] === 'object' && !Buffer.isBuffer(params[0])) {
        const obj = { ...params[0] };
        for (const [key, val] of Object.entries(obj)) {
          // Strip prefix character (@, :, $) if present
          const cleanKey = key.replace(/^[@:$]/, '');
          if (fieldsToEncrypt.includes(cleanKey)) {
            obj[key] = encryptValue(val, activeKey, activeVersion);
          }
        }
        return [obj];
      }

      // Case 3: multiple positional parameters, e.g., stmt.run(val1, val2)
      return params.map((param, index) => {
        const colName = columns[index];
        if (colName && fieldsToEncrypt.includes(colName)) {
          return encryptValue(param, activeKey, activeVersion);
        }
        return param;
      });
    };

    const wrapStatementMethod = (originalMethod: Function) => {
      return function (...params: any[]) {
        const processedParams = encryptParams(params);
        const result = originalMethod.apply(statement, processedParams);

        if (parsed) {
          const table = parsed.table;
          if (Array.isArray(result)) {
            return result.map(row => decryptRow(row, table, keys, options));
          } else if (result) {
            return decryptRow(result, table, keys, options);
          }
        } else {
          // If query SQL parsing was skipped (e.g. SELECT *), decrypt rows generically
          // using first table configured in options as fallback
          const defaultTable = Object.keys(options.entities)[0] || 'Model';
          if (Array.isArray(result)) {
            return result.map(row => decryptRow(row, defaultTable, keys, options));
          } else if (result) {
            return decryptRow(result, defaultTable, keys, options);
          }
        }

        return result;
      };
    };

    statement.run = wrapStatementMethod(statement.run);
    statement.get = wrapStatementMethod(statement.get);
    statement.all = wrapStatementMethod(statement.all);

    return statement;
  };

  return db;
}

/**
 * Wraps an Oracle connection and encrypts configured bind values before execution.
 */
export function wrapOracleConnection(connection: any, options: DbGuardDriverOptions): any {
  const { keys, activeVersion, activeKey } = normalizeKeys(options.key, options.activeKeyVersion);
  registerKeysForZeroization(keys);

  const originalExecute = connection.execute;
  connection.execute = async function (sql: string, bindParams: any = {}, execOptions: any = {}, ...args: any[]) {
    const parsed = getParamColumns(sql);
    if (!parsed && hasEncryptedTargets(options) && /\b(insert|update)\b/i.test(sql)) {
      throw dbGuardError('Vollcrypt DbGuard: SQL write statement could not be parsed for encrypted fields. Refusing plaintext write.');
    }
    assertEncryptedWritesUseParameters(sql, parsed, options);
    let processedBinds = bindParams;

    if (parsed) {
      const table = parsed.table;
      const columns = parsed.columns;
      const fieldsToEncrypt = options.entities[table] || [];

      if (fieldsToEncrypt.length > 0) {
        if (Array.isArray(bindParams)) {
          processedBinds = bindParams.map((param, index) => {
            const colName = columns[index];
            if (colName && fieldsToEncrypt.includes(colName)) {
              return encryptValue(param, activeKey, activeVersion);
            }
            return param;
          });
        } else if (bindParams && typeof bindParams === 'object') {
          processedBinds = { ...bindParams };
          for (const field of fieldsToEncrypt) {
            if (processedBinds[field] !== undefined && processedBinds[field] !== null) {
              processedBinds[field] = encryptValue(processedBinds[field], activeKey, activeVersion);
            }
          }
        }
      }
    }

    const result = await originalExecute.call(this, sql, processedBinds, execOptions, ...args);

    if (result && result.rows) {
      const targetTable = parsed ? parsed.table : (Object.keys(options.entities)[0] || 'Model');
      result.rows = result.rows.map((row: any) => decryptRow(row, targetTable, keys, options));
    }

    return result;
  };

  return connection;
}
