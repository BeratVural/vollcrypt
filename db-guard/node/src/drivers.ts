import { encryptValue, decryptValue } from './prisma.js';
import { decryptWithSecurity, registerKeysForZeroization, RateLimiterOptions } from './security.js';

export interface DbGuardDriverOptions {
  key: Buffer | Record<string, Buffer>;
  activeKeyVersion?: string;
  entities: Record<string, string[]>; // table/entity -> encrypted columns
  cryptoRbac?: {
    roles: Record<string, {
      decrypt: string[];
      mask?: Record<string, 'credit_card' | 'email' | 'tc_no' | ((v: any) => any) | string>;
    }>;
  };
  rateLimiter?: RateLimiterOptions;
}

function getKeys(options: DbGuardDriverOptions) {
  let keys: Record<string, Buffer>;
  let activeVersion: string;

  if (Buffer.isBuffer(options.key)) {
    keys = { '1': options.key };
    activeVersion = '1';
  } else {
    keys = options.key;
    activeVersion = options.activeKeyVersion || Object.keys(keys)[0];
  }

  return { keys, activeVersion };
}

function getParamColumns(sql: string): { table: string; columns: string[] } | null {
  const sqlClean = sql.replace(/\s+/g, ' ').trim();
  
  // Match INSERT INTO table (col1, col2) ...
  const insertMatch = sqlClean.match(/INSERT\s+INTO\s+(\w+)\s*\(([^)]+)\)/i);
  if (insertMatch) {
    const table = insertMatch[1];
    const columns = insertMatch[2].split(',').map(c => c.trim());
    return { table, columns };
  }
  
  // Match UPDATE table SET col1 = ?, col2 = ? ...
  const updateMatch = sqlClean.match(/UPDATE\s+(\w+)\s+SET\s+([\s\S]+?)(?:\s+WHERE|$)/i);
  if (updateMatch) {
    const table = updateMatch[1];
    const setParts = updateMatch[2].split(',');
    const columns: string[] = [];
    for (const part of setParts) {
      const match = part.match(/(\w+)\s*=/);
      if (match) {
        columns.push(match[1]);
      }
    }
    return { table, columns };
  }
  
  return null;
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
          } catch {
            // Keep original on failure
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
          } catch {
            // Keep original on failure
          }
        }
      }
    }
    return cloned;
  }
  return row;
}

export function wrapSqliteDatabase(db: any, options: DbGuardDriverOptions): any {
  const { keys, activeVersion } = getKeys(options);
  const activeKey = keys[activeVersion];
  registerKeysForZeroization(keys);

  const originalPrepare = db.prepare;
  db.prepare = function (sql: string, ...args: any[]) {
    const statement = originalPrepare.call(this, sql, ...args);
    const parsed = getParamColumns(sql);

    // Helper to encrypt query input parameters
    const encryptParams = (params: any[]) => {
      if (!parsed) return params;
      const table = parsed.table;
      const columns = parsed.columns;
      const fieldsToEncrypt = options.entities[table] || [];
      if (fieldsToEncrypt.length === 0) return params;

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

export function wrapOracleConnection(connection: any, options: DbGuardDriverOptions): any {
  const { keys, activeVersion } = getKeys(options);
  const activeKey = keys[activeVersion];
  registerKeysForZeroization(keys);

  const originalExecute = connection.execute;
  connection.execute = async function (sql: string, bindParams: any = {}, execOptions: any = {}, ...args: any[]) {
    const parsed = getParamColumns(sql);
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
