"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.wrapSqliteDatabase = wrapSqliteDatabase;
exports.wrapOracleConnection = wrapOracleConnection;
const prisma_js_1 = require("./prisma.js");
const security_js_1 = require("./security.js");
function getKeys(options) {
    let keys;
    let activeVersion;
    if (Buffer.isBuffer(options.key)) {
        keys = { '1': options.key };
        activeVersion = '1';
    }
    else {
        keys = options.key;
        activeVersion = options.activeKeyVersion || Object.keys(keys)[0];
    }
    return { keys, activeVersion };
}
function getParamColumns(sql) {
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
        const columns = [];
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
function decryptRow(row, table, keys, options) {
    if (!row)
        return row;
    if (typeof row === 'object') {
        const cloned = Array.isArray(row) ? [...row] : { ...row };
        if (Array.isArray(row)) {
            // Array format (index-based)
            for (let i = 0; i < row.length; i++) {
                const val = row[i];
                if (typeof val === 'string' && val.startsWith('VOLLVALT:')) {
                    try {
                        cloned[i] = (0, security_js_1.decryptWithSecurity)(val, (v) => (0, prisma_js_1.decryptValue)(v, keys), table, `column_${i}`, undefined, options);
                    }
                    catch {
                        // Keep original on failure
                    }
                }
            }
        }
        else {
            // Object format (key-value)
            const fields = options.entities[table] || [];
            for (const [key, val] of Object.entries(row)) {
                if (typeof val === 'string' && val.startsWith('VOLLVALT:')) {
                    try {
                        cloned[key] = (0, security_js_1.decryptWithSecurity)(val, (v) => (0, prisma_js_1.decryptValue)(v, keys), table, key, row.id || row._id, options);
                    }
                    catch {
                        // Keep original on failure
                    }
                }
            }
        }
        return cloned;
    }
    return row;
}
function wrapSqliteDatabase(db, options) {
    const { keys, activeVersion } = getKeys(options);
    const activeKey = keys[activeVersion];
    (0, security_js_1.registerKeysForZeroization)(keys);
    const originalPrepare = db.prepare;
    db.prepare = function (sql, ...args) {
        const statement = originalPrepare.call(this, sql, ...args);
        const parsed = getParamColumns(sql);
        // Helper to encrypt query input parameters
        const encryptParams = (params) => {
            if (!parsed)
                return params;
            const table = parsed.table;
            const columns = parsed.columns;
            const fieldsToEncrypt = options.entities[table] || [];
            if (fieldsToEncrypt.length === 0)
                return params;
            return params.map((param, index) => {
                const colName = columns[index];
                if (colName && fieldsToEncrypt.includes(colName)) {
                    return (0, prisma_js_1.encryptValue)(param, activeKey, activeVersion);
                }
                return param;
            });
        };
        const wrapStatementMethod = (originalMethod) => {
            return function (...params) {
                const processedParams = encryptParams(params);
                const result = originalMethod.apply(statement, processedParams);
                if (parsed) {
                    const table = parsed.table;
                    if (Array.isArray(result)) {
                        return result.map(row => decryptRow(row, table, keys, options));
                    }
                    else if (result) {
                        return decryptRow(result, table, keys, options);
                    }
                }
                else {
                    // If query SQL parsing was skipped (e.g. SELECT *), decrypt rows generically
                    // using first table configured in options as fallback
                    const defaultTable = Object.keys(options.entities)[0] || 'Model';
                    if (Array.isArray(result)) {
                        return result.map(row => decryptRow(row, defaultTable, keys, options));
                    }
                    else if (result) {
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
function wrapOracleConnection(connection, options) {
    const { keys, activeVersion } = getKeys(options);
    const activeKey = keys[activeVersion];
    (0, security_js_1.registerKeysForZeroization)(keys);
    const originalExecute = connection.execute;
    connection.execute = async function (sql, bindParams = {}, execOptions = {}, ...args) {
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
                            return (0, prisma_js_1.encryptValue)(param, activeKey, activeVersion);
                        }
                        return param;
                    });
                }
                else if (bindParams && typeof bindParams === 'object') {
                    processedBinds = { ...bindParams };
                    for (const field of fieldsToEncrypt) {
                        if (processedBinds[field] !== undefined && processedBinds[field] !== null) {
                            processedBinds[field] = (0, prisma_js_1.encryptValue)(processedBinds[field], activeKey, activeVersion);
                        }
                    }
                }
            }
        }
        const result = await originalExecute.call(this, sql, processedBinds, execOptions, ...args);
        if (result && result.rows) {
            const targetTable = parsed ? parsed.table : (Object.keys(options.entities)[0] || 'Model');
            result.rows = result.rows.map((row) => decryptRow(row, targetTable, keys, options));
        }
        return result;
    };
    return connection;
}
