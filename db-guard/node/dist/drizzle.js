"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createDrizzleGuard = void 0;
const errors_1 = require("./errors");
const security_1 = require("./security");
const keys_1 = require("./keys");
/**
 * Creates encrypted and blind-index Drizzle custom column types for supported SQL dialects.
 */
const createDrizzleGuard = (options) => {
    if (options.blindIndexes) {
        (0, security_1.validateBlindIndexConfiguration)(options.blindIndexes.rootSalt, options.blindIndexes.allowFrequencyLeakage);
    }
    const pgCustomType = require('drizzle-orm/pg-core').customType;
    const mysqlCustomType = require('drizzle-orm/mysql-core').customType;
    const sqliteCustomType = require('drizzle-orm/sqlite-core').customType;
    const { keys, activeVersion, activeKey } = (0, keys_1.normalizeKeys)(options.key, options.activeKeyVersion);
    (0, security_1.registerKeysForZeroization)(keys);
    const rootSalt = options.blindIndexes?.rootSalt;
    return {
        pgText: (name, columnPath) => pgCustomType({
            dataType() {
                return 'text';
            },
            toDriver(value) {
                return (0, security_1.encryptValue)(value, activeKey, activeVersion);
            },
            fromDriver(value) {
                const parts = columnPath?.split('.') || [name];
                const mName = parts[0] || 'Model';
                const fName = parts[1] || name;
                return (0, security_1.decryptWithSecurity)(value, (val) => (0, security_1.decryptValue)(val, keys), mName, fName, undefined, options);
            }
        })(name),
        mysqlText: (name, columnPath) => mysqlCustomType({
            dataType() {
                return 'text';
            },
            toDriver(value) {
                return (0, security_1.encryptValue)(value, activeKey, activeVersion);
            },
            fromDriver(value) {
                const parts = columnPath?.split('.') || [name];
                const mName = parts[0] || 'Model';
                const fName = parts[1] || name;
                return (0, security_1.decryptWithSecurity)(value, (val) => (0, security_1.decryptValue)(val, keys), mName, fName, undefined, options);
            }
        })(name),
        sqliteText: (name, columnPath) => sqliteCustomType({
            dataType() {
                return 'text';
            },
            toDriver(value) {
                return (0, security_1.encryptValue)(value, activeKey, activeVersion);
            },
            fromDriver(value) {
                const parts = columnPath?.split('.') || [name];
                const mName = parts[0] || 'Model';
                const fName = parts[1] || name;
                return (0, security_1.decryptWithSecurity)(value, (val) => (0, security_1.decryptValue)(val, keys), mName, fName, undefined, options);
            }
        })(name),
        pgBlindIndex: (name, columnName) => pgCustomType({
            dataType() {
                return 'text';
            },
            toDriver(value) {
                if (!rootSalt) {
                    throw (0, errors_1.dbGuardError)('Blind index root salt is not configured in Drizzle guard options.');
                }
                return (0, security_1.computeBlindIndex)(value, rootSalt, columnName, options.blindIndexes.allowFrequencyLeakage);
            },
            fromDriver(value) {
                return value;
            }
        })(name),
        mysqlBlindIndex: (name, columnName) => mysqlCustomType({
            dataType() {
                return 'text';
            },
            toDriver(value) {
                if (!rootSalt) {
                    throw (0, errors_1.dbGuardError)('Blind index root salt is not configured in Drizzle guard options.');
                }
                return (0, security_1.computeBlindIndex)(value, rootSalt, columnName, options.blindIndexes.allowFrequencyLeakage);
            },
            fromDriver(value) {
                return value;
            }
        })(name),
        sqliteBlindIndex: (name, columnName) => sqliteCustomType({
            dataType() {
                return 'text';
            },
            toDriver(value) {
                if (!rootSalt) {
                    throw (0, errors_1.dbGuardError)('Blind index root salt is not configured in Drizzle guard options.');
                }
                return (0, security_1.computeBlindIndex)(value, rootSalt, columnName, options.blindIndexes.allowFrequencyLeakage);
            },
            fromDriver(value) {
                return value;
            }
        })(name)
    };
};
exports.createDrizzleGuard = createDrizzleGuard;
