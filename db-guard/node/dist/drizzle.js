"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createDrizzleGuard = void 0;
const pg_core_1 = require("drizzle-orm/pg-core");
const mysql_core_1 = require("drizzle-orm/mysql-core");
const sqlite_core_1 = require("drizzle-orm/sqlite-core");
const prisma_1 = require("./prisma");
const blind_index_1 = require("./blind-index");
const security_1 = require("./security");
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
const createDrizzleGuard = (options) => {
    const { keys, activeVersion } = getKeys(options);
    const activeKey = keys[activeVersion];
    if (!activeKey) {
        throw new Error(`Active encryption key version "${activeVersion}" is not present in the key map.`);
    }
    (0, security_1.registerKeysForZeroization)(keys);
    const rootSalt = options.blindIndexes?.rootSalt;
    return {
        pgText: (name, columnPath) => (0, pg_core_1.customType)({
            dataType() {
                return 'text';
            },
            toDriver(value) {
                return (0, prisma_1.encryptValue)(value, activeKey, activeVersion);
            },
            fromDriver(value) {
                const parts = columnPath?.split('.') || [name];
                const mName = parts[0] || 'Model';
                const fName = parts[1] || name;
                return (0, security_1.decryptWithSecurity)(value, (val) => (0, prisma_1.decryptValue)(val, keys), mName, fName, undefined, options);
            }
        })(name),
        mysqlText: (name, columnPath) => (0, mysql_core_1.customType)({
            dataType() {
                return 'text';
            },
            toDriver(value) {
                return (0, prisma_1.encryptValue)(value, activeKey, activeVersion);
            },
            fromDriver(value) {
                const parts = columnPath?.split('.') || [name];
                const mName = parts[0] || 'Model';
                const fName = parts[1] || name;
                return (0, security_1.decryptWithSecurity)(value, (val) => (0, prisma_1.decryptValue)(val, keys), mName, fName, undefined, options);
            }
        })(name),
        sqliteText: (name, columnPath) => (0, sqlite_core_1.customType)({
            dataType() {
                return 'text';
            },
            toDriver(value) {
                return (0, prisma_1.encryptValue)(value, activeKey, activeVersion);
            },
            fromDriver(value) {
                const parts = columnPath?.split('.') || [name];
                const mName = parts[0] || 'Model';
                const fName = parts[1] || name;
                return (0, security_1.decryptWithSecurity)(value, (val) => (0, prisma_1.decryptValue)(val, keys), mName, fName, undefined, options);
            }
        })(name),
        pgBlindIndex: (name, columnName) => (0, pg_core_1.customType)({
            dataType() {
                return 'text';
            },
            toDriver(value) {
                if (!rootSalt) {
                    throw new Error('Blind index root salt is not configured in Drizzle guard options.');
                }
                return (0, blind_index_1.computeBlindIndex)(value, rootSalt, columnName);
            },
            fromDriver(value) {
                return value;
            }
        })(name),
        mysqlBlindIndex: (name, columnName) => (0, mysql_core_1.customType)({
            dataType() {
                return 'text';
            },
            toDriver(value) {
                if (!rootSalt) {
                    throw new Error('Blind index root salt is not configured in Drizzle guard options.');
                }
                return (0, blind_index_1.computeBlindIndex)(value, rootSalt, columnName);
            },
            fromDriver(value) {
                return value;
            }
        })(name),
        sqliteBlindIndex: (name, columnName) => (0, sqlite_core_1.customType)({
            dataType() {
                return 'text';
            },
            toDriver(value) {
                if (!rootSalt) {
                    throw new Error('Blind index root salt is not configured in Drizzle guard options.');
                }
                return (0, blind_index_1.computeBlindIndex)(value, rootSalt, columnName);
            },
            fromDriver(value) {
                return value;
            }
        })(name)
    };
};
exports.createDrizzleGuard = createDrizzleGuard;
