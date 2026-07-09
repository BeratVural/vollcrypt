"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createDrizzleGuard = void 0;
const security_1 = require("./security");
function getKeys(options) {
    let keys;
    let activeVersion;
    if (Buffer.isBuffer(options.key)) {
        keys = { '1': Buffer.from(options.key) };
        activeVersion = '1';
    }
    else {
        keys = {};
        for (const [v, k] of Object.entries(options.key)) {
            keys[v] = Buffer.from(k);
        }
        activeVersion = options.activeKeyVersion || Object.keys(keys)[0];
    }
    return { keys, activeVersion };
}
const createDrizzleGuard = (options) => {
    const pgCustomType = require('drizzle-orm/pg-core').customType;
    const mysqlCustomType = require('drizzle-orm/mysql-core').customType;
    const sqliteCustomType = require('drizzle-orm/sqlite-core').customType;
    const { keys, activeVersion } = getKeys(options);
    const activeKey = keys[activeVersion];
    if (!activeKey) {
        throw new Error(`Active encryption key version "${activeVersion}" is not present in the key map.`);
    }
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
                    throw new Error('Blind index root salt is not configured in Drizzle guard options.');
                }
                return (0, security_1.computeBlindIndex)(value, rootSalt, columnName);
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
                    throw new Error('Blind index root salt is not configured in Drizzle guard options.');
                }
                return (0, security_1.computeBlindIndex)(value, rootSalt, columnName);
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
                    throw new Error('Blind index root salt is not configured in Drizzle guard options.');
                }
                return (0, security_1.computeBlindIndex)(value, rootSalt, columnName);
            },
            fromDriver(value) {
                return value;
            }
        })(name)
    };
};
exports.createDrizzleGuard = createDrizzleGuard;
