import { customType as pgCustomType } from 'drizzle-orm/pg-core';
import { customType as mysqlCustomType } from 'drizzle-orm/mysql-core';
import { customType as sqliteCustomType } from 'drizzle-orm/sqlite-core';
import { encryptValue, decryptValue } from './prisma';
import { computeBlindIndex } from './blind-index';
import { registerKeysForZeroization, decryptWithSecurity, RateLimiterOptions } from './security';

export interface DrizzleDbGuardOptions {
  key: Buffer | Record<string, Buffer>;
  activeKeyVersion?: string;
  blindIndexes?: {
    rootSalt: Buffer;
  };
  cryptoRbac?: {
    roles: Record<string, {
      decrypt: string[];
      mask?: Record<string, 'credit_card' | 'email' | 'tc_no' | ((v: any) => any) | string>;
    }>;
  };
  rateLimiter?: RateLimiterOptions;
}

function getKeys(options: DrizzleDbGuardOptions) {
  let keys: Record<string, Buffer>;
  let activeVersion: string;

  if (Buffer.isBuffer(options.key)) {
    keys = { '1': Buffer.from(options.key) };
    activeVersion = '1';
  } else {
    keys = {};
    for (const [v, k] of Object.entries(options.key)) {
      keys[v] = Buffer.from(k);
    }
    activeVersion = options.activeKeyVersion || Object.keys(keys)[0];
  }

  return { keys, activeVersion };
}

export const createDrizzleGuard = (options: DrizzleDbGuardOptions) => {
  const { keys, activeVersion } = getKeys(options);
  const activeKey = keys[activeVersion];

  if (!activeKey) {
    throw new Error(`Active encryption key version "${activeVersion}" is not present in the key map.`);
  }

  registerKeysForZeroization(keys);

  const rootSalt = options.blindIndexes?.rootSalt;

  return {
    pgText: (name: string, columnPath?: string) => pgCustomType({
      dataType() {
        return 'text';
      },
      toDriver(value: any): string {
        return encryptValue(value, activeKey, activeVersion);
      },
      fromDriver(value: any): string {
        const parts = columnPath?.split('.') || [name];
        const mName = parts[0] || 'Model';
        const fName = parts[1] || name;
        return decryptWithSecurity(
          value,
          (val) => decryptValue(val, keys),
          mName,
          fName,
          undefined,
          options
        );
      }
    })(name),

    mysqlText: (name: string, columnPath?: string) => mysqlCustomType({
      dataType() {
        return 'text';
      },
      toDriver(value: any): string {
        return encryptValue(value, activeKey, activeVersion);
      },
      fromDriver(value: any): string {
        const parts = columnPath?.split('.') || [name];
        const mName = parts[0] || 'Model';
        const fName = parts[1] || name;
        return decryptWithSecurity(
          value,
          (val) => decryptValue(val, keys),
          mName,
          fName,
          undefined,
          options
        );
      }
    })(name),

    sqliteText: (name: string, columnPath?: string) => sqliteCustomType({
      dataType() {
        return 'text';
      },
      toDriver(value: any): string {
        return encryptValue(value, activeKey, activeVersion);
      },
      fromDriver(value: any): string {
        const parts = columnPath?.split('.') || [name];
        const mName = parts[0] || 'Model';
        const fName = parts[1] || name;
        return decryptWithSecurity(
          value,
          (val) => decryptValue(val, keys),
          mName,
          fName,
          undefined,
          options
        );
      }
    })(name),

    pgBlindIndex: (name: string, columnName: string) => pgCustomType({
      dataType() {
        return 'text';
      },
      toDriver(value: any): string {
        if (!rootSalt) {
          throw new Error('Blind index root salt is not configured in Drizzle guard options.');
        }
        return computeBlindIndex(value, rootSalt, columnName);
      },
      fromDriver(value: any): string {
        return value;
      }
    })(name),

    mysqlBlindIndex: (name: string, columnName: string) => mysqlCustomType({
      dataType() {
        return 'text';
      },
      toDriver(value: any): string {
        if (!rootSalt) {
          throw new Error('Blind index root salt is not configured in Drizzle guard options.');
        }
        return computeBlindIndex(value, rootSalt, columnName);
      },
      fromDriver(value: any): string {
        return value;
      }
    })(name),

    sqliteBlindIndex: (name: string, columnName: string) => sqliteCustomType({
      dataType() {
        return 'text';
      },
      toDriver(value: any): string {
        if (!rootSalt) {
          throw new Error('Blind index root salt is not configured in Drizzle guard options.');
        }
        return computeBlindIndex(value, rootSalt, columnName);
      },
      fromDriver(value: any): string {
        return value;
      }
    })(name)
  };
};
