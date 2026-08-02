import { dbGuardError } from './errors';
import type { customType as pgCustomTypeType } from 'drizzle-orm/pg-core';
import type { customType as mysqlCustomTypeType } from 'drizzle-orm/mysql-core';
import type { customType as sqliteCustomTypeType } from 'drizzle-orm/sqlite-core';
import { encryptValue, decryptValue, computeBlindIndex, validateBlindIndexConfiguration, registerKeysForZeroization, decryptWithSecurity } from './security';
import type { CommonDbGuardSecurityOptions } from './contract';
import { normalizeKeys } from './keys';

export interface DrizzleDbGuardOptions extends CommonDbGuardSecurityOptions {
  key: Buffer | Record<string, Buffer>;
  activeKeyVersion?: string;
  blindIndexes?: {
    rootSalt: Buffer;
    allowFrequencyLeakage: true;
  };

}

/**
 * Creates encrypted and blind-index Drizzle custom column types for supported SQL dialects.
 */
export const createDrizzleGuard = (options: DrizzleDbGuardOptions) => {
  if (options.blindIndexes) {
    validateBlindIndexConfiguration(
      options.blindIndexes.rootSalt,
      options.blindIndexes.allowFrequencyLeakage
    );
  }
  const pgCustomType = require('drizzle-orm/pg-core').customType as typeof pgCustomTypeType;
  const mysqlCustomType = require('drizzle-orm/mysql-core').customType as typeof mysqlCustomTypeType;
  const sqliteCustomType = require('drizzle-orm/sqlite-core').customType as typeof sqliteCustomTypeType;

  const { keys, activeVersion, activeKey } = normalizeKeys(options.key, options.activeKeyVersion);

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
          throw dbGuardError('Blind index root salt is not configured in Drizzle guard options.');
        }
        return computeBlindIndex(value, rootSalt, columnName, options.blindIndexes!.allowFrequencyLeakage);
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
          throw dbGuardError('Blind index root salt is not configured in Drizzle guard options.');
        }
        return computeBlindIndex(value, rootSalt, columnName, options.blindIndexes!.allowFrequencyLeakage);
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
          throw dbGuardError('Blind index root salt is not configured in Drizzle guard options.');
        }
        return computeBlindIndex(value, rootSalt, columnName, options.blindIndexes!.allowFrequencyLeakage);
      },
      fromDriver(value: any): string {
        return value;
      }
    })(name)
  };
};
