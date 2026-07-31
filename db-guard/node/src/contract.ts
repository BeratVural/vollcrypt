import type { PrismaDbGuardOptions } from './prisma';
import type { MongooseDbGuardOptions } from './mongoose';
import type { DrizzleDbGuardOptions } from './drizzle';
import type { TypeOrmDbGuardOptions } from './typeorm';
import type { RateLimiterOptions } from './security';

export const DB_GUARD_CONTRACT_VERSION = 1 as const;
export const SUPPORTED_KEY_VERSIONS = ['1', '2'] as const;

export type DbGuardContractErrorCode =
  | 'UNSUPPORTED_CONTRACT_VERSION'
  | 'INVALID_KEYRING'
  | 'INVALID_RESOURCE_SCOPE'
  | 'RESOURCE_NOT_FOUND';

export class DbGuardContractError extends Error {
  constructor(
    public readonly code: DbGuardContractErrorCode,
    message: string
  ) {
    super(`Vollcrypt DbGuard contract [${code}]: ${message}`);
    this.name = 'DbGuardContractError';
  }
}

export type DbGuardMask =
  | 'credit_card'
  | 'email'
  | 'tc_no'
  | ((value: any) => any)
  | string;

export interface CryptoRbacConfig {
  roles: Record<string, {
    decrypt: string[];
    mask?: Record<string, DbGuardMask>;
  }>;
}

export interface CommonDbGuardSecurityOptions {
  cryptoRbac?: CryptoRbacConfig;
  rateLimiter?: RateLimiterOptions;
  allowUnrestrictedDecrypt?: boolean;
}

export interface DbGuardContractV1 {
  contractVersion: typeof DB_GUARD_CONTRACT_VERSION;
  keyring: {
    keys: Buffer | Record<string, Buffer>;
    activeVersion?: string;
  };
  resources: Record<string, string[]>;
  blindIndexes?: {
    rootSalt: Buffer;
    allowFrequencyLeakage: true;
    resources: Record<string, string[]>;
  };
  security?: CommonDbGuardSecurityOptions;
}

function keyVersions(keys: Buffer | Record<string, Buffer>): string[] {
  return Buffer.isBuffer(keys) ? ['1'] : Object.keys(keys);
}

function validateResourceMap(resources: Record<string, string[]>, label: string) {
  const entries = Object.entries(resources);
  if (entries.length === 0) {
    throw new DbGuardContractError('INVALID_RESOURCE_SCOPE', `${label} must not be empty.`);
  }
  for (const [resource, fields] of entries) {
    if (!resource.trim() || !Array.isArray(fields) || fields.length === 0) {
      throw new DbGuardContractError(
        'INVALID_RESOURCE_SCOPE',
        `${label}.${resource || '<empty>'} must contain at least one field.`
      );
    }
    if (fields.some((field) => typeof field !== 'string' || !field.trim())) {
      throw new DbGuardContractError(
        'INVALID_RESOURCE_SCOPE',
        `${label}.${resource} contains an invalid field name.`
      );
    }
  }
}

export function validateDbGuardContract(contract: DbGuardContractV1): void {
  if (contract.contractVersion !== DB_GUARD_CONTRACT_VERSION) {
    throw new DbGuardContractError(
      'UNSUPPORTED_CONTRACT_VERSION',
      `expected ${DB_GUARD_CONTRACT_VERSION}, got ${String(contract.contractVersion)}.`
    );
  }

  const versions = keyVersions(contract.keyring.keys);
  if (versions.length === 0 || versions.some((version) => !SUPPORTED_KEY_VERSIONS.includes(version as any))) {
    throw new DbGuardContractError(
      'INVALID_KEYRING',
      `key versions must be one or more of ${SUPPORTED_KEY_VERSIONS.join(', ')}.`
    );
  }
  for (const version of versions) {
    const key = Buffer.isBuffer(contract.keyring.keys)
      ? contract.keyring.keys
      : contract.keyring.keys[version];
    if (!Buffer.isBuffer(key) || key.length !== 32) {
      throw new DbGuardContractError('INVALID_KEYRING', `key version ${version} must be 32 bytes.`);
    }
  }

  const activeVersion = contract.keyring.activeVersion || versions[0];
  if (!versions.includes(activeVersion)) {
    throw new DbGuardContractError(
      'INVALID_KEYRING',
      `active key version ${activeVersion} is not present in the keyring.`
    );
  }

  validateResourceMap(contract.resources, 'resources');
  if (contract.blindIndexes) {
    validateResourceMap(contract.blindIndexes.resources, 'blindIndexes.resources');
  }
}

function securityOptions(contract: DbGuardContractV1): CommonDbGuardSecurityOptions {
  return contract.security ? { ...contract.security } : {};
}

export function toPrismaDbGuardOptions(contract: DbGuardContractV1): PrismaDbGuardOptions {
  validateDbGuardContract(contract);
  return {
    key: contract.keyring.keys,
    activeKeyVersion: contract.keyring.activeVersion,
    models: contract.resources,
    blindIndexes: contract.blindIndexes
      ? {
          rootSalt: contract.blindIndexes.rootSalt,
          allowFrequencyLeakage: contract.blindIndexes.allowFrequencyLeakage,
          models: contract.blindIndexes.resources
        }
      : undefined,
    ...securityOptions(contract)
  };
}

export function toMongooseDbGuardOptions(
  contract: DbGuardContractV1,
  resource: string
): MongooseDbGuardOptions {
  validateDbGuardContract(contract);
  const fields = contract.resources[resource];
  if (!fields) {
    throw new DbGuardContractError('RESOURCE_NOT_FOUND', `resource ${resource} is not configured.`);
  }
  return {
    key: contract.keyring.keys,
    activeKeyVersion: contract.keyring.activeVersion,
    fields,
    blindIndexes: contract.blindIndexes
      ? {
          rootSalt: contract.blindIndexes.rootSalt,
          allowFrequencyLeakage: contract.blindIndexes.allowFrequencyLeakage,
          fields: contract.blindIndexes.resources[resource] || [],
          modelName: resource
        }
      : undefined,
    ...securityOptions(contract)
  };
}

export function toDrizzleDbGuardOptions(contract: DbGuardContractV1): DrizzleDbGuardOptions {
  validateDbGuardContract(contract);
  return {
    key: contract.keyring.keys,
    activeKeyVersion: contract.keyring.activeVersion,
    blindIndexes: contract.blindIndexes
      ? {
          rootSalt: contract.blindIndexes.rootSalt,
          allowFrequencyLeakage: contract.blindIndexes.allowFrequencyLeakage
        }
      : undefined,
    ...securityOptions(contract)
  };
}

export function toTypeOrmDbGuardOptions(contract: DbGuardContractV1): TypeOrmDbGuardOptions {
  validateDbGuardContract(contract);
  return {
    key: contract.keyring.keys,
    activeKeyVersion: contract.keyring.activeVersion,
    entities: contract.resources,
    blindIndexes: contract.blindIndexes
      ? {
          rootSalt: contract.blindIndexes.rootSalt,
          allowFrequencyLeakage: contract.blindIndexes.allowFrequencyLeakage,
          entities: contract.blindIndexes.resources
        }
      : undefined,
    ...securityOptions(contract)
  };
}