import type { EntitySubscriberInterface, InsertEvent, UpdateEvent } from 'typeorm';
import { encryptValue, decryptValue, computeBlindIndex, decryptWithSecurity, registerKeysForZeroization, RateLimiterOptions } from './security';

export interface TypeOrmDbGuardOptions {
  key: Buffer | Record<string, Buffer>;
  activeKeyVersion?: string;
  entities: Record<string, string[]>;
  blindIndexes?: {
    rootSalt: Buffer;
    entities: Record<string, string[]>; // entities and fields to calculate blind indexes for
  };
  cryptoRbac?: {
    roles: Record<string, {
      decrypt: string[];
      mask?: Record<string, 'credit_card' | 'email' | 'tc_no' | ((v: any) => any) | string>;
    }>;
  };
  rateLimiter?: RateLimiterOptions;
}

function getKeys(options: TypeOrmDbGuardOptions) {
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

export function createTypeOrmSubscriber(options: TypeOrmDbGuardOptions) {
  const { EventSubscriber } = require('typeorm');
  const { keys, activeVersion } = getKeys(options);
  const activeKey = keys[activeVersion];

  if (!activeKey) {
    throw new Error(`Active encryption key version "${activeVersion}" is not present in the key map.`);
  }

  registerKeysForZeroization(keys);

  @EventSubscriber()
  class VollcryptDbGuardSubscriber implements EntitySubscriberInterface {
    listenTo() {
      return Object;
    }

    beforeInsert(event: InsertEvent<any>) {
      const entityName = event.metadata.name;
      const fields = options.entities[entityName];
      if (fields && event.entity) {
        // Calculate blind indexes first (before the original field gets encrypted)
        if (options.blindIndexes && options.blindIndexes.rootSalt) {
          const bidxFields = options.blindIndexes.entities[entityName];
          if (bidxFields) {
            for (const field of bidxFields) {
              if (event.entity[field] !== undefined && event.entity[field] !== null) {
                const bidxField = `${field}_bidx`;
                event.entity[bidxField] = computeBlindIndex(event.entity[field], options.blindIndexes.rootSalt, `${entityName}.${field}`);
              }
            }
          }
        }

        // Encrypt fields
        for (const field of fields) {
          if (event.entity[field] !== undefined && event.entity[field] !== null) {
            event.entity[field] = encryptValue(event.entity[field], activeKey, activeVersion);
          }
        }
      }
    }

    beforeUpdate(event: UpdateEvent<any>) {
      const entityName = event.metadata.name;
      const fields = options.entities[entityName];
      if (fields && event.entity) {
        // Calculate blind indexes first
        if (options.blindIndexes && options.blindIndexes.rootSalt) {
          const bidxFields = options.blindIndexes.entities[entityName];
          if (bidxFields) {
            for (const field of bidxFields) {
              if (event.entity[field] !== undefined && event.entity[field] !== null) {
                const bidxField = `${field}_bidx`;
                event.entity[bidxField] = computeBlindIndex(event.entity[field], options.blindIndexes.rootSalt, `${entityName}.${field}`);
              }
            }
          }
        }

        // Encrypt fields
        for (const field of fields) {
          if (event.entity[field] !== undefined && event.entity[field] !== null) {
            event.entity[field] = encryptValue(event.entity[field], activeKey, activeVersion);
          }
        }
      }
    }

    afterLoad(entity: any, event: any) {
      if (!event || !event.metadata) return;
      const entityName = event.metadata.name;
      const fields = options.entities[entityName];
      if (fields && entity) {
        for (const field of fields) {
          if (entity[field] !== undefined && entity[field] !== null) {
            try {
              entity[field] = decryptWithSecurity(
                entity[field],
                (val) => decryptValue(val, keys),
                entityName,
                field,
                entity.id || entity._id,
                options
              );
            } catch (err) {
              throw new Error(`TypeORM db-guard failed to decrypt field "${field}": ${(err as Error).message}`);
            }
          }
        }
      }
    }
  }

  return VollcryptDbGuardSubscriber;
}
