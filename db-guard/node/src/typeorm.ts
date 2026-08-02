import { dbGuardError } from './errors';
import type { EntitySubscriberInterface, InsertEvent, UpdateEvent } from 'typeorm';
import { encryptValue, decryptValue, computeBlindIndex, validateBlindIndexConfiguration, decryptWithSecurity, registerKeysForZeroization } from './security';
import type { CommonDbGuardSecurityOptions } from './contract';
import { normalizeKeys } from './keys';

export interface TypeOrmDbGuardOptions extends CommonDbGuardSecurityOptions {
  key: Buffer | Record<string, Buffer>;
  activeKeyVersion?: string;
  entities: Record<string, string[]>;
  blindIndexes?: {
    rootSalt: Buffer;
    allowFrequencyLeakage: true;
    entities: Record<string, string[]>; // entities and fields to calculate blind indexes for
  };

}

/**
 * Creates a TypeORM subscriber that encrypts configured fields before writes and decrypts after loads.
 */
export function createTypeOrmSubscriber(options: TypeOrmDbGuardOptions) {
  if (options.blindIndexes) {
    validateBlindIndexConfiguration(
      options.blindIndexes.rootSalt,
      options.blindIndexes.allowFrequencyLeakage
    );
  }
  const { EventSubscriber } = require('typeorm');
  const { keys, activeVersion, activeKey } = normalizeKeys(options.key, options.activeKeyVersion);

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
                event.entity[bidxField] = computeBlindIndex(event.entity[field], options.blindIndexes.rootSalt, `${entityName}.${field}`, options.blindIndexes.allowFrequencyLeakage);
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
                event.entity[bidxField] = computeBlindIndex(event.entity[field], options.blindIndexes.rootSalt, `${entityName}.${field}`, options.blindIndexes.allowFrequencyLeakage);
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
              throw dbGuardError(`TypeORM db-guard failed to decrypt field "${field}": ${(err as Error).message}`);
            }
          }
        }
      }
    }
  }

  return VollcryptDbGuardSubscriber;
}
