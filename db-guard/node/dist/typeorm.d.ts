import type { InsertEvent, UpdateEvent } from 'typeorm';
import { RateLimiterOptions } from './security';
export interface TypeOrmDbGuardOptions {
    key: Buffer | Record<string, Buffer>;
    activeKeyVersion?: string;
    entities: Record<string, string[]>;
    blindIndexes?: {
        rootSalt: Buffer;
        entities: Record<string, string[]>;
    };
    cryptoRbac?: {
        roles: Record<string, {
            decrypt: string[];
            mask?: Record<string, 'credit_card' | 'email' | 'tc_no' | ((v: any) => any) | string>;
        }>;
    };
    rateLimiter?: RateLimiterOptions;
}
export declare function createTypeOrmSubscriber(options: TypeOrmDbGuardOptions): {
    new (): {
        listenTo(): ObjectConstructor;
        beforeInsert(event: InsertEvent<any>): void;
        beforeUpdate(event: UpdateEvent<any>): void;
        afterLoad(entity: any, event: any): void;
    };
};
