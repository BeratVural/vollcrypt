import type { InsertEvent, UpdateEvent } from 'typeorm';
import type { CommonDbGuardSecurityOptions } from './contract';
export interface TypeOrmDbGuardOptions extends CommonDbGuardSecurityOptions {
    key: Buffer | Record<string, Buffer>;
    activeKeyVersion?: string;
    entities: Record<string, string[]>;
    blindIndexes?: {
        rootSalt: Buffer;
        allowFrequencyLeakage: true;
        entities: Record<string, string[]>;
    };
}
export declare function createTypeOrmSubscriber(options: TypeOrmDbGuardOptions): {
    new (): {
        listenTo(): ObjectConstructor;
        beforeInsert(event: InsertEvent<any>): void;
        beforeUpdate(event: UpdateEvent<any>): void;
        afterLoad(entity: any, event: any): void;
    };
};
