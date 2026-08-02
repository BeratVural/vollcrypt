import type { Schema } from 'mongoose';
import type { CommonDbGuardSecurityOptions } from './contract';
import { MultiTenantKeyOptions } from './tenant';
export interface MongooseDbGuardOptions extends CommonDbGuardSecurityOptions {
    key: Buffer | Record<string, Buffer>;
    activeKeyVersion?: string;
    fields: string[];
    blindIndexes?: {
        rootSalt: Buffer;
        allowFrequencyLeakage: true;
        fields: string[];
        modelName?: string;
    };
    multiTenant?: MultiTenantKeyOptions;
}
/**
 * Installs fail-closed encryption, blind-index, and decryption hooks on a Mongoose schema.
 */
export declare function mongooseDbGuard(schema: Schema, options: MongooseDbGuardOptions): void;
