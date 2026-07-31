import type { Schema } from 'mongoose';
import type { CommonDbGuardSecurityOptions } from './contract';
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
    multiTenant?: {
        cacheTtlMs?: number;
        tenants?: Record<string, {
            key?: Buffer | Record<string, Buffer>;
            kms?: any;
        }>;
        getTenantConfig?: (tenantId: string) => Promise<{
            key?: Buffer | Record<string, Buffer>;
            kms?: any;
        } | undefined>;
    };
}
export declare function mongooseDbGuard(schema: Schema, options: MongooseDbGuardOptions): void;
