import { Schema } from 'mongoose';
import { RateLimiterOptions } from './security';
export interface MongooseDbGuardOptions {
    key: Buffer | Record<string, Buffer>;
    activeKeyVersion?: string;
    fields: string[];
    blindIndexes?: {
        rootSalt: Buffer;
        fields: string[];
        modelName?: string;
    };
    cryptoRbac?: {
        roles: Record<string, {
            decrypt: string[];
            mask?: Record<string, 'credit_card' | 'email' | 'tc_no' | ((v: any) => any) | string>;
        }>;
    };
    rateLimiter?: RateLimiterOptions;
    multiTenant?: {
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
