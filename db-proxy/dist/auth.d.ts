export interface ProxyUserContext {
    userId: string;
    role: string;
    tenantId?: string;
}
export interface ProxyConfig {
    users: Record<string, {
        role: string;
        userId: string;
        tenantId?: string;
    }>;
    cryptoRbac?: {
        roles: Record<string, {
            decrypt: string[];
            mask?: Record<string, 'credit_card' | 'email' | 'tc_no' | string>;
        }>;
    };
}
/**
 * Resolves a database user context based on the incoming username and configuration.
 */
export declare function resolveUserContext(username: string, config?: ProxyConfig): ProxyUserContext;
export declare function getRbacConfig(config?: ProxyConfig): {
    roles: Record<string, {
        decrypt: string[];
        mask?: Record<string, "credit_card" | "email" | "tc_no" | string>;
    }>;
} | undefined;
