export interface ComplianceAuditInput {
    key?: any;
    kms?: {
        provider: any;
        wrappedKey: any;
        wrappedKek?: any;
        activeKeyVersion?: string;
    };
    models?: Record<string, string[]>;
    blindIndexes?: {
        rootSalt: any;
        models: Record<string, string[]>;
    };
    cryptoRbac?: {
        roles: Record<string, {
            decrypt: string[];
            mask?: Record<string, any>;
        }>;
    };
    rateLimiter?: {
        maxDecryptionsPerSecond?: number;
        mode?: 'fail_closed' | 'warn' | 'disabled';
        maxPageSize?: number;
        onPageSizeExceeded?: 'warn' | 'error' | 'bypass';
    };
    auditTrailPath?: string;
    breakGlassThreshold?: number;
    breakGlassPublicKeys?: string[];
    postQuantumEnabled?: boolean;
}
export interface ComplianceScorecard {
    gdprScore: number;
    kvkkScore: number;
    pciScore: number;
    passedChecks: string[];
    failedChecks: string[];
    summaryText: string;
}
export declare function auditConfiguration(config: ComplianceAuditInput): ComplianceScorecard;
export declare function generateComplianceHtmlReport(config: ComplianceAuditInput): string;
