"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DRIVER_SECURITY_CAPABILITIES = void 0;
exports.resolveUserContext = resolveUserContext;
exports.getRbacConfig = getRbacConfig;
exports.validateProxyDriverSecurityConfig = validateProxyDriverSecurityConfig;
const DEFAULT_CONFIG = {
    users: {
        postgres: { role: 'OWNER', userId: 'usr-admin' },
        analyst_hr: { role: 'HR_ADMIN', userId: 'usr-hr-01' },
        analyst_marketing: { role: 'MARKETING', userId: 'usr-mkt-01' },
    },
    cryptoRbac: {
        roles: {
            OWNER: {
                decrypt: ['*', 'users.email', 'users.credit_card', 'users.tc_no'],
            },
            HR_ADMIN: {
                decrypt: ['users.email', 'users.tc_no'],
                mask: {
                    'users.credit_card': 'credit_card',
                },
            },
            MARKETING: {
                decrypt: ['users.email'],
                mask: {
                    'users.tc_no': 'tc_no',
                    'users.credit_card': 'credit_card',
                },
            },
        },
    },
};
/**
 * Resolves a database user context based on the incoming username and configuration.
 */
function resolveUserContext(username, config = DEFAULT_CONFIG) {
    const userMapping = config.users[username];
    if (userMapping) {
        return {
            userId: userMapping.userId,
            role: userMapping.role,
            tenantId: userMapping.tenantId,
        };
    }
    // Fallback to guest / unauthorized access
    return {
        userId: `usr-guest-${username}`,
        role: 'GUEST',
    };
}
function getRbacConfig(config = DEFAULT_CONFIG) {
    return config.cryptoRbac;
}
exports.DRIVER_SECURITY_CAPABILITIES = {
    postgres: {
        waf: true,
        tenantIsolation: true,
        cryptoRbac: true,
        decryptRateLimit: true,
        rawCellDlp: true,
        jitApproval: true,
        anomalyScoring: true,
        queryRateLimit: true,
        maxRowsPerQuery: true,
        fingerprinting: true,
        temporalConstraints: true,
        versionMask: true,
    },
    mysql: {
        waf: true,
        tenantIsolation: true,
        cryptoRbac: true,
        decryptRateLimit: true,
        rawCellDlp: false,
        jitApproval: false,
        anomalyScoring: false,
        queryRateLimit: false,
        maxRowsPerQuery: false,
        fingerprinting: false,
        temporalConstraints: false,
        versionMask: false,
    },
    mongodb: {
        waf: true,
        tenantIsolation: true,
        cryptoRbac: true,
        decryptRateLimit: true,
        rawCellDlp: false,
        jitApproval: false,
        anomalyScoring: false,
        queryRateLimit: false,
        maxRowsPerQuery: false,
        fingerprinting: false,
        temporalConstraints: false,
        versionMask: false,
    },
    mssql: {
        waf: true,
        tenantIsolation: true,
        cryptoRbac: true,
        decryptRateLimit: true,
        rawCellDlp: false,
        jitApproval: false,
        anomalyScoring: false,
        queryRateLimit: false,
        maxRowsPerQuery: false,
        fingerprinting: false,
        temporalConstraints: false,
        versionMask: false,
    },
    oracle: {
        waf: true,
        tenantIsolation: true,
        cryptoRbac: true,
        decryptRateLimit: true,
        rawCellDlp: false,
        jitApproval: false,
        anomalyScoring: false,
        queryRateLimit: false,
        maxRowsPerQuery: false,
        fingerprinting: false,
        temporalConstraints: false,
        versionMask: false,
    },
};
function validateProxyDriverSecurityConfig(dbType = 'postgres', config = DEFAULT_CONFIG) {
    const capabilities = exports.DRIVER_SECURITY_CAPABILITIES[dbType];
    if (!capabilities) {
        throw new Error(`Unsupported dbType "${dbType}".`);
    }
    if (dbType === 'postgres')
        return;
    const firewall = config.firewall;
    const unsupported = [];
    if (firewall?.jitApprovalRequired && !capabilities.jitApproval)
        unsupported.push('firewall.jitApprovalRequired');
    if (firewall?.anomalyEngine?.enabled && !capabilities.anomalyScoring)
        unsupported.push('firewall.anomalyEngine.enabled');
    if (firewall?.fingerprinting?.enabled && !capabilities.fingerprinting)
        unsupported.push('firewall.fingerprinting.enabled');
    if (firewall?.rateLimits?.maxQueriesPerSecond && !capabilities.queryRateLimit)
        unsupported.push('firewall.rateLimits.maxQueriesPerSecond');
    if (firewall?.maxRowsPerQuery && !capabilities.maxRowsPerQuery)
        unsupported.push('firewall.maxRowsPerQuery');
    if (firewall?.temporalConstraints && Object.keys(firewall.temporalConstraints).length > 0 && !capabilities.temporalConstraints)
        unsupported.push('firewall.temporalConstraints');
    if (firewall?.versionMask && !capabilities.versionMask)
        unsupported.push('firewall.versionMask');
    if (unsupported.length > 0) {
        throw new Error(`db-proxy ${dbType} driver does not implement requested security controls: ${unsupported.join(', ')}. ` +
            `Use dbType=postgres for these controls or disable them explicitly; startup is fail-closed to avoid a misleading protection level.`);
    }
}
