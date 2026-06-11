"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveUserContext = resolveUserContext;
exports.getRbacConfig = getRbacConfig;
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
