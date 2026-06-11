export interface ProxyUserContext {
  userId: string;
  role: string;
  tenantId?: string;
}

export interface FirewallConfig {
  versionMask?: string;
  maxRowsPerQuery?: number;
  temporalConstraints?: Record<string, { startHour: number; endHour: number; allowedDays: number[] }>;
  rateLimits?: { maxQueriesPerSecond: number };
  fingerprinting?: {
    enabled: boolean;
    mode: 'learning' | 'blocking';
    allowlistPath?: string;
  };
  jitApprovalRequired?: boolean;
  anomalyEngine?: {
    enabled: boolean;
  };
}

export interface ProxyConfig {
  users: Record<string, { role: string; userId: string; tenantId?: string }>;
  cryptoRbac?: {
    roles: Record<
      string,
      {
        decrypt: string[];
        mask?: Record<string, 'credit_card' | 'email' | 'tc_no' | string>;
      }
    >;
  };
  rateLimiter?: any;
  firewall?: FirewallConfig;
}

const DEFAULT_CONFIG: ProxyConfig = {
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
export function resolveUserContext(
  username: string,
  config: ProxyConfig = DEFAULT_CONFIG
): ProxyUserContext {
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

export function getRbacConfig(config: ProxyConfig = DEFAULT_CONFIG) {
  return config.cryptoRbac;
}
