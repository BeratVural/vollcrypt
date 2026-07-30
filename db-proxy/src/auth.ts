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
  jitWebhookUrl?: string;
  jitSecret?: string;
  anomalyEngine?: {
    enabled: boolean;
    baselineQueries?: string[];
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

export type DbProxyDriverType = 'postgres' | 'mysql' | 'mongodb' | 'mssql' | 'oracle';

export interface DriverSecurityCapability {
  waf: boolean;
  tenantIsolation: boolean;
  cryptoRbac: boolean;
  decryptRateLimit: boolean;
  rawCellDlp: boolean;
  jitApproval: boolean;
  anomalyScoring: boolean;
  queryRateLimit: boolean;
  maxRowsPerQuery: boolean;
  fingerprinting: boolean;
  temporalConstraints: boolean;
  versionMask: boolean;
}

export const DRIVER_SECURITY_CAPABILITIES: Record<DbProxyDriverType, DriverSecurityCapability> = {
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

export function validateProxyDriverSecurityConfig(dbType: DbProxyDriverType = 'postgres', config: ProxyConfig = DEFAULT_CONFIG): void {
  const capabilities = DRIVER_SECURITY_CAPABILITIES[dbType];
  if (!capabilities) {
    throw new Error(`Unsupported dbType "${dbType}".`);
  }
  if (dbType === 'postgres') return;

  const firewall = config.firewall;
  const unsupported: string[] = [];
  if (firewall?.jitApprovalRequired && !capabilities.jitApproval) unsupported.push('firewall.jitApprovalRequired');
  if (firewall?.anomalyEngine?.enabled && !capabilities.anomalyScoring) unsupported.push('firewall.anomalyEngine.enabled');
  if (firewall?.fingerprinting?.enabled && !capabilities.fingerprinting) unsupported.push('firewall.fingerprinting.enabled');
  if (firewall?.rateLimits?.maxQueriesPerSecond && !capabilities.queryRateLimit) unsupported.push('firewall.rateLimits.maxQueriesPerSecond');
  if (firewall?.maxRowsPerQuery && !capabilities.maxRowsPerQuery) unsupported.push('firewall.maxRowsPerQuery');
  if (firewall?.temporalConstraints && Object.keys(firewall.temporalConstraints).length > 0 && !capabilities.temporalConstraints) unsupported.push('firewall.temporalConstraints');
  if (firewall?.versionMask && !capabilities.versionMask) unsupported.push('firewall.versionMask');

  if (unsupported.length > 0) {
    throw new Error(
      `db-proxy ${dbType} driver does not implement requested security controls: ${unsupported.join(', ')}. ` +
      `Use dbType=postgres for these controls or disable them explicitly; startup is fail-closed to avoid a misleading protection level.`
    );
  }
}