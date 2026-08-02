import type * as net from 'net';
import {
  dbGuardContextStore,
  decryptValue,
  decryptWithSecurity,
} from '@vollcrypt/db-guard';
import {
  getRbacConfig,
  type ProxyConfig,
  type ProxyUserContext,
} from '../auth.js';

/** Shared connection options implemented by every protocol driver. */
export interface DriverConnectionOptions {
  dbHost: string;
  dbPort: number;
  noWaf?: boolean;
  role: string;
  clientIp: string;
  resolvedKeys: Record<string, Buffer>;
  config?: ProxyConfig;
  logSiem: (event: string, severity: number, message: string) => void;
}

/** Security context required to decrypt one protocol value. */
export interface DriverDecryptContext {
  keys: Record<string, Buffer>;
  role: string;
  userId: string;
  tenantId?: string;
  config?: ProxyConfig;
}

/** Common callable contract for protocol connection handlers. */
export type DriverConnectionHandler = (
  clientSocket: net.Socket,
  options: DriverConnectionOptions
) => void;

/** Creates the fail-closed initial identity for a new database connection. */
export function createInitialUserContext(role: string): ProxyUserContext {
  return {
    role,
    userId: role === 'OWNER' ? 'usr-admin' : 'guest-user',
  };
}

/** Resolves a projected column qualifier into DB Guard model and field names. */
export function resolveProjectedField(
  projectedColumn: string | undefined,
  modelName: string,
  fallbackField: string
): { model: string; field: string } {
  if (!projectedColumn) return { model: modelName, field: fallbackField };

  const parts = projectedColumn.split('.');
  const field = parts[parts.length - 1];
  const qualifier = parts.length > 1 ? parts[0] : undefined;
  const model = qualifier && qualifier !== 'u' && qualifier !== 't'
    ? qualifier
    : modelName;

  return { model, field };
}

/** Runs one field decryption through the shared DB Guard security context. */
export function decryptDriverValue(
  ciphertext: string,
  model: string,
  field: string,
  context: DriverDecryptContext
): string {
  return dbGuardContextStore.run(
    {
      role: context.role,
      userId: context.userId,
      tenantId: context.tenantId,
      maxDecryptionsPerSecond: context.config?.rateLimiter?.maxDecryptionsPerSecond,
      rateLimiterMode: context.config?.rateLimiter?.mode,
    },
    () => decryptWithSecurity(
      ciphertext,
      (value) => decryptValue(value, context.keys),
      model,
      field,
      undefined,
      {
        cryptoRbac: getRbacConfig(context.config),
        rateLimiter: context.config?.rateLimiter,
      }
    )
  );
}
