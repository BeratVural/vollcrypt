import type { ProxyConfig } from './auth.js';
/**
 * Normalizes SQL queries by stripping comments and collapsing delimiters.
 * Prevents WAF bypasses using comment delimiters (e.g. DROP comments block TABLE).
 */
export declare function normalizeQuery(query: string): string;
/**
 * Validates a SQL query string against security profiles.
 * Throws an Error if a security policy violation is detected.
 */
export declare function validateQuery(query: string, role: string): void;
/**
 * Generates an abstract fingerprint of the SQL query by stripping literals.
 */
export declare function generateFingerprint(query: string): string;
/**
 * Evaluates semantic threats in a SQL query and returns a combined threat score.
 */
export declare function evaluateThreatScore(query: string): number;
/**
 * Tokenizes SQL query string to isolate strings and symbols.
 */
export declare function tokenizeSql(sql: string): string[];
/**
 * Rewrites SQL queries to inject RLS tenant isolation and database-level masking rules.
 */
export declare function rewriteQuery(sql: string, role: string, tenantId: string | undefined, config: ProxyConfig | undefined): string;
/**
 * Enforces fail-closed tenant scoping for non-PostgreSQL drivers.
 */
export declare function ensureTenantScopedQuery(sql: string, tenantId: string | undefined): void;
/**
 * Generates Laplace noise for Differential Privacy.
 */
export declare function generateLaplaceNoise(scale: number): number;
/** Identifies aggregate positions in a SQL projection. */
export declare function identifyAggregates(sql: string): boolean[];
/** Extracts source projection columns for field-level RBAC mapping. */
export declare function extractProjectionColumns(sql: string): string[];
/** Extracts the primary source table from a SQL statement. */
export declare function extractTableName(sql: string): string;
