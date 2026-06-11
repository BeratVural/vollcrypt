/**
 * Database Web Application Firewall (WAF) & SQLi protection rules.
 */
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
 * Rewrites SQL queries to inject RLS tenant isolation and database-level masking rules.
 */
/**
 * Tokenizes SQL query string to isolate strings and symbols.
 */
export declare function tokenizeSql(sql: string): string[];
/**
 * Rewrites SQL queries to inject RLS tenant isolation and database-level masking rules.
 */
export declare function rewriteQuery(sql: string, role: string, tenantId: string | undefined, config: any): string;
/**
 * Generates Laplace noise for Differential Privacy.
 */
export declare function generateLaplaceNoise(scale: number): number;
/**
 * Generates mock Remote Attestation Quote for secure enclave execution verification.
 */
export declare function getMockAttestationReport(): any;
