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
