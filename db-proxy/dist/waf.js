"use strict";
/**
 * Database Web Application Firewall (WAF) & SQLi protection rules.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeQuery = normalizeQuery;
exports.validateQuery = validateQuery;
// Common SQL Injection patterns
const SQLI_PATTERNS = [
    /\bunion\s+all\s+select\b/i,
    /\bunion\s+select\b/i,
    /\b(or|and)\s+\d+\s*=\s*\d+\b/i,
    /\b(or|and)\s+['"][^'"]*['"]\s*=\s*['"][^'"]*['"]/i,
    /--/i,
    /\/\*/i,
    /;\s*drop\s+/i,
    /;\s*truncate\s+/i,
];
// Dangerous DDL commands
const DDL_PATTERNS = [
    /\bdrop\s+(table|database|schema|view|index|user|role)\b/i,
    /\btruncate\s+table\b/i,
    /\balter\s+(table|database|schema|view|index|user|role)\b/i,
];
/**
 * Normalizes SQL queries by stripping comments and collapsing delimiters.
 * Prevents WAF bypasses using comment delimiters (e.g. DROP comments block TABLE).
 */
function normalizeQuery(query) {
    // 1. Remove multiline comments
    let cleaned = query.replace(/\/\*[\s\S]*?\*\//g, ' ');
    // 2. Remove single line comments
    cleaned = cleaned.replace(/--.*$/gm, ' ');
    // 3. Collapse multiple whitespaces to single spaces
    return cleaned.replace(/\s+/g, ' ').trim();
}
/**
 * Validates a SQL query string against security profiles.
 * Throws an Error if a security policy violation is detected.
 */
function validateQuery(query, role) {
    const normalized = normalizeQuery(query);
    // 1. Check for SQL Injection signatures
    for (const pattern of SQLI_PATTERNS) {
        if (pattern.test(normalized)) {
            throw new Error(`SQL Injection signature detected: query matched security rule ${pattern.toString()}`);
        }
    }
    // 2. Check for restricted DDL commands
    for (const pattern of DDL_PATTERNS) {
        if (pattern.test(normalized)) {
            if (role !== 'OWNER') {
                throw new Error(`Unauthorized command: role "${role}" is not permitted to execute DDL queries matching ${pattern.toString()}`);
            }
        }
    }
}
