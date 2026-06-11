/**
 * Database Web Application Firewall (WAF) & SQLi protection rules.
 */

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
export function normalizeQuery(query: string): string {
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
export function validateQuery(query: string, role: string): void {
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

/**
 * Generates an abstract fingerprint of the SQL query by stripping literals.
 */
export function generateFingerprint(query: string): string {
  const normalized = normalizeQuery(query);
  
  // Replace single-quoted string literals with '?'
  let fingerprinted = normalized.replace(/'(?:''|[^'])*'/g, '?');
  
  // Replace double-quoted string literals with '?'
  fingerprinted = fingerprinted.replace(/"(?:""|[^"])*"/g, '?');
  
  // Replace hex numerical literals
  fingerprinted = fingerprinted.replace(/\b0x[0-9a-fA-F]+\b/g, '?');
  
  // Replace decimal and integer numeric literals
  fingerprinted = fingerprinted.replace(/\b\d+(?:\.\d+)?\b/g, '?');
  
  // Replace boolean literals
  fingerprinted = fingerprinted.replace(/\b(?:true|false)\b/gi, '?');
  
  // Collapse whitespace
  return fingerprinted.replace(/\s+/g, ' ').trim();
}

/**
 * Evaluates semantic threats in a SQL query and returns a combined threat score.
 */
export function evaluateThreatScore(query: string): number {
  const normalized = normalizeQuery(query);
  let score = 0;

  // 1. Timing delays (pg_sleep or general sleep)
  if (/\b(pg_sleep|sleep)\s*\(/i.test(normalized)) {
    score += 8;
  }

  // 2. Logical Tautologies (e.g. 1=1, 'a'='a', or column=column in WHERE clause)
  if (/\b(?:or|and)\s+([a-zA-Z0-9_'\"]+)\s*=\s*\1\b/i.test(normalized)) {
    score += 8;
  }
  if (/\b(?:or|and)\s+(\d+|'[^']+')\s*=\s*\1\b/i.test(normalized)) {
    score += 8;
  }

  // 3. Unauthorized UNION commands
  if (/\bunion\b.*\bselect\b/i.test(normalized)) {
    score += 6;
  }

  // 4. System Catalog Access
  if (/\b(?:pg_catalog|information_schema|pg_tables|pg_namespace|pg_class|pg_database)\b/i.test(normalized)) {
    score += 5;
  }

  // 5. Stacked query semi-colon injection
  if (/;\s*(select|insert|update|delete|drop|truncate|alter|create)\b/i.test(normalized)) {
    score += 4;
  }

  return score;
}

