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

/**
 * Rewrites SQL queries to inject RLS tenant isolation and database-level masking rules.
 */
/**
 * Tokenizes SQL query string to isolate strings and symbols.
 */
export function tokenizeSql(sql: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inString = false;
  let inDoubleQuote = false;
  let i = 0;
  while (i < sql.length) {
    const char = sql[i];
    if (inString) {
      current += char;
      if (char === "'") {
        if (sql[i + 1] === "'") {
          current += "'"; // escaped single quote
          i++;
        } else {
          inString = false;
          tokens.push(current);
          current = '';
        }
      }
    } else if (inDoubleQuote) {
      current += char;
      if (char === '"') {
        inDoubleQuote = false;
        tokens.push(current);
        current = '';
      }
    } else {
      if (char === "'") {
        if (current) tokens.push(current);
        current = "'";
        inString = true;
      } else if (char === '"') {
        if (current) tokens.push(current);
        current = '"';
        inDoubleQuote = true;
      } else if (/\s/.test(char)) {
        if (current) {
          tokens.push(current);
          current = '';
        }
      } else if ([',', '=', '(', ')', ';', '<', '>', '!'].includes(char)) {
        if (current) {
          tokens.push(current);
          current = '';
        }
        tokens.push(char);
      } else {
        current += char;
      }
    }
    i++;
  }
  if (current) tokens.push(current);
  return tokens;
}

/**
 * Rewrites SQL queries to inject RLS tenant isolation and database-level masking rules.
 */
export function rewriteQuery(
  sql: string,
  role: string,
  tenantId: string | undefined,
  config: any
): string {
  const normalized = normalizeQuery(sql);
  const tokens = tokenizeSql(normalized);

  // 1. Identify projection context and inject SQL-level masking expressions
  const mask = config?.cryptoRbac?.roles?.[role]?.mask;
  const rewrittenTokens: string[] = [];
  let inProjection = false;

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    const upperToken = token.toUpperCase();

    if (upperToken === 'SELECT') {
      inProjection = true;
      rewrittenTokens.push(token);
      continue;
    }
    if (upperToken === 'FROM') {
      inProjection = false;
      rewrittenTokens.push(token);
      continue;
    }

    if (inProjection && mask) {
      let foundMaskRule: string | undefined;
      for (const [colPath, rule] of Object.entries(mask)) {
        const parts = colPath.split('.');
        const fieldName = parts[parts.length - 1];
        if (token.toLowerCase() === fieldName.toLowerCase() || token.toLowerCase() === colPath.toLowerCase()) {
          const nextToken = tokens[i + 1];
          if (nextToken !== '=') {
            foundMaskRule = rule as string;
            break;
          }
        }
      }

      if (foundMaskRule) {
        let maskExpr = `'***'`;
        const colName = token;
        if (foundMaskRule === 'credit_card') {
          maskExpr = `'XXXX-XXXX-XXXX-' || right(${colName}, 4)`;
        } else if (foundMaskRule === 'tc_no') {
          maskExpr = `left(${colName}, 3) || 'XXXXXX' || right(${colName}, 2)`;
        } else if (foundMaskRule === 'email') {
          maskExpr = `'***@***.***'`;
        }
        rewrittenTokens.push(`${maskExpr} AS ${colName}`);
        continue;
      }
    }

    rewrittenTokens.push(token);
  }

  // 2. Inject RLS tenant isolation condition
  if (tenantId) {
    let whereIndex = -1;
    for (let i = 0; i < rewrittenTokens.length; i++) {
      if (rewrittenTokens[i].toUpperCase() === 'WHERE') {
        whereIndex = i;
        break;
      }
    }

    if (whereIndex !== -1) {
      rewrittenTokens.splice(whereIndex + 1, 0, `tenant_id = '${tenantId}'`, 'AND');
    } else {
      let insertIndex = rewrittenTokens.length;
      for (let i = 0; i < rewrittenTokens.length; i++) {
        const t = rewrittenTokens[i].toUpperCase();
        if (['GROUP', 'ORDER', 'LIMIT', 'UNION', 'HAVING', ';'].includes(t)) {
          insertIndex = i;
          break;
        }
      }
      rewrittenTokens.splice(insertIndex, 0, 'WHERE', `tenant_id = '${tenantId}'`);
    }
  }

  // Reconstruct the SQL query from tokens
  let result = '';
  for (let i = 0; i < rewrittenTokens.length; i++) {
    const t = rewrittenTokens[i];
    if (i > 0) {
      const prev = rewrittenTokens[i - 1];
      if (['(', ';'].includes(prev) || [',', ';', ')', '('].includes(t)) {
        result += t;
      } else {
        result += ' ' + t;
      }
    } else {
      result += t;
    }
  }

  return result;
}

/**
 * Generates Laplace noise for Differential Privacy.
 */
export function generateLaplaceNoise(scale: number): number {
  const u = Math.random() - 0.5;
  return -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
}

/**
 * Generates mock Remote Attestation Quote for secure enclave execution verification.
 */
export function getMockAttestationReport(): any {
  return {
    attestation_type: "Intel SGX Quote",
    mrenclave: "d3f4b5a6c7e8f901a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f901a2b3c4d5e6",
    mrsigner: "a1b2c3d4e5f60102030405060708090a0b0c0d0e0f101112131415161718191a",
    isv_prod_id: 1,
    isv_svn: 1,
    quote_signature: "30450221008f51a4b9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f802200a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
    enclave_timestamp: new Date().toISOString()
  };
}


