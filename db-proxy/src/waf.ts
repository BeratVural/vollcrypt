/**
 * Database Web Application Firewall (WAF) & SQLi protection rules.
 */

// Common SQL Injection patterns
const SQLI_PATTERNS = [
  /\bunion\s+all\s+select\b/i,
  /\bunion\s+select\b/i,
  /\b(or|and)\s+\d+\s*=\s*\d+\b/i,
  /\b(or|and)\s+['"][^'"]*['"]\s*=\s*['"][^'"]*['"]/i,
  /\b(and|or)\s+(?:exists\s*)?\(\s*select\b/i,
  /\b(and|or)\s+([a-zA-Z0-9_'"\(\)]+)\s*=\s*\(?\s*select\b/i,
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

  // 6. Subquery-based injection (e.g. AND (SELECT ...), OR (SELECT ...), or comparative subquery injection)
  if (/\b(?:and|or)\s+(?:exists\s*)?\(\s*select\b/i.test(normalized)) {
    score += 8;
  }
  if (/\b(?:and|or)\s+([a-zA-Z0-9_'"\(\)]+)\s*=\s*\(?\s*select\b/i.test(normalized)) {
    score += 8;
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

function cleanColumnName(name: string): string {
  let cleaned = name.trim();
  if (cleaned.startsWith('"') && cleaned.endsWith('"')) {
    cleaned = cleaned.substring(1, cleaned.length - 1);
  } else if (cleaned.startsWith('`') && cleaned.endsWith('`')) {
    cleaned = cleaned.substring(1, cleaned.length - 1);
  } else if (cleaned.startsWith('[') && cleaned.endsWith(']')) {
    cleaned = cleaned.substring(1, cleaned.length - 1);
  }
  return cleaned;
}

/**
 * Rewrites SQL queries to inject RLS tenant isolation and database-level masking rules.
 */
function rewriteQueryBlock(
  tokens: string[],
  role: string,
  tenantId: string | undefined,
  config: any
): string[] {
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
      const cleanedToken = cleanColumnName(token);
      for (const [colPath, rule] of Object.entries(mask)) {
        const parts = colPath.split('.');
        const fieldName = parts[parts.length - 1];
        const cleanedLower = cleanedToken.toLowerCase();
        const fieldLower = fieldName.toLowerCase();
        const colPathLower = colPath.toLowerCase();

        // Support table aliases like u.credit_card or full paths like users.credit_card or exact column credit_card
        if (
          cleanedLower === fieldLower ||
          cleanedLower === colPathLower ||
          cleanedLower.endsWith('.' + fieldLower)
        ) {
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

  return rewrittenTokens;
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

  const blocks: string[][] = [];
  const operators: string[][] = []; // To store 'UNION' or 'UNION' 'ALL'
  let currentBlock: string[] = [];
  let depth = 0;

  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i];
    const upperToken = token.toUpperCase();

    if (token === '(') depth++;
    else if (token === ')') depth--;

    if (depth === 0 && upperToken === 'UNION') {
      blocks.push(currentBlock);
      currentBlock = [];
      const op = ['UNION'];
      if (tokens[i + 1] && tokens[i + 1].toUpperCase() === 'ALL') {
        op.push('ALL');
        i++;
      }
      operators.push(op);
    } else {
      currentBlock.push(token);
    }
    i++;
  }
  blocks.push(currentBlock);

  // Rewrite each block
  const rewrittenBlocks = blocks.map(block => rewriteQueryBlock(block, role, tenantId, config));

  // Combine them back
  const combinedTokens: string[] = [];
  for (let j = 0; j < rewrittenBlocks.length; j++) {
    combinedTokens.push(...rewrittenBlocks[j]);
    if (j < operators.length) {
      combinedTokens.push(...operators[j]);
    }
  }

  // Reconstruct the SQL query from tokens
  let result = '';
  for (let j = 0; j < combinedTokens.length; j++) {
    const t = combinedTokens[j];
    if (j > 0) {
      const prev = combinedTokens[j - 1];
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

export function identifyAggregates(sql: string): boolean[] {
  const normalized = normalizeQuery(sql);
  const tokens = tokenizeSql(normalized);

  // Find the first SELECT token
  let selectIdx = -1;
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].toUpperCase() === 'SELECT') {
      selectIdx = i;
      break;
    }
  }
  if (selectIdx === -1) return [];

  // Find the matching FROM token for the main SELECT (at depth 0)
  let fromIdx = -1;
  let depth = 0;
  for (let i = selectIdx + 1; i < tokens.length; i++) {
    const t = tokens[i].toUpperCase();
    if (t === '(') depth++;
    else if (t === ')') depth--;
    else if (depth === 0 && t === 'FROM') {
      fromIdx = i;
      break;
    }
  }

  const endIdx = fromIdx !== -1 ? fromIdx : tokens.length;

  // Split projection tokens by commas at depth 0
  const projectionItems: string[][] = [];
  let currentItem: string[] = [];
  depth = 0;
  for (let i = selectIdx + 1; i < endIdx; i++) {
    const t = tokens[i];
    if (t === '(') depth++;
    else if (t === ')') depth--;

    if (depth === 0 && t === ',') {
      projectionItems.push(currentItem);
      currentItem = [];
    } else {
      currentItem.push(t);
    }
  }
  if (currentItem.length > 0) {
    projectionItems.push(currentItem);
  }

  return projectionItems.map(item => {
    if (item.length === 0) return false;

    // Find the expression part before the alias
    let exprTokens = [...item];
    
    // Check for "AS" keyword at depth 0
    let asIdx = -1;
    let d = 0;
    for (let i = 0; i < item.length; i++) {
      const t = item[i];
      if (t === '(') d++;
      else if (t === ')') d--;
      else if (d === 0 && t.toUpperCase() === 'AS') {
        asIdx = i;
        break;
      }
    }

    if (asIdx !== -1) {
      exprTokens = item.slice(0, asIdx);
    } else {
      // Check if there is an implicit alias (multiple tokens at depth 0)
      const depth0Indices: number[] = [];
      let curDepth = 0;
      for (let i = 0; i < item.length; i++) {
        const t = item[i];
        if (t === '(') curDepth++;
        else if (t === ')') curDepth--;
        else if (curDepth === 0) {
          depth0Indices.push(i);
        }
      }
      if (depth0Indices.length >= 2) {
        const lastDepth0Idx = depth0Indices[depth0Indices.length - 1];
        exprTokens = item.slice(0, lastDepth0Idx);
      }
    }

    if (exprTokens.length === 0) return false;

    // Check if exprTokens start with avg, sum, count (either function call or column name)
    const firstToken = exprTokens[0].toLowerCase();
    return firstToken.startsWith('avg') || firstToken.startsWith('sum') || firstToken.startsWith('count');
  });
}

export function extractProjectionColumns(sql: string): string[] {
  const normalized = normalizeQuery(sql);
  const tokens = tokenizeSql(normalized);

  // Find the first SELECT token
  let selectIdx = -1;
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].toUpperCase() === 'SELECT') {
      selectIdx = i;
      break;
    }
  }
  if (selectIdx === -1) return [];

  // Find the matching FROM token
  let fromIdx = -1;
  let depth = 0;
  for (let i = selectIdx + 1; i < tokens.length; i++) {
    const t = tokens[i].toUpperCase();
    if (t === '(') depth++;
    else if (t === ')') depth--;
    else if (depth === 0 && t === 'FROM') {
      fromIdx = i;
      break;
    }
  }

  const endIdx = fromIdx !== -1 ? fromIdx : tokens.length;

  const projectionItems: string[][] = [];
  let currentItem: string[] = [];
  depth = 0;
  for (let i = selectIdx + 1; i < endIdx; i++) {
    const t = tokens[i];
    if (t === '(') depth++;
    else if (t === ')') depth--;

    if (depth === 0 && t === ',') {
      projectionItems.push(currentItem);
      currentItem = [];
    } else {
      currentItem.push(t);
    }
  }
  if (currentItem.length > 0) {
    projectionItems.push(currentItem);
  }

  return projectionItems.map(item => {
    if (item.length === 0) return '';
    
    // Find alias or column name
    let asIdx = -1;
    let d = 0;
    for (let i = 0; i < item.length; i++) {
      const t = item[i];
      if (t === '(') d++;
      else if (t === ')') d--;
      else if (d === 0 && t.toUpperCase() === 'AS') {
        asIdx = i;
        break;
      }
    }

    if (asIdx !== -1 && item[asIdx + 1]) {
      return cleanColumnName(item[asIdx + 1]);
    }

    // Check implicit alias
    const depth0Indices: number[] = [];
    let curDepth = 0;
    for (let i = 0; i < item.length; i++) {
      const t = item[i];
      if (t === '(') curDepth++;
      else if (t === ')') curDepth--;
      else if (curDepth === 0) {
        depth0Indices.push(i);
      }
    }

    if (depth0Indices.length >= 2) {
      const lastIdx = depth0Indices[depth0Indices.length - 1];
      const lastToken = item[lastIdx];
      if (!['+', '-', '*', '/', 'AND', 'OR'].includes(lastToken.toUpperCase())) {
        return cleanColumnName(lastToken);
      }
    }

    // Otherwise, clean the last token of the expression
    const lastToken = item[item.length - 1];
    return cleanColumnName(lastToken);
  });
}

export function extractTableName(sql: string): string {
  const normalized = normalizeQuery(sql);
  const tokens = tokenizeSql(normalized);
  
  let fromIdx = -1;
  let depth = 0;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i].toUpperCase();
    if (t === '(') depth++;
    else if (t === ')') depth--;
    else if (depth === 0 && t === 'FROM') {
      fromIdx = i;
      break;
    }
  }
  if (fromIdx !== -1 && tokens[fromIdx + 1]) {
    return cleanColumnName(tokens[fromIdx + 1]);
  }
  return 'users'; // default fallback
}



