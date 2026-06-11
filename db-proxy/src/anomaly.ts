/**
 * Tokenizes a SQL query into semantic keyword/literal tokens, stripping numbers and string literals.
 */
export function tokenizeQuery(query: string): string[] {
  // Replace string literals with a placeholder
  let processed = query.replace(/'[^']*'/g, 'STRING_LITERAL');
  // Replace numbers with a placeholder
  processed = processed.replace(/\b\d+\b/g, 'NUMERIC_LITERAL');
  // Split by whitespace and symbols
  const tokens = processed.toLowerCase().match(/\b[a-z_0-9]+|[^\s\w]/gi);
  return tokens || [];
}

/**
 * Generates a term-frequency vector from a token array.
 */
export function getQueryVector(tokens: string[]): Record<string, number> {
  const vector: Record<string, number> = {};
  for (const token of tokens) {
    vector[token] = (vector[token] || 0) + 1;
  }
  return vector;
}

/**
 * Calculates the Cosine Similarity between two term-frequency vectors.
 */
export function calculateCosineSimilarity(
  vec1: Record<string, number>,
  vec2: Record<string, number>
): number {
  let dotProduct = 0;
  let magnitudeVec1 = 0;
  let magnitudeVec2 = 0;

  // Union of terms
  const allTerms = new Set([...Object.keys(vec1), ...Object.keys(vec2)]);

  for (const term of allTerms) {
    const val1 = vec1[term] || 0;
    const val2 = vec2[term] || 0;
    dotProduct += val1 * val2;
    magnitudeVec1 += val1 * val1;
    magnitudeVec2 += val2 * val2;
  }

  if (magnitudeVec1 === 0 || magnitudeVec2 === 0) {
    return 0.0;
  }

  return dotProduct / (Math.sqrt(magnitudeVec1) * Math.sqrt(magnitudeVec2));
}

export class QueryAnomalyScorer {
  private userBaselineVectors: Record<string, Record<string, number>> = {};

  /**
   * Learns a baseline query vector for a user.
   */
  public learnBaseline(username: string, sampleQueries: string[]) {
    const combinedVector: Record<string, number> = {};
    let totalTokens = 0;

    for (const query of sampleQueries) {
      const tokens = tokenizeQuery(query);
      totalTokens += tokens.length;
      const vec = getQueryVector(tokens);
      for (const [term, val] of Object.entries(vec)) {
        combinedVector[term] = (combinedVector[term] || 0) + val;
      }
    }

    // Normalize
    if (totalTokens > 0) {
      for (const term of Object.keys(combinedVector)) {
        combinedVector[term] = combinedVector[term] / totalTokens;
      }
    }

    this.userBaselineVectors[username] = combinedVector;
  }

  /**
   * Evaluates the anomaly threat score of a query for a given user.
   * Returns a score between 0.0 (completely normal) and 1.0 (highly anomalous).
   */
  public getAnomalyScore(username: string, query: string): number {
    const baseline = this.userBaselineVectors[username];
    if (!baseline) {
      // No baseline learned yet, assume normal to avoid false-positives
      return 0.0;
    }

    const currentTokens = tokenizeQuery(query);
    const currentVector = getQueryVector(currentTokens);

    // Normalize current vector
    const totalCurrentTokens = currentTokens.length;
    if (totalCurrentTokens > 0) {
      for (const term of Object.keys(currentVector)) {
        currentVector[term] = currentVector[term] / totalCurrentTokens;
      }
    }

    const similarity = calculateCosineSimilarity(baseline, currentVector);
    // Anomaly score is inverse of similarity
    return 1.0 - similarity;
  }
}
