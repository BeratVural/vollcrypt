/**
 * Tokenizes a SQL query into semantic keyword/literal tokens, stripping numbers and string literals.
 */
export declare function tokenizeQuery(query: string): string[];
/**
 * Generates a term-frequency vector from a token array.
 */
export declare function getQueryVector(tokens: string[]): Record<string, number>;
/**
 * Calculates the Cosine Similarity between two term-frequency vectors.
 */
export declare function calculateCosineSimilarity(vec1: Record<string, number>, vec2: Record<string, number>): number;
export declare class QueryAnomalyScorer {
    private userBaselineVectors;
    /**
     * Learns a baseline query vector for a user.
     */
    learnBaseline(username: string, sampleQueries: string[]): void;
    /**
     * Evaluates the anomaly threat score of a query for a given user.
     * Returns a score between 0.0 (completely normal) and 1.0 (highly anomalous).
     */
    getAnomalyScore(username: string, query: string): number;
}
