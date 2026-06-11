"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.QueryAnomalyScorer = void 0;
exports.tokenizeQuery = tokenizeQuery;
exports.getQueryVector = getQueryVector;
exports.calculateCosineSimilarity = calculateCosineSimilarity;
/**
 * Tokenizes a SQL query into semantic keyword/literal tokens, stripping numbers and string literals.
 */
function tokenizeQuery(query) {
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
function getQueryVector(tokens) {
    const vector = {};
    for (const token of tokens) {
        vector[token] = (vector[token] || 0) + 1;
    }
    return vector;
}
/**
 * Calculates the Cosine Similarity between two term-frequency vectors.
 */
function calculateCosineSimilarity(vec1, vec2) {
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
class QueryAnomalyScorer {
    userBaselineVectors = {};
    /**
     * Learns a baseline query vector for a user.
     */
    learnBaseline(username, sampleQueries) {
        const combinedVector = {};
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
    getAnomalyScore(username, query) {
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
exports.QueryAnomalyScorer = QueryAnomalyScorer;
