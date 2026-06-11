/**
 * Scans a cell string value for sensitive PII anywhere in the string.
 * If PII is discovered, applies masking to the matching substring.
 * Otherwise, returns the original value.
 */
export declare function scanAndMaskCell(val: string): string;
