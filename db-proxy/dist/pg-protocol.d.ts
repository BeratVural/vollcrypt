import { Buffer } from 'buffer';
export interface StartupParams {
    user?: string;
    database?: string;
    [key: string]: string | undefined;
}
/**
 * Parses a PostgreSQL StartupMessage and extracts parameters like username and database name.
 */
export declare function parseStartupMessage(buf: Buffer): StartupParams;
/**
 * Parses a PostgreSQL RowDescription ('T') packet to extract column names.
 */
export declare function parseRowDescription(buf: Buffer): string[];
/**
 * Parses a PostgreSQL DataRow ('D') packet into an array of Buffer values (or null).
 */
export declare function parseDataRow(buf: Buffer): (Buffer | null)[];
/**
 * Reconstructs a valid PostgreSQL DataRow ('D') packet from values.
 */
export declare function serializeDataRow(values: (Buffer | null)[]): Buffer;
/**
 * Buffer-based stream chunk framer that outputs complete PostgreSQL messages.
 */
export declare class PostgresStreamParser {
    private buffer;
    append(data: Buffer): Buffer[];
}
export interface ParameterStatus {
    name: string;
    value: string;
}
/**
 * Parses a PostgreSQL ParameterStatus ('S') packet.
 */
export declare function parseParameterStatus(buf: Buffer): ParameterStatus | null;
/**
 * Serializes a PostgreSQL ParameterStatus ('S') packet.
 */
export declare function serializeParameterStatus(name: string, value: string): Buffer;
/**
 * Serializes a PostgreSQL PasswordMessage ('p') packet.
 */
export declare function serializePasswordMessage(password: string): Buffer;
