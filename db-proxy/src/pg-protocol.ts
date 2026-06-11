import { Buffer } from 'buffer';

export interface StartupParams {
  user?: string;
  database?: string;
  [key: string]: string | undefined;
}

/**
 * Parses a PostgreSQL StartupMessage and extracts parameters like username and database name.
 */
export function parseStartupMessage(buf: Buffer): StartupParams {
  // StartupMessage structure:
  // 4 bytes: length
  // 4 bytes: protocol version (196608 = 3.0)
  // key-value pairs (null-terminated string key, null-terminated string value)
  // ends with a single null byte
  const params: StartupParams = {};
  if (buf.length < 8) return params;

  let offset = 8;
  while (offset < buf.length - 1) {
    // Read key
    const keyNull = buf.indexOf(0, offset);
    if (keyNull === -1 || keyNull === offset) break;
    const key = buf.toString('utf8', offset, keyNull);
    offset = keyNull + 1;

    // Read value
    const valNull = buf.indexOf(0, offset);
    if (valNull === -1) break;
    const val = buf.toString('utf8', offset, valNull);
    offset = valNull + 1;

    params[key] = val;
  }
  return params;
}

/**
 * Parses a PostgreSQL RowDescription ('T') packet to extract column names.
 */
export function parseRowDescription(buf: Buffer): string[] {
  // RowDescription structure:
  // 1 byte: 'T'
  // 4 bytes: length
  // 2 bytes: number of fields
  // For each field:
  //   String: column name (null-terminated)
  //   4 bytes: table OID
  //   2 bytes: column attribute number
  //   4 bytes: data type OID
  //   2 bytes: data type size
  //   4 bytes: type modifier
  //   2 bytes: format code (0 = text, 1 = binary)
  if (buf.length < 7) return [];
  const fieldCount = buf.readInt16BE(5);
  let offset = 7;
  const columnNames: string[] = [];

  for (let i = 0; i < fieldCount; i++) {
    const nullIdx = buf.indexOf(0, offset);
    if (nullIdx === -1) break;
    const name = buf.toString('utf8', offset, nullIdx);
    columnNames.push(name);
    offset = nullIdx + 1; // skip null byte
    offset += 4; // table OID
    offset += 2; // column attribute number
    offset += 4; // data type OID
    offset += 2; // data type size
    offset += 4; // type modifier
    offset += 2; // format code
  }
  return columnNames;
}

/**
 * Parses a PostgreSQL DataRow ('D') packet into an array of Buffer values (or null).
 */
export function parseDataRow(buf: Buffer): (Buffer | null)[] {
  // DataRow structure:
  // 1 byte: 'D'
  // 4 bytes: length
  // 2 bytes: number of columns
  // For each column:
  //   4 bytes: column value length (Int32). -1 means NULL value.
  //   Value data bytes.
  if (buf.length < 7) return [];
  const colCount = buf.readInt16BE(5);
  let offset = 7;
  const values: (Buffer | null)[] = [];

  for (let i = 0; i < colCount; i++) {
    if (offset + 4 > buf.length) break;
    const valLen = buf.readInt32BE(offset);
    offset += 4;
    if (valLen === -1) {
      values.push(null);
    } else {
      if (offset + valLen > buf.length) break;
      const val = buf.subarray(offset, offset + valLen);
      values.push(val);
      offset += valLen;
    }
  }
  return values;
}

/**
 * Reconstructs a valid PostgreSQL DataRow ('D') packet from values.
 */
export function serializeDataRow(values: (Buffer | null)[]): Buffer {
  const colCount = values.length;
  let totalDataSize = 0;
  for (const val of values) {
    if (val === null) {
      totalDataSize += 4;
    } else {
      totalDataSize += 4 + val.length;
    }
  }

  const msgLen = 4 + 2 + totalDataSize; // length + colCount + data
  const buf = Buffer.alloc(1 + msgLen); // type 'D' + msgLen
  buf.write('D', 0, 'ascii');
  buf.writeInt32BE(msgLen, 1);
  buf.writeInt16BE(colCount, 5);

  let offset = 7;
  for (const val of values) {
    if (val === null) {
      buf.writeInt32BE(-1, offset);
      offset += 4;
    } else {
      buf.writeInt32BE(val.length, offset);
      offset += 4;
      val.copy(buf, offset);
      offset += val.length;
    }
  }

  return buf;
}

/**
 * Buffer-based stream chunk framer that outputs complete PostgreSQL messages.
 */
export class PostgresStreamParser {
  private buffer: Buffer = Buffer.alloc(0);

  public append(data: Buffer): Buffer[] {
    this.buffer = Buffer.concat([this.buffer, data]);
    const messages: Buffer[] = [];

    while (true) {
      if (this.buffer.length === 0) {
        break;
      }

      const firstByte = this.buffer[0];
      if (firstByte === 0) {
        // StartupMessage or SSLRequest (length is first 4 bytes)
        if (this.buffer.length < 4) {
          break;
        }
        const len = this.buffer.readInt32BE(0);
        if (len <= 0 || len > 1024 * 1024) {
          throw new Error(`Invalid PostgreSQL startup message length: ${len}`);
        }
        if (this.buffer.length < len) {
          break;
        }
        messages.push(this.buffer.subarray(0, len));
        this.buffer = this.buffer.subarray(len);
      } else {
        // Standard Message (1 byte type + 4 bytes length)
        if (this.buffer.length < 5) {
          break;
        }
        const len = this.buffer.readInt32BE(1);
        if (len <= 0 || len > 100 * 1024 * 1024) {
          throw new Error(`Invalid PostgreSQL message length: ${len}`);
        }
        if (this.buffer.length < 1 + len) {
          break;
        }
        messages.push(this.buffer.subarray(0, 1 + len));
        this.buffer = this.buffer.subarray(1 + len);
      }
    }

    return messages;
  }
}

export interface ParameterStatus {
  name: string;
  value: string;
}

/**
 * Parses a PostgreSQL ParameterStatus ('S') packet.
 */
export function parseParameterStatus(buf: Buffer): ParameterStatus | null {
  if (buf[0] !== 0x53) return null; // 'S'
  const nameNull = buf.indexOf(0, 5);
  if (nameNull === -1) return null;
  const name = buf.toString('utf8', 5, nameNull);
  const valueNull = buf.indexOf(0, nameNull + 1);
  if (valueNull === -1) return null;
  const value = buf.toString('utf8', nameNull + 1, valueNull);
  return { name, value };
}

/**
 * Serializes a PostgreSQL ParameterStatus ('S') packet.
 */
export function serializeParameterStatus(name: string, value: string): Buffer {
  const nameBuf = Buffer.from(name, 'utf8');
  const valueBuf = Buffer.from(value, 'utf8');
  const msgLen = 4 + nameBuf.length + 1 + valueBuf.length + 1;
  const buf = Buffer.alloc(1 + msgLen);
  buf.write('S', 0, 'ascii');
  buf.writeInt32BE(msgLen, 1);
  nameBuf.copy(buf, 5);
  buf.writeUInt8(0, 5 + nameBuf.length);
  valueBuf.copy(buf, 5 + nameBuf.length + 1);
  buf.writeUInt8(0, 5 + nameBuf.length + 1 + valueBuf.length);
  return buf;
}

/**
 * Serializes a PostgreSQL PasswordMessage ('p') packet.
 */
export function serializePasswordMessage(password: string): Buffer {
  const passBuf = Buffer.from(password, 'utf8');
  const msgLen = 4 + passBuf.length + 1;
  const buf = Buffer.alloc(1 + msgLen);
  buf.write('p', 0, 'ascii');
  buf.writeInt32BE(msgLen, 1);
  passBuf.copy(buf, 5);
  buf.writeUInt8(0, 5 + passBuf.length);
  return buf;
}


