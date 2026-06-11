# db-proxy

A zero-trust, wire-protocol database cryptographic gateway for PostgreSQL. It transparently intercepts query response streams to decrypt and mask encrypted database fields on-the-fly, allowing off-the-shelf BI tools (DBeaver, PowerBI, Tableau) and application clients to access encrypted data securely without modifying database engine logic.

`db-proxy` works in conjunction with `@vollcrypt/db-guard` to enforce field-level security, role-based access control (RBAC), and decryption rate limits at the network layer.

---

## Key Features

- **Protocol-Level Interception**: Intercepts PostgreSQL v3.0 wire traffic to inspect backend `DataRow` packets without parsing or modifying complex SQL command dialects.
- **SSL/TLS Fallback Negotiation**: Auto-refuses database client `SSLRequest` frames by responding with standard protocol fallback indicators, forcing clients to establish unencrypted TCP connections to the local proxy. This eliminates local certificate management overhead.
- **Built-in Database Firewall (Database WAF / SQLi Protection)**: Scans incoming query packets ('Q' Simple Queries and 'P' Parse Extended Queries) to block SQL Injection signatures and unauthorized DDL operations (DROP, TRUNCATE, ALTER) based on the client's role.
- **Dynamic Data Loss Prevention (DLP)**: Scans raw, unencrypted database cell responses for PII formats (Credit Cards, Emails, National IDs, and IBANs) and automatically applies masking filters in transit.
- **Cryptographic Access Control**: Translates query-time column metadata (`RowDescription` packets) to match column tags against RBAC permissions.
- **PostgreSQL Error Frame Mapping**: Generates authentic PostgreSQL error packets (code `42501` - Insufficient Privilege) when an unauthorized client requests columns they are not permitted to decrypt or performs forbidden SQL commands.
- **Fail-Closed Protection**: Shuts down decryption, zeroizes keys in memory, and blocks subsequent queries if the decryption rate limit or access violation threshold is crossed.

---

## Architecture

```mermaid
graph TD
    classDef client fill:#f0db4f,stroke:#333,stroke-width:1px,color:#333;
    classDef proxy fill:#8A2BE2,stroke:#333,stroke-width:1px,color:#fff;
    classDef db fill:#df5c3f,stroke:#333,stroke-width:1px,color:#fff;

    client_app["BI Tool / SQL Client<br>(DBeaver, PowerBI, pg)"]:::client
    db_proxy["Vollcrypt DB-Proxy<br>(TCP Interceptor Port 54320)"]:::proxy
    postgres_db["PostgreSQL Server<br>(Port 5432)"]:::db
    kms_service["KMS Key Provider / HSM"]:::proxy

    subgraph WAF ["1. Database WAF Block"]
        check_sqli["SQLi Scan"]
        check_ddl["DDL Permission Control"]
    end

    subgraph DLP ["2. Response Inspection Block"]
        check_crypt["Decryption Parser (VOLLVALT)"]
        check_pii["DLP PII Scan (CC, Email, ID, IBAN)"]
    end

    client_app -- "1. Send Query" --> db_proxy
    db_proxy --> WAF
    WAF -- "Violation? Yes" --> client_app
    WAF -- "Violation? No" --> postgres_db
    postgres_db -- "2. Return DataRows" --> db_proxy
    db_proxy --> DLP
    DLP -- "3. Decrypt / Mask cells" --> client_app
```

---

## Configuration & Usage

Start the proxy server using the built-in CLI:

```bash
vollcrypt-db-proxy --port 54320 --db-host 127.0.0.1 --db-port 5432 --config config.json
```

### Configuration Options

The proxy is configured via a JSON configuration file (`config.json`). This file defines the database username-to-role mappings, RBAC permissions, masking filters, decryption keys, and security rate limits.

#### Configuration Example (`config.json`):

```json
{
  "key": "0101010101010101010101010101010101010101010101010101010101010101",
  "users": {
    "postgres": { "role": "OWNER", "userId": "usr-admin" },
    "analyst_hr": { "role": "HR_ADMIN", "userId": "usr-hr-01" },
    "analyst_marketing": { "role": "MARKETING", "userId": "usr-mkt-01" }
  },
  "cryptoRbac": {
    "roles": {
      "OWNER": {
        "decrypt": ["users.email", "users.tc_no", "users.credit_card"]
      },
      "HR_ADMIN": {
        "decrypt": ["users.email", "users.tc_no"],
        "mask": {
          "users.credit_card": "credit_card"
        }
      },
      "MARKETING": {
        "decrypt": ["users.email"],
        "mask": {
          "users.tc_no": "tc_no",
          "users.credit_card": "credit_card"
        }
      }
    }
  },
  "rateLimiter": {
    "maxDecryptionsPerSecond": 100,
    "mode": "fail_closed"
  }
}
```

---

## Dynamic Role Mapping & Masking Behavior

When a SQL client connects to the proxy, the proxy parses the connection parameters:

1. **Connection Username**: Resolved to a role context (e.g. connecting as `analyst_hr` maps to the `HR_ADMIN` role).
2. **Query Validation (WAF)**:
   - If SQL Injection signatures are found (e.g. `' OR 1=1`), the query is aborted.
   - If DDL operations (e.g. `DROP TABLE`) are run by a non-`OWNER` role, the query is aborted.
   - An ErrorResponse packet is sent to the client socket, and the query is stopped without ever touching the database server.
3. **Response Inspection (DLP & Decryption)**: 
   - A query returning columns starting with the ciphertext header `VOLLVALT:` is scanned.
     - If the role is authorized to decrypt the column, the proxy returns the plaintext cell.
     - If the role is unauthorized but has a masking rule, the proxy returns the masked cell.
     - If the role is unauthorized and no masking rule is defined, the query aborts immediately. The proxy sends a native PostgreSQL error packet (`42501` - Insufficient Privilege) back to the client.
   - Raw columns (without `VOLLVALT:` prefix) are scanned by the DLP engine. If a cell matches Credit Cards, Emails, National IDs, or IBAN formats, it is dynamically masked before transmission.

---

## Build from Source

Navigate to the `db-proxy` folder and build the package:

```bash
cd db-proxy
npm install
npm run build
```

Run the integration tests:

```bash
npm test
```

---

## Enterprise Features Roadmap

### 1. Post-Quantum mTLS Termination
Implement custom hybrid mTLS handshakes (Ed25519 + ML-DSA-65) for client-to-proxy certificate authentication, cryptographically preventing unauthorized machines from establishing TCP connections to the gateway.

### 2. Cryptographic Connection Pooling
Multiplex client connections into a persistent backend pool to reduce database connection allocation costs, and cache KMS key handshakes locally in memory within the secure cache wrapper.

---

## Licensing

`db-proxy` is dual-licensed under:
- **Open Source:** GNU General Public License v3.0 ([LICENSE-GPL](LICENSE-GPL))
- **Commercial:** Vollcrypt Commercial License ([LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md))

For licensing details or commercial purchases, please contact [berat.vural.tr@gmail.com](mailto:berat.vural.tr@gmail.com).
