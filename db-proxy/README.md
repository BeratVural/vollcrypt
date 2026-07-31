# db-proxy

A zero-trust, wire-protocol database cryptographic gateway for PostgreSQL. It transparently intercepts query response streams to decrypt and mask encrypted database fields on-the-fly, allowing off-the-shelf BI tools (DBeaver, PowerBI, Tableau) and application clients to access encrypted data securely without modifying database engine logic.

`db-proxy` works in conjunction with `@vollcrypt/db-guard` to enforce field-level security, role-based access control (RBAC), and decryption rate limits at the network layer.

---

## Key Features

- **Protocol-Level Interception**: Intercepts PostgreSQL v3.0 wire traffic to inspect backend `DataRow` packets without parsing or modifying complex SQL command dialects.
- **Explicit TLS Trust Configuration**: Loads a persistent certificate and private key from `tls.certPath` and `tls.keyPath`. Without them, PostgreSQL `SSLRequest` is refused; ephemeral self-signed certificates require the explicit development-only `allowEphemeralSelfSigned` opt-in.
- **Built-in Database Firewall (Database WAF / SQLi Protection)**: Scans incoming query packets (`Q` Simple Queries and `P` Parse Extended Queries) to block SQL injection signatures and unauthorized DDL/DCL operations based on the client's role.
- **Dynamic Data Loss Prevention (DLP)**: Scans raw, unencrypted database cell responses for PII formats (Credit Cards, Emails, National IDs, and IBANs) and automatically applies masking filters in transit.
- **Cryptographic Access Control**: Translates query-time column metadata (`RowDescription` packets) to match column tags against RBAC permissions.
- **PostgreSQL Error Frame Mapping**: Generates authentic PostgreSQL error packets (code `42501` - Insufficient Privilege) when an unauthorized client requests columns they are not permitted to decrypt or performs forbidden SQL commands.
- **Fail-Closed Protection**: Shuts down decryption, zeroizes keys in memory, and blocks subsequent queries if the decryption rate limit or access violation threshold is crossed.

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
  "tls": {
    "keyPath": "./secrets/proxy-key.pem",
    "certPath": "./secrets/proxy-cert.pem"
  },
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

`tls.keyPath` and `tls.certPath` must refer to a persistent certificate issued by a CA trusted by clients. `tls.allowEphemeralSelfSigned` is only for isolated development and tests where clients explicitly disable certificate verification.

Cluster mode requires a dedicated `firewall.gossipSecret` of at least 32 characters. It must differ from `firewall.jitSecret` so cluster authentication and JIT token signing remain separate cryptographic contexts.

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

## Driver Security Capability Matrix

`dbType=postgres` is the full-security driver. Alternative drivers expose only the controls that are implemented in their wire-protocol adapters. At startup, db-proxy fails closed if a non-Postgres driver is configured with a security control that it does not implement, so operators cannot accidentally believe a control is active when it is not.

| Control | PostgreSQL | MySQL | MongoDB | MSSQL | Oracle |
| --- | --- | --- | --- | --- | --- |
| WAF query blocking | Yes | Yes | Yes | Yes | Yes |
| Tenant isolation checks | Yes | Yes | Yes | Yes | Yes |
| Crypto-RBAC decrypt authorization | Yes | Yes | Yes | Yes | Yes |
| Decryption rate limiting/fail-closed | Yes | Yes | Yes | Yes | Yes |
| Raw plaintext cell DLP masking | Yes | No | No | No | No |
| JIT approval workflow | Yes | No | No | No | No |
| Anomaly scoring | Yes | No | No | No | No |
| Query QPS firewall rate limits | Yes | No | No | No | No |
| `maxRowsPerQuery` exfiltration cap | Yes | No | No | No | No |
| Query fingerprint allowlist | Yes | No | No | No | No |
| Temporal constraints | Yes | No | No | No | No |
| PostgreSQL `server_version` masking | Yes | No | No | No | No |

For MySQL, MongoDB, MSSQL, and Oracle, enabling unsupported `firewall.*` controls such as `jitApprovalRequired`, `anomalyEngine.enabled`, `fingerprinting.enabled`, `rateLimits.maxQueriesPerSecond`, `maxRowsPerQuery`, `temporalConstraints`, or `versionMask` causes startup to throw an error. Use PostgreSQL for the full gateway security pipeline or disable unsupported controls explicitly for alternative drivers.

## Cluster Security State

Cluster gossip synchronizes banned IP addresses and query-fingerprint allowlist entries. SSO sessions, JIT grants, query QPS counters, and decryption rate counters are not synchronized between proxy processes. db-proxy rejects those local controls when cluster mode is configured and rejects local SSO/JIT registration. Put those controls behind a distributed authorization and rate-limit service, or run a single proxy instance.
