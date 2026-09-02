# Walden Authentication & Authorization Specification: Format v1

> **Status:** Published Specification (v1)  
> **Milestone:** M1 · Journal format v1  
> **Rulings Covered:** Ruling 3 of 5 (Repo Identifiers are Caller-Chosen Strings), Ruling 5 of 5 (Creation is a Scope, Not a Knob), Scope Vocabulary & Glob Matching Rules, Built-in Token Format & Storage, Delegated Capability Envelope & Cryptographic Verification, Expiry Semantics, and Single-Line Refusal Formats.

---

## 1. Overview and Security Model

Walden answers exactly one authorization question before serving any Git HTTP request:
> **"Does this token grant action $A$ on repository $R$?"**

Walden defines two complementary, interoperable authentication modes using the same underlying scope vocabulary and repository identifier rules:

1. **Built-in Mode (Default):** Static bearer tokens minted by the server's CLI (`walden token create`), stored hashed (SHA-256) in a local store and journaled to the `_meta` stream.
2. **Delegated Mode:** Ephemeral capability tokens minted by an external authority, signed with Ed25519 against a single trusted public key (`WALDEN_AUTH_TRUST`). Verified purely locally with zero network calls, zero callbacks, and zero external dependencies.

```
                  Git Client Request (HTTP Smart Protocol)
                                    │
                                    ▼
                  ┌───────────────────────────────────┐
                  │ Extract Bearer Token & Action A   │
                  │ Target Repository Identifier R    │
                  └─────────────────┬─────────────────┘
                                    │
                   Is WALDEN_AUTH_TRUST configured?
                                    │
                    ┌───────────────┴───────────────┐
                    ▼ YES                           ▼ NO
        ┌───────────────────────┐       ┌───────────────────────┐
        │  Delegated Mode       │       │  Built-in Mode        │
        │  - Verify Ed25519 sig │       │  - Hash token SHA-256 │
        │  - Check TTL / Expiry │       │  - Lookup in Store    │
        │  - Extract Scopes     │       │  - Extract Scopes     │
        └───────────┬───────────┘       └───────────┬───────────┘
                    │                               │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                  ┌───────────────────────────────────┐
                  │ Evaluate Scopes against (A, R)    │
                  │ Match Globs (*, prefix, infix)    │
                  └─────────────────┬─────────────────┘
                                    │
                       ┌────────────┴────────────┐
                       ▼ YES                     ▼ NO
                 [Allow Request]           [Refuse (1-line)]
```

---

## 2. Repository Identifiers (Ruling 3)

### 2.1 The Flat Namespace Principle
Walden enforces a strictly flat repository namespace. There are no subdirectories, user directories, organization trees, or nested hierarchies. Repositories are stored directly on the data volume as bare Git repositories named `<repo-id>.git`.

Walden is deliberately agnostic about whether repository identifiers are opaque IDs (e.g. `r_8f3a2b1c90de`) or human-chosen names (e.g. `blog-backend`, `api.v2-service`). Opacity is an application-layer concern; flatness is the storage principle.

### 2.2 Character Set and Syntax
A valid repository identifier MUST satisfy all of the following rules:

1. **Allowed Character Set:** ASCII letters (`a-z`, `A-Z`), digits (`0-9`), period (`.`), hyphen (`-`), and underscore (`_`). Regular expression: `^[a-zA-Z0-9._-]+$`.
2. **Length Bounds:** Minimum length of **1** character; maximum length of **100** characters.
3. **Leading and Trailing Boundaries:** MUST start and end with an alphanumeric character or underscore (`[a-zA-Z0-9_]`). A repository identifier MUST NOT begin or end with a period (`.`) or hyphen (`-`).
4. **No Path Traversal:** MUST NOT contain consecutive periods (`..`).
5. **No Slashes:** MUST NOT contain forward slashes (`/`) or backslashes (`\`).
6. **No Control Characters or Whitespace:** MUST NOT contain ASCII control characters (`0x00`–`0x1F`, `0x7F`) or whitespace (`0x20`, `\t`, `\n`, `\r`).
7. **No Reserved Names:** The identifier `_meta` is reserved for the journal meta stream and MUST NOT be used as a repository identifier.

### 2.3 Identifier Validation Refusals
When an invalid repository identifier is encountered, Walden rejects the request immediately with a single-line refusal:

| Violation | Refusal Error String |
| :--- | :--- |
| **Empty Identifier** | `refusal: invalid repository identifier: identifier cannot be empty (provide a valid repository identifier matching [a-zA-Z0-9._-])` |
| **Exceeds Max Length** | `refusal: invalid repository identifier: length <N> exceeds maximum of 100 characters (use a repository identifier between 1 and 100 characters)` |
| **Invalid Characters** | `refusal: invalid repository identifier: contains invalid character '<c>' (allowed characters are [a-zA-Z0-9._-])` |
| **Path Traversal (`..`)** | `refusal: invalid repository identifier: path traversal '..' is not allowed (walden repositories use a flat namespace without directory traversal)` |
| **Leading/Trailing Dot or Dash** | `refusal: invalid repository identifier: identifier cannot start or end with '.' or '-' (ensure repository identifier starts and ends with [a-zA-Z0-9_])` |
| **Contains Slashes** | `refusal: invalid repository identifier: slashes are not allowed (walden repositories use a flat namespace without hierarchy)` |
| **Reserved Name `_meta`** | `refusal: invalid repository identifier: '_meta' is a reserved journal stream name (choose a different repository identifier)` |

---

## 3. Scope Vocabulary (Ruling 5)

### 3.1 Creation is a Scope, Not a Knob
Creation of repositories is authorized via permissions (`c`) rather than a server-wide configuration flag or knob. This eliminates a configuration knob, supports multi-tenant isolation policies per token, and consolidates all access control into a single unified vocabulary.

### 3.2 Action Vocabulary
Walden recognizes three fundamental actions:

| Action Code | Name | Permitted Operations |
| :---: | :--- | :--- |
| **`r`** | **Read** | `GET /{repo}/info/refs?service=git-upload-pack`<br>`POST /{repo}/git-upload-pack` (fetch, clone) |
| **`w`** | **Write** | `GET /{repo}/info/refs?service=git-receive-pack`<br>`POST /{repo}/git-receive-pack` (push to existing repo) |
| **`c`** | **Create** | Implicit repository creation on first push (`POST /{repo}/git-receive-pack` when repository does not yet exist on disk/journal) |

### 3.3 Scope Syntax
A scope string defines authorized actions over a set of repositories matching a glob pattern:
```
<actions>:<pattern>
```

- **`<actions>`**: A non-empty string consisting of any permutation of distinct action characters: `r`, `w`, `c`.
  - Valid action strings: `r`, `w`, `c`, `rw`, `rc`, `wc`, `rwc` (or any permutation such as `wr`, `crw`).
  - Canonical ordering: `r`, `w`, `c` (i.e. `rwc`).
- **`<pattern>`**: A glob pattern evaluated against repository identifiers.
- **Separator:** Exactly one colon (`:`).

#### Common Scope Examples
- `rwc:*` — Full administrative control (read, write, create any repository). Standard default for single-tenant instances.
- `rw:blog-*` — Read and write any existing repository starting with `blog-` (cannot create new repos).
- `rwc:user-sandbox-*` — Read, write, and create repositories starting with `user-sandbox-`.
- `r:*` — Read-only access to all repositories.
- `r:docs` — Read-only access specifically to the repository `docs`.
- `w:metrics-collector` — Write-only access to existing repository `metrics-collector`.

### 3.4 Multi-Scope Evaluation Rules
A token may carry one or more scopes. Access for action $A$ on repository $R$ is granted if and only if **at least one** scope in the token satisfies both conditions:
1. The scope's action set contains $A$.
2. The scope's glob pattern matches $R$.

If a push request targets a repository that does not exist:
- The operation requires action `c` (to create the repository) AND action `w` (to accept the pushed ref transaction).
- If the token grants `c` and `w` (e.g. `rwc:*` or `wc:project-*`), the repository is initialized and the push proceeds.
- If the token grants `w` but lacks `c`, the push is refused with:
  `refusal: repository not found: repository '<repo>' does not exist and token lacks create scope 'c' (request create scope 'c' or push to an existing repository)`

---

## 4. Glob Matching Rules

### 4.1 Pattern Syntax
A glob pattern consists of allowed repository identifier characters (`[a-zA-Z0-9._-]`) and the wildcard character `*`.

### 4.2 Matching Semantics
1. **Wildcard `*`:** Matches zero or more valid repository identifier characters (`[a-zA-Z0-9._-]`).
2. **Exact Match:** A pattern without `*` (e.g. `repo-alpha`) matches only the identical string `repo-alpha`.
3. **Universal Wildcard:** `*` matches every valid repository identifier.
4. **Prefix Pattern:** `prefix-*` matches any identifier starting with `prefix-` followed by zero or more valid characters.
5. **Suffix Pattern:** `*-suffix` matches any identifier ending with `-suffix` preceded by zero or more valid characters.
6. **Infix / Multi-Wildcard:** `a-*-b` or `proj-*-svc-*` matches strings starting with `a-` and ending with `-b`, or matching the intermediate components in sequence.
7. **No Directory Recursion:** Since the namespace is flat, `*` does not cross directory boundaries (slashes are invalid in identifiers).

---

## 5. Built-in Token Format and Storage

### 5.1 Token Construction
Built-in tokens are minted by the CLI (`walden token create`):
- **Raw Token String:** Prefix `walden_` followed by 32 cryptographically secure random bytes (`crypto/rand`) encoded as URL-safe unpadded base64 or lowercase hex (e.g. `walden_k9x2mP...` or `walden_8f3a...`).
- **Storage Hash:** The server never stores raw tokens. Tokens are hashed with SHA-256 (`crypto/sha256`) and formatted as:
  ```
  sha256:<64-lowercase-hex>
  ```

### 5.2 Meta Stream Record (`token_create`)
When a built-in token is created, a record is conditionally appended to the `_meta` stream in the journal, so that replaying the journal onto an empty disk brings the token table back with the repositories. The record is defined normatively by the [journal specification, section 4.3](../../journal/v1/README.md#43-token-creation-records-token_create); this is the golden journal's own record, byte for byte:
```json
{
  "version": "v1",
  "stream": "_meta",
  "seq": "1",
  "type": "token_create",
  "token_id": "tok_admin_01",
  "token_hash": "sha256:b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb",
  "scopes": [
    "rwc:*"
  ],
  "timestamp": "2026-08-31T00:01:00Z"
}
```

The token is `tok_admin_01` of [`fixtures/builtin_tokens.json`](fixtures/builtin_tokens.json), and `token_hash` is the hash of section 5.1 over that token's raw string — the two fixture sets describe one instance. `scopes` is an array because a token may carry more than one (section 3.4); the journal spec's section 4.3 shows `tok_writer_02` and its two.

These are journal records, so their `seq` field is a JSON string holding its exact decimal form — here and in Section 5.3 — and the normative rule is [journal specification section 1.1](../../journal/v1/README.md#11-sequence-numbers-are-json-strings), not restated here.

### 5.3 Token Revocation (`token_revoke`)
Revoking a token appends a `token_revoke` record to the `_meta` stream, defined normatively by the [journal specification, section 4.4](../../journal/v1/README.md#44-token-revocation-records-token_revoke). Again the golden journal's own record, which revokes the token created above:
```json
{
  "version": "v1",
  "stream": "_meta",
  "seq": "3",
  "type": "token_revoke",
  "token_id": "tok_admin_01",
  "token_hash": "sha256:b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb",
  "timestamp": "2026-08-31T00:08:00Z"
}
```

---

## 6. Delegated Capability Tokens

### 6.1 Envelope Format
Delegated capability tokens are stateless, cryptographically signed bearer tokens. They are transmitted in Git HTTP requests via the standard `Authorization` header:
```
Authorization: Bearer <compact-token>
```
or via HTTP Basic authentication (where `<compact-token>` is supplied as the password with any username or username `walden`).

### 6.2 Compact Token Representation
The standard wire format is a dot-separated compact string:
```
v1.<payload-base64url>.<signature-base64url>
```
- **`v1`**: Format version prefix.
- **`<payload-base64url>`**: UTF-8 encoded JSON payload (see Section 6.3) encoded with standard URL-safe base64 without padding (`base64.RawURLEncoding`).
- **`<signature-base64url>`**: 64-byte Ed25519 signature encoded with URL-safe base64 without padding (`base64.RawURLEncoding`) or formatted as `ed25519:<128-hex>`.

Alternatively, Walden accepts a structured JSON envelope string:
```json
{
  "version": "v1",
  "payload": {
    "id": "cap_01j7abc",
    "issuer": "forge.example.com",
    "subject": "user_42",
    "scopes": ["rw:blog-*", "r:docs"],
    "issued_at": "2026-09-01T12:00:00Z",
    "expires_at": "2026-09-01T13:00:00Z",
    "not_before": "2026-09-01T12:00:00Z"
  },
  "signature": "ed25519:2ea7c2e8e15acf84573875fd8f94da0dca543fe8080c0a846d126ae3ba0a1a977af7a9fdedd920e8bb16b36c75184638d79e04cfa530b889f76e19a0823d0c07"
}
```

### 6.3 Capability Payload Schema
```json
{
  "version": "v1",
  "id": "cap_01j7abc123456789",
  "issuer": "forge.example.com",
  "subject": "user_42",
  "scopes": [
    "rw:blog-*",
    "r:docs"
  ],
  "issued_at": "2026-09-01T12:00:00Z",
  "expires_at": "2026-09-01T13:00:00Z",
  "not_before": "2026-09-01T12:00:00Z"
}
```

| Field | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `version` | string | **YES** | Format version; MUST be `"v1"`. |
| `id` | string | **YES** | Unique capability identifier (e.g. `cap_01j7...`). |
| `issuer` | string | NO | Identifier of the issuing authority. |
| `subject` | string | NO | Identifier of the authorized subject/principal. |
| `scopes` | array of strings | **YES** | Array of one or more scope strings (`<actions>:<pattern>`). |
| `issued_at` | string | **YES** | RFC 3339 / ISO 8601 UTC timestamp of token generation. |
| `expires_at` | string | **YES** | RFC 3339 / ISO 8601 UTC timestamp of token expiration. Strictly required. |
| `not_before` | string | NO | RFC 3339 / ISO 8601 UTC timestamp before which token is not valid. |

### 6.4 Canonical Signing Payload
The Ed25519 signature is computed over deterministic UTF-8 bytes structured as follows:
```
walden-auth-capability:v1\n
id:<id>\n
issuer:<issuer>\n
subject:<subject>\n
scope:<scope-1>\n
scope:<scope-2>\n
issued_at:<issued_at>\n
expires_at:<expires_at>\n
not_before:<not_before>\n
```

- **Header:** `walden-auth-capability:v1\n`
- **ID:** `id:<id>\n`
- **Issuer:** `issuer:<issuer>\n` (omitted if `issuer` is empty)
- **Subject:** `subject:<subject>\n` (omitted if `subject` is empty)
- **Scopes:** Emitted in array order: `scope:<scope>\n`
- **Issued At:** `issued_at:<issued_at>\n`
- **Expires At:** `expires_at:<expires_at>\n`
- **Not Before:** `not_before:<not_before>\n` (omitted if `not_before` is empty)
- Every line terminates with newline (`\n`, `0x0A`).

### 6.5 Expiry and Time Evaluation Semantics
1. **Local Evaluation:** Verification evaluates the server's local clock (`time.Now().UTC()`) against `expires_at` and `not_before`. No network calls or clock sync protocols are performed.
2. **Expired Token:** If $\text{current\_time} \ge \text{expires\_at}$, the token is invalid and MUST be rejected immediately:
   `refusal: capability expired: token expired at <expires_at> (current time <now>) (request a fresh token from the issuer)`
3. **Not-Yet-Valid Token:** If `not_before` is present and $\text{current\_time} < \text{not\_before}$:
   `refusal: capability not yet valid: token is not valid until <not_before> (current time <now>) (wait until token activation time)`
4. **Missing Expiry:** A capability payload without a valid `expires_at` timestamp is malformed and MUST be rejected:
   `refusal: invalid capability: missing 'expires_at' timestamp (delegated capabilities must specify a finite expiration time)`

---

## 7. Single-Line Refusals Summary

Every operator-facing refusal in Walden is formatted strictly on a single line following the pattern `<what>: <why> (<fix>)` per `PHILOSOPHY.md` and `internal/refusal`:

| Error Category | Single-Line Refusal Format |
| :--- | :--- |
| **Missing Token** | `refusal: unauthorized: missing authentication token (provide token via Bearer header or HTTP Basic auth)` |
| **Invalid Built-in Token** | `refusal: unauthorized: invalid or revoked token (verify token credentials or mint a new token with 'walden token create')` |
| **Delegated Mode Disabled** | `refusal: unauthorized: delegated capability auth is not enabled on this server (configure WALDEN_AUTH_TRUST or use a built-in token)` |
| **Malformed Token Envelope** | `refusal: invalid capability: malformed token envelope (<reason>) (provide a valid v1 capability token)` |
| **Invalid Signature** | `refusal: invalid signature: capability signature verification failed (verify token was signed with the trusted WALDEN_AUTH_TRUST key)` |
| **Capability Expired** | `refusal: capability expired: token expired at <expires_at> (current time <now>) (request a fresh token from the issuer)` |
| **Capability Not Yet Valid** | `refusal: capability not yet valid: token is not valid until <not_before> (current time <now>) (wait until token activation time)` |
| **Insufficient Scope (Forbidden)** | `refusal: forbidden: token does not grant action '<action>' on repository '<repo>' (request scope '<action>:<repo>' from administrator or issuer)` |
| **Missing Create Scope** | `refusal: repository not found: repository '<repo>' does not exist and token lacks create scope 'c' (request create scope 'c' or push to an existing repository)` |
| **Invalid Repository ID** | `refusal: invalid repository identifier: <reason> (<remedy>)` |
| **Invalid Scope Syntax** | `refusal: invalid scope: <reason> (use format <actions>:<pattern> with actions from [r,w,c])` |
