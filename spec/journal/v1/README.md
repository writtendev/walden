# Walden Journal Specification: Format v1

> **Status:** Published Specification (v1)  
> **Milestone:** M1 · Journal format v1  
> **Rulings Covered:** Ruling 1 of 5 (Signing Identity & Genesis), Ruling 2 of 5 (Stream Model & Key Layout), Ruling 3 of 5 (Ref-Transaction Records & Payload Canonicalization), Ruling 4 of 5 (Pack Segments & Content Addressing), Ruling 5 of 5 (Conditional Append, Per-Stream Fencing & CAS Requirement)

---

## 1. Overview and Coordinate Model

The walden journal is an append-only, content-addressed, tamper-evident log stored in S3-compatible object storage.

The journal format defines **`(stream-id, seq)`** as its primary coordinate:
- **`stream-id`**: A string identifying the log stream.
- **`seq`**: A 64-bit unsigned integer (`0` to `18,446,744,073,709,551,615`), zero-indexed, strictly monotonic with no gaps.

Every repository is modeled as an independent stream. The server instance's own internal state — including the server signing identity, key rotations, and token table mutations — is recorded in a reserved **meta stream** (`_meta`).

```
                              (stream-id, seq)
                                      │
               ┌──────────────────────┴──────────────────────┐
               ▼                                             ▼
       Repository Stream                                Meta Stream
    stream-id = "<repo-id>"                         stream-id = "_meta"
 ┌─────────────────────────────┐               ┌─────────────────────────────┐
 │ seq 0: First push ref tx    │               │ seq 0: Genesis (public key) │
 │ seq 1: Second push ref tx   │               │ seq 1: Token create (rwc:*) │
 │ seq 2: Force-push ref tx    │               │ seq 2: Key rotation (...)   │
 └─────────────────────────────┘               └─────────────────────────────┘
```

---

## 2. Server Signing Identity (Ruling 1)

### 2.1 The Signing Identity Lifecycle
The server's signing identity is born with the journal and lives in it:
- **Zero Configuration:** `WALDEN_AUTH_TRUST` is a verification key for inbound capability tokens, *not* a signing key for outbound records. The server generates its own signing keypair on first boot and appends the public key as the journal's **genesis record** — entry zero of the `_meta` stream.
- **Self-Certifying Journal:** A verifier replays from genesis, learns the public key, and checks every subsequent record. No certificate authority, external registry, or sixth configuration knob is required.
- **Algorithm & Encodings:**
  - **Algorithm:** Ed25519 (`crypto/ed25519`).
  - **Public Key Encoding:** `ed25519:<hex>` — prefix `ed25519:` followed by 64 lowercase hexadecimal characters representing the 32-byte public key.
  - **Signature Encoding:** `ed25519:<hex>` — prefix `ed25519:` followed by 128 lowercase hexadecimal characters representing the 64-byte signature.
  - **Private Key:** Stored locally on server disk alongside the token store; never written to object storage.

### 2.2 Security Model and Honest Boundaries
- **Tamper-Evidence, Not Server Trust:** Journal signing provides **tamper-evidence of the history, not protection from a malicious server.** A server that holds the signing key and wishes to lie can sign its lies. Signing guarantees that once written, history in object storage cannot be altered, forged, or spliced by unauthorized third parties or storage providers without failing cryptographic verification.
- **Permanent Private Key Loss:** Losing the private signing key is an unrecoverable-for-signing state. The server can no longer accept new writes or append new records. Existing history in the bucket remains permanently readable, verifiable from genesis forward, and fully restorable.

---

## 3. The Genesis Record (`_meta`, `seq = 0`)

The genesis record establishes the root of trust for the entire journal instance.

- **Location:** `v1/streams/_meta/tx/00000000000000000000.json`
- **Stream:** `_meta`
- **Sequence:** `0`
- **Type:** `"genesis"`

### 3.1 JSON Schema and Field Specification
```json
{
  "version": "v1",
  "stream": "_meta",
  "seq": 0,
  "type": "genesis",
  "public_key": "ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
  "timestamp": "2026-08-31T00:00:00Z"
}
```

| Field | Type | Description |
| :--- | :--- | :--- |
| `version` | string | Format version; MUST be `"v1"`. |
| `stream` | string | MUST be `"_meta"`. |
| `seq` | integer | MUST be `0`. |
| `type` | string | MUST be `"genesis"`. |
| `public_key` | string | Formatted Ed25519 public key (`ed25519:<64-hex>`). |
| `timestamp` | string | ISO-8601 / RFC 3339 UTC timestamp of journal initialization. |

### 3.2 Initialization and Adoption Invariants
1. **First-Boot Minting:** When started against an empty journal prefix, walden generates an Ed25519 keypair and performs a conditional PUT (`If-None-Match: *`) to `v1/streams/_meta/tx/00000000000000000000.json`.
2. **Adoption:** If `_meta` `seq = 0` already exists, walden adopts the existing genesis record and its root identity rather than overwriting it.
3. **No Prior Records:** A journal with transactions but no genesis record at `_meta` `seq = 0` is corrupt; verifiers MUST reject it.

---

## 4. Key Rotation Records (`_meta`, `seq >= 1`)

Signing keys can be rotated without out-of-band coordination by appending a `key_rotation` record to the `_meta` stream.

- **Location:** `v1/streams/_meta/tx/<seq>.json` (where `<seq> >= 1`)
- **Stream:** `_meta`
- **Type:** `"key_rotation"`

### 4.1 JSON Schema and Field Specification
```json
{
  "version": "v1",
  "stream": "_meta",
  "seq": 2,
  "type": "key_rotation",
  "old_public_key": "ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
  "new_public_key": "ed25519:8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
  "timestamp": "2026-08-31T00:02:00Z",
  "signature": "ed25519:8d0d7ae5d2d52ad753cdb533a1db8f8608d85600fc3809333f197e48f65cd03a5f11581b21d5f87c29c1f6adc9b9baad949cae3ac0de73719ab2405c9a241c0e"
}
```

| Field | Type | Description |
| :--- | :--- | :--- |
| `version` | string | Format version; MUST be `"v1"`. |
| `stream` | string | MUST be `"_meta"`. |
| `seq` | integer | Strictly monotonic sequence number ($k \ge 1$). |
| `type` | string | MUST be `"key_rotation"`. |
| `old_public_key` | string | Currently active public key in the verifier's chain (`ed25519:<64-hex>`). |
| `new_public_key` | string | New public key to activate (`ed25519:<64-hex>`), distinct from `old_public_key`. |
| `timestamp` | string | ISO-8601 / RFC 3339 UTC timestamp of rotation. |
| `signature` | string | Ed25519 signature generated by the private key of `old_public_key` over the canonical payload. |

### 4.2 Canonical Signing Payload
The signature is computed over deterministic UTF-8 bytes structured as follows:
```
walden-key-rotation:v1\n
stream:_meta\n
seq:<seq>\n
old_public_key:<old_public_key>\n
new_public_key:<new_public_key>\n
timestamp:<timestamp>\n
```
Each line terminates with a newline (`\n`, `0x0A`).

---

## 5. Ref-Transaction Records (Ruling 3)

The ref-transaction record is the atomic unit of repository history in walden. Every accepted push appends exactly one ref-transaction record to the repository's stream after its packfile segments have been acknowledged by object storage.

- **Location:** `v1/streams/<stream-id>/tx/<seq>.json` (where `<seq> >= 0`)
- **Stream:** `<stream-id>` (matches `^[a-zA-Z0-9._-]+$`, max 255 bytes)
- **Type:** `"ref_update"`

### 5.1 JSON Schema and Field Specification
```json
{
  "version": "v1",
  "stream": "repo-alpha",
  "seq": 0,
  "type": "ref_update",
  "segments": [
    "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"
  ],
  "updates": [
    {
      "ref": "refs/heads/main",
      "old_oid": "0000000000000000000000000000000000000000",
      "new_oid": "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    }
  ],
  "timestamp": "2026-08-31T00:02:00Z",
  "signature": "ed25519:2ea7c2e8e15acf84573875fd8f94da0dca543fe8080c0a846d126ae3ba0a1a977af7a9fdedd920e8bb16b36c75184638d79e04cfa530b889f76e19a0823d0c07"
}
```

| Field | Type | Description |
| :--- | :--- | :--- |
| `version` | string | Format version; MUST be `"v1"`. |
| `stream` | string | Stream identifier (`<stream-id>`). |
| `seq` | integer | Strictly monotonic unsigned 64-bit sequence number ($k \ge 0$). |
| `type` | string | MUST be `"ref_update"`. |
| `segments` | array of strings | List of zero or more 64-character lowercase hexadecimal SHA-256 digests of newly written packfiles. May be empty (`[]`) for operations not introducing new objects (e.g. branch deletion, fast-forward to existing commit, tag deletion). |
| `updates` | array of objects | List of one or more ref update triples defining atomic ref transitions. MUST NOT contain duplicate ref names within the same transaction. |
| `timestamp` | string | ISO-8601 / RFC 3339 UTC timestamp of transaction creation (e.g. `"2026-08-31T00:02:00Z"`). |
| `signature` | string | Ed25519 signature formatted as `ed25519:<128-hex>`, signed by the active server signing key over the Canonical Ref-Transaction Signing Payload. |

#### Ref Update Triple (`updates[]`)
Each object in the `updates` array represents a single ref transition:

| Field | Type | Description |
| :--- | :--- | :--- |
| `ref` | string | The full Git ref name as an exact byte sequence (e.g. `"refs/heads/main"`, `"refs/tags/v1.0"`). MUST NOT be empty. |
| `old_oid` | string | 40-character (SHA-1) or 64-character (SHA-256) lowercase hex object ID before update, or all zeros (`0000...`) for ref creation. |
| `new_oid` | string | 40-character (SHA-1) or 64-character (SHA-256) lowercase hex object ID after update, or all zeros (`0000...`) for ref deletion. |

### 5.2 Ref Names as Raw Byte Sequences (Not UTF-8 Strings)
In Git, ref names are raw sequences of non-zero bytes subject only to Git's ref format rules (`git-check-ref-format`). Git does not enforce UTF-8 encoding or Unicode normalization on ref names.

- **Byte Preservation Invariant:** Writers and readers MUST treat ref names as exact, opaque byte sequences.
- **No Unicode Normalization:** Unicode normalization algorithms (such as NFC or NFD conversion) MUST NOT be applied to ref names. Applying Unicode normalization alters the raw byte sequence and permanently breaks signature verification.
- **Character Restrictions:** Ref names must not contain ASCII control characters (`0x00`–`0x1F`, `0x7F`), space (`0x20`), `~`, `^`, `:`, `?`, `*`, `[`, `\`, `@{`, `//`, trailing slashes, leading/trailing component dots, end with `.lock`, or have any slash-delimited component ending with `.lock`.

### 5.3 Canonical Ref-Transaction Signing Payload
The transaction's Ed25519 signature is computed over a deterministic byte stream structured with line-oriented prefixes:

```
walden-ref-update:v1\n
stream:<stream>\n
seq:<seq>\n
timestamp:<timestamp>\n
segment:<sha256-1>\n
segment:<sha256-2>\n
update:<ref-1> <old_oid-1> <new_oid-1>\n
update:<ref-2> <old_oid-2> <new_oid-2>\n
```

1. **Header Line:** `walden-ref-update:v1\n`
2. **Stream Line:** `stream:<stream>\n` where `<stream>` is the exact stream ID string.
3. **Sequence Line:** `seq:<seq>\n` where `<seq>` is the decimal sequence number with no leading zeros (e.g. `0`, `1`, `42`).
4. **Timestamp Line:** `timestamp:<timestamp>\n` where `<timestamp>` is the RFC 3339 UTC timestamp string.
5. **Segment Lines:** For each SHA-256 hash in `segments` (in array order), a line formatted as `segment:<lowercase-64-hex>\n`. If `segments` is empty, zero segment lines are emitted.
6. **Update Lines:** For each update triple in `updates` (in array order), a line formatted as `update:<ref> <lowercase-old_oid> <lowercase-new_oid>\n`.
7. **Newline Termination:** Every line MUST terminate with a single newline byte (`\n`, `0x0A`).

### 5.4 Rules for Unknown Fields (Forward Compatibility)
To support forward compatibility and extensible metadata:
1. **Ignored During Deserialization:** Readers parsing v1 records MUST ignore unrecognized JSON object keys.
2. **Excluded from Canonical Payload:** Unknown fields MUST NOT be included in the Canonical Ref-Transaction Signing Payload. The canonical payload is strictly composed of the fields defined in Section 5.3 (`stream`, `seq`, `timestamp`, `segments`, `updates`).
3. **Writers:** Writers generating v1 records MUST NOT emit undefined fields.

### 5.5 What a Future v2 Reader Owes a v1 Record (Permanent Verifiability)
History written in v1 is immutable and permanently verifiable.
1. **Permanent Compatibility:** A future v2 (or higher) reader encountering a record with `"version": "v1"` MUST parse and verify the record strictly using the v1 specification rules and v1 canonical payload format.
2. **No Rejection for Missing v2 Features:** A v2 reader MUST NOT reject a valid v1 record for lacking fields, metadata, or signature formats introduced in v2.
3. **No Migration Re-signing Required:** Upgrading a Walden instance never requires rewriting or re-signing historical v1 journal objects in object storage.

---

## 6. Pack Segments and Content Addressing (Ruling 4)

### 6.1 Verbatim Storage and Content Addressing Principle
Packfiles uploaded by clients during push operations are stored **verbatim and content-addressed** in object storage:
- **Zero Transformation:** Walden already has the exact packfile byte stream in hand from `git receive-pack`. Journaling them costs exactly one object storage `PUT`. Walden contains no pack decompression, no delta resolution, and no object repacking on the write path.
- **Content Addressing:** Every pack segment is stored under an object key derived directly and exclusively from the cryptographic hash of its verbatim bytes.

### 6.2 Hash Algorithm
The content hash algorithm is standard **SHA-256** (`crypto/sha256`):
- **Input:** The exact, raw packfile byte sequence from byte 0 through the final byte of the packfile (including the 12-byte pack header, all compressed object entries, and the trailing Git checksum).
- **Encoding:** The hash is represented as exactly 64 lowercase hexadecimal characters matching `^[0-9a-f]{64}$`.

### 6.3 Key Derivation
The object storage key for a pack segment is deterministically derived as:
```
v1/streams/<stream-id>/segments/<sha256>.pack
```
- `<stream-id>`: The repository stream identifier (e.g. `repo-alpha`).
- `<sha256>`: The 64-character lowercase hexadecimal SHA-256 digest of the raw packfile bytes.
- Extension: `.pack`.

### 6.4 Idempotency & Crash-and-Retry Semantics
Re-uploading identical pack segment bytes is strictly defined as a **no-op success (idempotent PUT), never an error**:
- **Crash Safety:** If a server process crashes or network connectivity is interrupted after uploading a pack segment to object storage but *before* the ref-transaction CAS record is appended, the push is unacknowledged. When the client retries the push, Walden uploads the segment again.
- **Unconditional Write:** Unlike ref-transaction records (`tx/<seq>.json`) which require conditional CAS writes (`If-None-Match: *`), pack segment writes are unconditional. Object storage will overwrite the target key with identical bytes or return success (HTTP 200 OK).
- **No Conflict:** A duplicate segment upload MUST NOT produce an error, conflict, or precondition refusal. The crash-and-retry durability path depends strictly on this idempotent behavior.

### 6.5 Object Sidecar Metadata and Separation of Concerns
When storing a pack segment, Walden sets standard HTTP headers and object metadata:
- **`Content-Type`:** `application/x-git-packed-objects` (the standard MIME type for Git packfiles).
- **`Content-Length`:** The exact size of the packfile in bytes.
- **User Metadata Headers:**
  - `x-amz-meta-walden-stream`: `<stream-id>`
  - `x-amz-meta-walden-hash`: `<sha256>` (lowercase 64-hex)

#### Separation of Storage and Semantics ("No Meaning in the Storage Layer")
Per walden's core philosophy, the storage layer holds only authenticated, journaled bytes:
- Object storage sidecar metadata is restricted strictly to transport and routing identifiers (`stream`, `hash`).
- **No Semantic Meaning in Object Headers:** No ref names, sequence numbers, commit messages, author information, or branch mappings are stored in object metadata headers or sidecars.
- **Transaction Sovereignty:** All semantic transitions (ref updates, sequences, and timestamps) are held exclusively in the signed ref-transaction record (`tx/<seq>.json`) that references the segment hash.

### 6.6 Packfile Validation Invariants
Before appending a pack segment to object storage, the server verifies basic packfile framing rules:
1. **Header Magic:** The first 4 bytes MUST be ASCII `PACK` (`0x50 0x41 0x43 0x4B`).
2. **Pack Version:** The next 4 bytes (big-endian `uint32`) MUST be version `2` or `3`.
3. **Object Count:** The next 4 bytes (big-endian `uint32`) declare the number of objects contained in the pack.
4. **Minimum Length:**
   - For SHA-1 repositories: 12-byte header + 20-byte trailing checksum = **32 bytes minimum**.
   - For SHA-256 repositories: 12-byte header + 32-byte trailing checksum = **44 bytes minimum**.
   - Packfiles with length $< 32$ bytes are rejected as corrupt.
5. **Trailing Checksum:** The final 20 bytes (SHA-1) or 32 bytes (SHA-256) of the packfile represent the Git checksum computed over all preceding bytes in the packfile.

### 6.7 Reader & Materialization Verification
When downloading pack segments during replay, restore, or materialization:
1. **Hash Verification:** The reader MUST compute the SHA-256 digest over the downloaded bytes and assert equality with the hash referenced in the `ref_update` record.
2. **Missing Segment Refusal:** If a referenced segment cannot be fetched from object storage, the reader MUST abort immediately with a single-line refusal:
   ```
   refusal: replay failed: missing pack segment <sha256> on stream <stream-id> (verify object storage bucket integrity or restore from backup)
   ```
3. **Hash Mismatch Refusal:** If downloaded bytes do not match the expected SHA-256 digest:
   ```
   refusal: replay failed: segment hash mismatch for <sha256> on stream <stream-id> (computed <actual-sha256>) (pack segment in object storage is corrupt)
   ```
4. **Corrupt Packfile Refusal:** If the packfile header magic, version, or length is invalid:
   ```
   refusal: replay failed: corrupt pack segment <sha256> on stream <stream-id> (<reason>) (packfile header is malformed)
   ```

---

## 7. Reader Verification Algorithm

Every reader or recovery engine verifying a journal MUST execute the following deterministic algorithm:

```
┌────────────────────────────────────────────────────────┐
│ 1. Read Genesis: _meta/tx/00000000000000000000.json    │
│    ActiveKey = genesis.public_key                      │
│    LastMetaSeq = 0                                     │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ 2. Sequential Replay of _meta Stream                   │
│    For each tx at LastMetaSeq + 1:                     │
│    ├── type == "key_rotation":                         │
│    │     Assert old_public_key == ActiveKey            │
│    │     Verify signature with ActiveKey over payload  │
│    │     ActiveKey = new_public_key                    │
│    │     LastMetaSeq = seq                             │
│    └── other meta records (e.g. token mutations):      │
│          Verify contiguous sequence                    │
│          LastMetaSeq = seq                             │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ 3. Verify Repository Streams & Ref Transactions        │
│    For each stream matching ^[a-zA-Z0-9._-]+$:         │
│    ├── Verify sequence starts at 0 with no gaps        │
│    ├── For each ref transaction at seq 0, 1, 2, ...:   │
│    │     Verify type == "ref_update"                   │
│    │     Verify ref format and OID transition rules    │
│    │     For each segment in record.segments:          │
│    │       Fetch segment from segments/<sha256>.pack   │
│    │       Verify SHA-256(bytes) == <sha256>           │
│    │       Verify packfile header (PACK, len >= 32)    │
│    │     Compute Canonical Ref-Transaction Payload     │
│    │     Verify Ed25519 signature against ActiveKey    │
│    └── Track ref states from seq 0 forward             │
└────────────────────────────────────────────────────────┘
```

### 7.1 Verification Failure Rules
1. **Unchainable Rotation:** If `record.old_public_key != ActiveKey`, the rotation does not chain to genesis. The reader MUST abort immediately with a single-line error:
   ```
   refusal: replay failed: key rotation at seq <N> does not chain to active key
   ```
2. **Signature Verification Failure:** If `ed25519.Verify` returns false, the record has been tampered with. The reader MUST abort immediately with a single-line error:
   ```
   refusal: replay failed: signature mismatch for record at seq <N>
   ```
3. **Ref Transaction Signature Mismatch:** If verification of a `ref_update` record signature fails:
   ```
   refusal: replay failed: signature mismatch for ref update on stream <id> at seq <N>
   ```
4. **Sequence Gap:** If sequence numbers are not strictly contiguous ($0, 1, 2, \dots$), the reader MUST abort immediately:
   ```
   refusal: replay failed: sequence gap detected on stream <id> (expected <E>, got <A>)
   ```
5. **Missing Segment:** If a referenced pack segment does not exist in storage:
   ```
   refusal: replay failed: missing pack segment <sha256> on stream <id> (verify object storage bucket integrity or restore from backup)
   ```
6. **Segment Hash Mismatch:** If downloaded pack segment bytes fail SHA-256 verification:
   ```
   refusal: replay failed: segment hash mismatch for <sha256> on stream <id> (computed <actual>) (pack segment in object storage is corrupt)
   ```
7. **Never Guess:** Readers MUST never skip unverified, unchainable, or missing records. Partial or guessed recovery is strictly prohibited.

---

## 8. Stream Model and Key Space Layout (Ruling 2)

### 8.1 Stream Partitioning
- **Repository Streams:** Each repo is one stream with caller-chosen ID matching `^[a-zA-Z0-9._-]+$` (max 255 bytes). Sequence starts at `0` upon first push.
- **The Meta Stream (`_meta`):** Reserved for server identity, key rotations, and token mutations.
- **Per-Stream Fencing:** Fencing leases are strictly isolated per stream. A conditional append conflict on repo stream $A$ fences stream $A$ on that instance, with zero effect on repo stream $B$ or on `_meta`.

### 8.2 Key Space Layout
All keys reside under base prefix `v1/streams/<stream-id>/`:
```
v1/streams/<stream-id>/
├── tx/
│   ├── 00000000000000000000.json
│   ├── 00000000000000000001.json
│   └── 00000000000000000002.json
├── segments/
│   ├── <sha256-hex-1>.pack
│   └── <sha256-hex-2>.pack
├── snapshots/
│   └── <sha256-hex-snapshot>.pack
└── marker.json
```

- **`tx/<seq>.json`:** 20-digit zero-padded decimal unsigned 64-bit sequence (`%020d`). Lexicographically sorted by sequence number.
- **`segments/<sha256>.pack`:** Raw git packfiles content-addressed by 64-hex SHA-256 digest. Upload is idempotent.
- **`snapshots/<sha256>.pack`:** Consolidated packfile from background compaction.
- **`marker.json`:** Replay baseline marker pointing to snapshot pack and compacted sequence.

---

## 9. Lexicographical Ordering Guarantees

| Key Category | Key Pattern | Lexicographically Ordered by Sequence? | Reader Invariants |
| :--- | :--- | :---: | :--- |
| **Transaction Records** | `v1/streams/<stream-id>/tx/<seq>.json` | **YES** | Strictly ascending numerical order. Replay order matches lexicographical listing order. |
| **Pack Segments** | `v1/streams/<stream-id>/segments/<sha256>.pack` | **NO** | Random cryptographic hash order. Referenced by hash in transactions. |
| **Compaction Snapshots** | `v1/streams/<stream-id>/snapshots/<sha256>.pack` | **NO** | Resolved via `marker.json`. |
| **Replay Marker** | `v1/streams/<stream-id>/marker.json` | **N/A** | Direct GET. |
| **Stream Directory** | `v1/streams/<stream-id>/` | **NO** (Alphabetical) | Stream listing order does not imply creation order. |

---

## 10. Fencing, Conditional Append, and the Compare-and-Swap (CAS) Requirement (Ruling 5)

### 10.1 Compare-and-Swap (CAS) as a Non-Negotiable Storage Requirement

Compare-and-swap (CAS) is a hard, non-negotiable requirement of the storage bucket, stated plainly rather than hedged.

Fencing rests entirely on conditional writes. Claiming support for "any S3-compatible bucket" overstates reality: object storage providers differ significantly in their protocol support, and several major providers gained conditional-write capabilities only recently. Walden requires native compare-and-swap semantics from its underlying storage tier to guarantee single-writer mutual exclusion, linearizability, and split-brain prevention.

#### Storage Contract and Invariants
The underlying object storage backend MUST support atomic conditional object creation via standard HTTP conditional headers (specifically `If-None-Match: *`).
1. **Atomic Object Creation:** When an upload request carrying `If-None-Match: *` is received for a key that does not exist, the storage backend MUST create the object and return HTTP `200 OK` (or `201 Created`).
2. **Precondition Failure:** If the target key already exists at the moment of evaluation, the storage backend MUST reject the write atomically, return HTTP status `412 Precondition Failed` (or S3 error code `PreconditionFailed`), and leave the existing object bytes completely untouched.
3. **No Overwrites Under Precondition:** Under no circumstance may the storage backend perform an overwrite or return success when `If-None-Match: *` is supplied against an existing key.
4. **Strong Consistency:** The storage backend MUST provide strong read-after-write consistency and atomic evaluation of conditional PUT operations across all storage nodes.

If an object storage provider does not natively support atomic conditional writes with HTTP 412 rejection, it **CANNOT** be used as a backend for the walden journal.

---

### 10.2 S3-Compatible Provider Support Matrix

The following matrix documents the compatibility of major S3-compatible object storage providers with walden's compare-and-swap requirement:

| Provider | Conditional Header Mechanism | Conflict Response Status & Code | Support Status | Notes & Compatibility Details |
| :--- | :--- | :--- | :---: | :--- |
| **AWS S3** | `If-None-Match: *` | `412 Precondition Failed`<br>`PreconditionFailed` | **Supported** | Native conditional PUT support launched in August 2024. Strong read-after-write consistency and atomic evaluation across all standard AWS regions. |
| **Cloudflare R2** | `If-None-Match: *` | `412 Precondition Failed`<br>`PreconditionFailed` | **Supported** | Full native support for S3 conditional operations (`If-None-Match: *`) on object PUT with atomic 412 rejection. |
| **Google Cloud Storage (GCS)** | `If-None-Match: *`<br>`x-goog-if-generation-match: 0` | `412 Precondition Failed`<br>`PreconditionFailed` | **Supported** | Supported via GCS S3 XML API. GCS evaluates `If-None-Match: *` against object generation 0, returning 412 on conflict. |
| **MinIO** | `If-None-Match: *` | `412 Precondition Failed`<br>`PreconditionFailed` | **Supported** | Supported in modern releases (RELEASE.2023+). Atomic precondition checking is coordinated across distributed erasure sets. |
| **Ceph Rados Gateway (RGW)** | `If-None-Match: *` | `412 Precondition Failed`<br>`PreconditionFailed` | **Supported** | Supported in Ceph Quincy (v17.2+), Reef (v18.2+), and Squid (v19.2+). Earlier releases (e.g. Pacific, Nautilus) lack S3 conditional write support. |
| **Backblaze B2** | `If-None-Match: *` | `412 Precondition Failed`<br>`PreconditionFailed` | **Supported** | Supported on S3-compatible endpoints for conditional object PUT. |
| **Garage S3** | `If-None-Match: *` | `412 Precondition Failed`<br>`PreconditionFailed` | **Supported** | Supported in modern Garage releases (v0.9+) with distributed CAS coordination. |
| **Wasabi** | `If-None-Match: *` | Non-standard / Unconditional Overwrite | **Unsupported** | Does not reliably evaluate `If-None-Match: *` atomically on object PUT; may overwrite existing objects without returning 412. Incompatible with walden v1. |
| **Azure Blob Storage (via S3 Gateway)** | `If-None-Match: *`<br>`x-ms-blob-condition-if-none-match: *` | `412 Precondition Failed` | **Conditional** | Native Azure Blob REST API supports conditional writes. S3 gateway proxies must faithfully translate `If-None-Match: *` to Azure headers and propagate 412 status. |

---

### 10.3 Out of Scope Declaration (No Fallback Coordination)

**Explicitly out of scope, now and forever for format v1 (and not a follow-up ticket):** any fallback path for non-CAS storage providers — such as:
- Distributed lock objects or lock-file dances in object storage
- Lease files, renewal loops, or heartbeat files
- Two-phase commit or consensus sidecars
- External distributed coordinators (e.g. etcd, Consul, ZooKeeper, DynamoDB, Redis)

#### Rationale
Building fallback coordination paths is how a hundred correctness-critical lines of code become five hundred lines of brittle failure modes. *"Works on fewer providers, correctly"* beats *"works everywhere, probably."*

Walden deliberately chooses standard-library maximalism and an absolute minimum surface area for correctness. If industry demand ever materializes for storage backends that lack native CAS, that is a v2 conversation with an explicit format revision, never a v1 compromise.

---

### 10.4 Writer Obligations and Fencing Lifecycle

Single-writer safety (fencing) is governed by strict deterministic rules. Any reimplementation of walden MUST adhere to the following writer obligations per stream without deviation:

```
                  ┌─────────────────────────────────┐
                  │ Push Request for Stream S       │
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────┐
                  │ Is Stream S Fenced in Memory?   │
                  └───────┬─────────────────┬───────┘
                          │                 │
                     YES  │                 │  NO
                          ▼                 ▼
          ┌───────────────────────┐  ┌───────────────────────────────────┐
          │ Refuse Write          │  │ Construct Key:                    │
          │ "stream S is          │  │   tx/<seq>.json                   │
          │  permanently fenced"  │  │ Header: If-None-Match: *          │
          │ (Zero network calls)  │  └─────────────────┬─────────────────┘
          └───────────────────────┘                    │
                                                       ▼
                                             ┌───────────────────┐
                                             │ HTTP PUT to S3    │
                                             └─────────┬─────────┘
                                                       │
                                 ┌─────────────────────┴─────────────────────┐
                                 │                                           │
                         HTTP 200 OK                                 HTTP 412 Precondition
                                 │                                           │
                                 ▼                                           ▼
                    ┌─────────────────────────┐                 ┌─────────────────────────┐
                    │ Ref Transaction Success │                 │ 1. Mark Stream S Fenced │
                    │ Acknowledge Push        │                 │ 2. Return Refusal       │
                    └─────────────────────────┘                 │ 3. FORBIDDEN: Do not    │
                                                                │    re-read head & retry │
                                                                └─────────────────────────┘
```

#### 1. Exact Preconditions for Appending `tx/<seq>.json`
- When appending a ref-transaction record at sequence number `seq` for stream `<stream-id>`:
  - The object key is deterministically computed as: `v1/streams/<stream-id>/tx/<seq:020d>.json`.
  - The writer MUST issue an HTTP `PUT` request containing the HTTP header:
    ```http
    If-None-Match: *
    ```
  - The writer MUST condition the write on the target key not existing prior to this request.

#### 2. Handling HTTP 412 Precondition Failed
- If the storage backend returns HTTP status `412 Precondition Failed` (or S3 error code `PreconditionFailed`):
  - The writer has received definitive proof that another writer has already appended a record at `seq` (or higher) to this stream.
  - The current writer has lost the race or is a stale writer that was presumed dead.

#### 3. Permanent Per-Stream Fenced State on the Instance
- Upon receiving HTTP 412 Precondition Failed on stream `S`, the instance MUST immediately transition stream `S` to **permanently fenced** in memory for the remaining lifetime of the process.
- The stream state transition to fenced is irreversible in the running process.
- Any subsequent write attempt targeting stream `S` on this instance MUST be refused immediately without making any network calls to object storage.

#### 4. Strict Prohibition of Retrying and Guessing (Never Re-read Head and Retry)
- **The forbidden action is the important half:** A fenced writer **MUST NOT** re-read the head sequence (via `LIST` or `GET`) and retry appending with `seq+1` or higher.
- Retrying after a failed condition is **guessing**. A fenced writer does not know why another writer took over, what ref updates the competing writer made, or whether the current writer's in-memory view of refs is stale.
- Attempting to re-read and retry would risk interleaving unrelated ref transitions, corrupting history, or violating client intent.
- When fenced, the writer MUST stop serving writes for that stream immediately and return a one-line refusal to the client.

#### 5. Stream Isolation Invariant
- Fencing is strictly isolated per stream coordinate `stream-id`.
- If repository stream `A` is fenced due to a conflict at sequence $k$, repository stream `B` and the `_meta` stream on the same walden instance are completely unaffected and continue normal write and read operations.
- Fencing on the `_meta` stream prevents further configuration/token mutations while repository push operations on individual repo streams continue unaffected (and vice-versa).

---

### 10.5 Single-Line Refusal Message Formats

In accordance with Walden's operator-facing refusal convention (`refusal.Refusal`: `<what>: <why> (<fix>)`), all fencing-related refusals MUST be formatted as single-line messages with no embedded newlines:

1. **Fencing Detection on Conflict (Repository Stream):**
   ```
   refusal: push failed: stream <stream-id> fenced by concurrent writer at seq <seq> (instance is fenced for this stream; restart or check active writer)
   ```
2. **Subsequent Write on Permanently Fenced Stream (Repository Stream):**
   ```
   refusal: push failed: stream <stream-id> is permanently fenced on this instance (restart walden process to re-materialize from journal)
   ```
3. **Fencing Detection on Conflict (Meta Stream):**
   ```
   refusal: meta operation failed: stream _meta fenced by concurrent writer at seq <seq> (instance is fenced for this stream; restart or check active writer)
   ```
4. **Subsequent Write on Permanently Fenced Stream (Meta Stream):**
   ```
   refusal: meta operation failed: stream _meta is permanently fenced on this instance (restart walden process to re-materialize from journal)
   ```
5. **Storage Provider Lacks CAS Support:**
   ```
   refusal: journal append failed: storage provider does not support compare-and-swap (CAS) conditional writes (verify bucket provider compatibility in spec)
   ```

---

## 11. Replay and Materialization Rules

To materialize or restore a repository stream from the journal:

1. **Locate Marker:** Check for `v1/streams/<stream-id>/marker.json`.
   - If present: Load the referenced snapshot packfile from `v1/streams/<stream-id>/snapshots/<sha256>.pack` and initialize repository state at `marker.sequence`.
   - If absent: Begin replay from `seq = 00000000000000000000`.
2. **Scan Transactions:** Perform a paginated `LIST` under `v1/streams/<stream-id>/tx/` with `start-after` set to the last materialized sequence.
3. **Verify Continuity:**
   - Verify that sequence numbers are strictly contiguous ($s_0, s_0+1, s_0+2, \dots$).
   - Any gap indicates journal truncation or missing objects and MUST cause materialization to abort loudly with a one-line error.
4. **Apply and Verify:** Apply ref updates in sequence order, fetching required pack segments by content hash. Superseded segments present in storage but not referenced in active replay MUST be ignored.

---

## 12. Reimplementation Grant

This specification is published with an unconditional reimplementation grant. Anyone may implement this signing identity model, genesis record, key rotation protocol, ref-transaction record format, pack segment content addressing, stream layout, and reader/writer semantics in any programming language, for any purpose, without restriction and without asking.
