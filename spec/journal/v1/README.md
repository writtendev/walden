# Walden Journal Specification: Format v1

> **Status:** Published Specification (v1)  
> **Milestone:** M1 · Journal format v1  
> **Rulings Covered:** Ruling 1 of 5 (Signing Identity & Genesis), Ruling 2 of 5 (Stream Model & Key Layout), Ruling 3 of 5 (Ref-Transaction Records & Payload Canonicalization)

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
    "4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638"
  ],
  "updates": [
    {
      "ref": "refs/heads/main",
      "old_oid": "0000000000000000000000000000000000000000",
      "new_oid": "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    }
  ],
  "timestamp": "2026-08-31T00:02:00Z",
  "signature": "ed25519:3785d69cb247493acb68cf2951477fc3aa5e356e1975bfb83d35600785d80062a7feecc289147333cfc8f7c6ff1c0893d311e7d7822471bc157c192cdb31be08"
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

## 6. Reader Verification Algorithm

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
│    │     Verify all segment packfiles exist in storage │
│    │     Verify ref format and OID transition rules    │
│    │     Compute Canonical Ref-Transaction Payload     │
│    │     Verify Ed25519 signature against ActiveKey    │
│    └── Track ref states from seq 0 forward             │
└────────────────────────────────────────────────────────┘
```

### 6.1 Verification Failure Rules
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
5. **Never Guess:** Readers MUST never skip unverified or unchainable records. Partial or guessed recovery is strictly prohibited.

---

## 7. Stream Model and Key Space Layout (Ruling 2)

### 7.1 Stream Partitioning
- **Repository Streams:** Each repo is one stream with caller-chosen ID matching `^[a-zA-Z0-9._-]+$` (max 255 bytes). Sequence starts at `0` upon first push.
- **The Meta Stream (`_meta`):** Reserved for server identity, key rotations, and token mutations.
- **Per-Stream Fencing:** Fencing leases are strictly isolated per stream. A conditional append conflict on repo stream $A$ fences stream $A$ on that instance, with zero effect on repo stream $B$ or on `_meta`.

### 7.2 Key Space Layout
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

## 8. Lexicographical Ordering Guarantees

| Key Category | Key Pattern | Lexicographically Ordered by Sequence? | Reader Invariants |
| :--- | :--- | :---: | :--- |
| **Transaction Records** | `v1/streams/<stream-id>/tx/<seq>.json` | **YES** | Strictly ascending numerical order. Replay order matches lexicographical listing order. |
| **Pack Segments** | `v1/streams/<stream-id>/segments/<sha256>.pack` | **NO** | Random cryptographic hash order. Referenced by hash in transactions. |
| **Compaction Snapshots** | `v1/streams/<stream-id>/snapshots/<sha256>.pack` | **NO** | Resolved via `marker.json`. |
| **Replay Marker** | `v1/streams/<stream-id>/marker.json` | **N/A** | Direct GET. |
| **Stream Directory** | `v1/streams/<stream-id>/` | **NO** (Alphabetical) | Stream listing order does not imply creation order. |

---

## 9. Fencing and Compare-and-Swap (CAS)

1. **Conditional Append:** Every write to `v1/streams/<stream-id>/tx/<seq>.json` MUST be executed as a conditional PUT requiring that the target key does not yet exist (`If-None-Match: *` or provider equivalent).
2. **Conflict as Fencing:** A precondition failure (HTTP 412) permanently transitions that stream to `fenced` on that instance.
3. **Strict Invariant:** Re-reading the head sequence and retrying is **strictly forbidden**.

---

## 10. Replay and Materialization Rules

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

## 11. Reimplementation Grant

This specification is published with an unconditional reimplementation grant. Anyone may implement this signing identity model, genesis record, key rotation protocol, ref-transaction record format, stream layout, and reader/writer semantics in any programming language, for any purpose, without restriction and without asking.
