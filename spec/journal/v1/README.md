# Walden Journal Specification: Format v1

> **Status:** Published Specification (v1)  
> **Milestone:** M1 · Journal format v1  
> **Rulings Covered:** Ruling 1 of 5 (Signing Identity & Genesis), Ruling 2 of 5 (Stream Model & Key Layout)

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

## 5. Reader Verification Algorithm

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
│    └── other meta records:                             │
│          Verify contiguous sequence                    │
│          LastMetaSeq = seq                             │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ 3. Verify Repository Streams & Ref Transactions        │
│    For each ref transaction on any repo stream:        │
│    └── Verify transaction signature against ActiveKey  │
└────────────────────────────────────────────────────────┘
```

### 5.1 Verification Failure Rules
1. **Unchainable Rotation:** If `record.old_public_key != ActiveKey`, the rotation does not chain to genesis. The reader MUST abort immediately with a single-line error:
   ```
   refusal: replay failed: key rotation at seq <N> does not chain to active key
   ```
2. **Signature Verification Failure:** If `ed25519.Verify` returns false, the record has been tampered with. The reader MUST abort immediately with a single-line error:
   ```
   refusal: replay failed: signature mismatch for record at seq <N>
   ```
3. **Sequence Gap:** If sequence numbers are not strictly contiguous ($0, 1, 2, \dots$), the reader MUST abort immediately:
   ```
   refusal: replay failed: sequence gap detected on stream <id> (expected <E>, got <A>)
   ```
4. **Never Guess:** Readers MUST never skip unverified or unchainable records. Partial or guessed recovery is strictly prohibited.

---

## 6. Stream Model and Key Space Layout (Ruling 2)

### 6.1 Stream Partitioning
- **Repository Streams:** Each repo is one stream with caller-chosen ID matching `^[a-zA-Z0-9._-]+$` (max 255 bytes). Sequence starts at `0` upon first push.
- **The Meta Stream (`_meta`):** Reserved for server identity, key rotations, and token mutations.
- **Per-Stream Fencing:** Fencing leases are strictly isolated per stream. A conditional append conflict on repo stream $A$ fences stream $A$ on that instance, with zero effect on repo stream $B$ or on `_meta`.

### 6.2 Key Space Layout
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

## 7. Lexicographical Ordering Guarantees

| Key Category | Key Pattern | Lexicographically Ordered by Sequence? | Reader Invariants |
| :--- | :--- | :---: | :--- |
| **Transaction Records** | `v1/streams/<stream-id>/tx/<seq>.json` | **YES** | Strictly ascending numerical order. Replay order matches lexicographical listing order. |
| **Pack Segments** | `v1/streams/<stream-id>/segments/<sha256>.pack` | **NO** | Random cryptographic hash order. Referenced by hash in transactions. |
| **Compaction Snapshots** | `v1/streams/<stream-id>/snapshots/<sha256>.pack` | **NO** | Resolved via `marker.json`. |
| **Replay Marker** | `v1/streams/<stream-id>/marker.json` | **N/A** | Direct GET. |
| **Stream Directory** | `v1/streams/<stream-id>/` | **NO** (Alphabetical) | Stream listing order does not imply creation order. |

---

## 8. Fencing and Compare-and-Swap (CAS)

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

This specification is published with an unconditional reimplementation grant. Anyone may implement this signing identity model, genesis record, key rotation protocol, stream layout, and reader/writer semantics in any programming language, for any purpose, without restriction and without asking.

