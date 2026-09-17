# Walden Journal Specification: Format v1

> **Status:** Published Specification (v1)  
> **Milestone:** M1 · Journal format v1  
> **Rulings & Topics Covered:** Ruling 1 of 5 (Signing Identity & Genesis), Ruling 2 of 5 (Stream Model & Key Layout), Ruling 3 of 5 (Ref-Transaction Records & Payload Canonicalization), Ruling 4 of 5 (Pack Segments & Content Addressing), Ruling 5 of 5 (Conditional Append, Per-Stream Fencing & CAS Requirement), Meta Stream Token Records (`token_create`, `token_revoke`), Compaction Snapshots & Replay-from-Here Marker (`marker.json`)

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
 │ seq 2: Branch delete ref tx │               │ seq 2: Key rotation (...)   │
 │ seq 3: Force-push ref tx    │               │ seq 3: Token revoke         │
 │                             │               │ seq 4: Token create (rw, r) │
 └─────────────────────────────┘               └─────────────────────────────┘
```

### 1.1 Sequence Numbers Are JSON Strings

Wherever a sequence number appears in a JSON document of this format — `seq` in a record, `sequence` in `marker.json` — it is encoded as a **JSON string holding its exact decimal form**, never as a JSON number: `"seq": "3"`. The same rule covers `key_epoch` (section 5.1): it is not itself a sequence — it indexes the signing key chain, not a position in a stream — but it is another 64-bit integer this format writes, and RFC 8259's precision problem applies to it exactly as it does to a sequence number, for exactly the same reason.

The reason, stated once here so that nobody tidies it back to a number: RFC 8259 does not fix numeric precision and notes that interoperability is best inside the IEEE-754 double range, and many readers — JavaScript's `JSON.parse` and everything built on it — decode every JSON number as a double, which represents integers exactly only up to 2^53. A number-encoded sequence near the top of the documented range comes back rounded (`18446744073709551615` reads back as `18446744073709552000`), so the record disagrees with the sequence in its own object key and a reader that cross-checks the two rejects a valid record. A string is read exactly by every conformant parser. This is the same convention protobuf's canonical JSON mapping applies to `int64` and `uint64`.

Normative rules:

1. **Exact decimal form.** The string MUST match `^(0|[1-9][0-9]*)$` and MUST denote a value in `0` to `18446744073709551615`. No leading zeros, no sign, no whitespace, no exponent, no grouping — nothing a re-encoding would introduce. The constraint is on the encoded form: the characters between the quotes in the serialized JSON MUST themselves match that regex, so no escape sequence is permitted even where it would decode to a digit (`"\u0033"` is refused, not read as `3`).
2. **Writers** MUST emit the exact decimal form. **Readers** MUST refuse any other encoding, a JSON number included, rather than coercing it: a rounded or reformatted sequence derives the wrong object key, which is the failure this rule exists to prevent.
3. **The object key is unaffected.** `tx/<seq>.json` is still the 20-digit zero-padded decimal of section 9.2, and a record's sequence MUST still equal the sequence in its key.
4. **The canonical signing payloads are unaffected.** Sections 4.2 and 5.3 serialize the sequence as decimal text on a `seq:<seq>` line and always have. Signatures cover that text, not the JSON encoding, so this rule changes no signature and re-signs no history.

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
- **Every Record Is Signed Except the One That Cannot Be:** Key rotations chain to genesis; ref transactions verify against the key that was active when they were written, named explicitly by the record's own `key_epoch` (section 5.1) so a reader never has to guess which key that was from timing alone; the marker verifies the same way against its own `key_epoch` (section 7.2); and `token_create` and `token_revoke` (sections 4.3, 4.4) verify against the key active at the meta sequence they were written to (section 4.3's canonical payload note; section 8, step 2). The genesis record is the one exception, and it is structural rather than a gap left open: it *establishes* the signing identity everything else in the journal chains to, so there is no prior key in this journal for it to be signed with. Nothing else this specification defines is unsigned, and a third party who can write to the bucket cannot append a working `token_create`, a moved ref, or a rewritten marker without failing verification.
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
  "seq": "0",
  "type": "genesis",
  "public_key": "ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
  "timestamp": "2026-08-31T00:00:00Z"
}
```

This is the golden journal's own genesis record, byte for byte:
[`fixtures/v1/streams/_meta/tx/00000000000000000000.json`](fixtures/v1/streams/_meta/tx/00000000000000000000.json).
Every example record in this document is a real record from that journal, so an
implementation can check itself against the example and the fixture at once.

| Field | Type | Description |
| :--- | :--- | :--- |
| `version` | string | Format version; MUST be `"v1"`. |
| `stream` | string | MUST be `"_meta"`. |
| `seq` | string | Sequence number in exact decimal form (section 1.1); MUST be `"0"`. |
| `type` | string | MUST be `"genesis"`. |
| `public_key` | string | Formatted Ed25519 public key (`ed25519:<64-hex>`). |
| `timestamp` | string | ISO-8601 / RFC 3339 UTC timestamp of journal initialization. |

### 3.2 Initialization and Adoption Invariants
1. **First-Boot Minting:** When started against an empty journal prefix, walden generates an Ed25519 keypair and performs a conditional PUT (`If-None-Match: *`) to `v1/streams/_meta/tx/00000000000000000000.json`.
2. **Adoption:** If `_meta` `seq = 0` already exists, walden adopts the existing genesis record and its root identity rather than overwriting it.
3. **No Prior Records:** A journal with transactions but no genesis record at `_meta` `seq = 0` is corrupt; verifiers MUST reject it.

---

## 4. Meta Stream Records (`_meta`, `seq >= 1`)

Past genesis, the meta stream carries the instance's own configuration state and nothing else: rotations of the server signing key, and mutations of the token table. No repository history is ever written here, and none of these records is ever written to a repository stream.

Every record in this section opens with the same four fields the genesis record opens with — `version`, `stream` (always `"_meta"`), `seq`, `type` — and is appended under the conditional-append rules of section 11 like any other record. Sequence `0` belongs to genesis, so these records begin at `1`.

### 4.1 Key Rotation Records (`key_rotation`)

Signing keys can be rotated without out-of-band coordination by appending a `key_rotation` record to the `_meta` stream.

- **Location:** `v1/streams/_meta/tx/<seq>.json` (where `<seq> >= 1`)
- **Stream:** `_meta`
- **Type:** `"key_rotation"`

#### JSON Schema and Field Specification
```json
{
  "version": "v1",
  "stream": "_meta",
  "seq": "2",
  "type": "key_rotation",
  "old_public_key": "ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
  "new_public_key": "ed25519:8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
  "timestamp": "2026-08-31T00:06:00Z",
  "signature": "ed25519:2f995aefc909b3e1030557e484b513d0e09045a46f39fc63333cfd4c20a10412f58bb158ea41ff3a36d1f506c9388f46f93613438573e2c8f1322db2dc80c003"
}
```

This is the golden journal's own rotation record, byte for byte:
[`fixtures/v1/streams/_meta/tx/00000000000000000002.json`](fixtures/v1/streams/_meta/tx/00000000000000000002.json).

| Field | Type | Description |
| :--- | :--- | :--- |
| `version` | string | Format version; MUST be `"v1"`. |
| `stream` | string | MUST be `"_meta"`. |
| `seq` | string | Strictly monotonic sequence number ($k \ge 1$) in exact decimal form (section 1.1). |
| `type` | string | MUST be `"key_rotation"`. |
| `old_public_key` | string | Currently active public key in the verifier's chain (`ed25519:<64-hex>`). |
| `new_public_key` | string | New public key to activate (`ed25519:<64-hex>`), distinct from `old_public_key`. |
| `timestamp` | string | ISO-8601 / RFC 3339 UTC timestamp of rotation. |
| `signature` | string | Ed25519 signature generated by the private key of `old_public_key` over the canonical payload. |

### 4.2 Canonical Signing Payload (Key Rotation)
The signature is computed over deterministic UTF-8 bytes structured as follows:
```
walden-key-rotation:v1\n
stream:_meta\n
seq:<seq>\n
old_public_key:<old_public_key>\n
new_public_key:<new_public_key>\n
timestamp:<timestamp>\n
```
Each line terminates with a newline (`\n`, `0x0A`). `<seq>` is the decimal sequence number with no leading zeros — the same text the JSON string carries, and unchanged by the encoding rule of section 1.1.

### 4.3 Token Creation Records (`token_create`)

A built-in token is minted by the server's own CLI, and the server stores its hash — never the raw token. The local token store is a cache like every other local file, so the mutation is appended to the meta stream as well: a reader that replays `_meta` holds the whole token table when it reaches the head. That is what makes a restore onto an empty disk restore the tokens too, rather than restoring every repository and locking the operator out of them.

- **Location:** `v1/streams/_meta/tx/<seq>.json` (where `<seq> >= 1`)
- **Stream:** `_meta`
- **Type:** `"token_create"`

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
  "timestamp": "2026-08-31T00:01:00Z",
  "signature": "ed25519:cef6207dd61108ad67d6381822e3e47fa100b220f62132432e233f3bc339e27d8a46fb2035d99bd3b7d568d2b413e0eb27886458de4dbd8bbdeff6dc799d5108"
}
```

This is the golden journal's own token creation record, byte for byte:
[`fixtures/v1/streams/_meta/tx/00000000000000000001.json`](fixtures/v1/streams/_meta/tx/00000000000000000001.json).

| Field | Type | Description |
| :--- | :--- | :--- |
| `version` | string | Format version; MUST be `"v1"`. |
| `stream` | string | MUST be `"_meta"`. |
| `seq` | string | Strictly monotonic sequence number ($k \ge 1$) in exact decimal form (section 1.1). |
| `type` | string | MUST be `"token_create"`. |
| `token_id` | string | Stable identifier for the token, matching `^[a-zA-Z0-9._-]+$` (max 255 bytes) — the same character class a stream ID uses, so it is safe unescaped in a key, a log line, and a one-line refusal. Unique within the journal: an identifier is never reused. |
| `token_hash` | string | The stored hash of the raw bearer token, `sha256:<64-lowercase-hex>`. Lowercase is required, not folded, because the value is compared byte for byte against the hash a request produces. |
| `scopes` | array of strings | One or more scope strings the token was minted with, in the order minted. Each MUST be a non-empty string containing no ASCII control character (`0x00`-`0x1F` or `0x7F`, the newline included) — the same character-class ban section 5.2 states for a ref name, and for the same reason: the Canonical Token Creation Signing Payload below frames one scope per line, and a scope carrying that line's own delimiter could otherwise be split into two once inside the payload. No string may repeat. |
| `timestamp` | string | ISO-8601 / RFC 3339 UTC timestamp of token creation. |
| `signature` | string | Ed25519 signature formatted as `ed25519:<128-hex>`, generated by the key active at this meta sequence (section 8, step 2) over the Canonical Token Creation Signing Payload (below). |

**The raw token is not here, and cannot be derived from what is.** The journal carries the hash the server compares against; a bucket, a backup of it, or a replay of it grants nobody a token they did not already hold.

**Scope strings are opaque to the journal.** They are stored verbatim and returned verbatim, and this format assigns them no meaning: the vocabulary — the `<actions>:<pattern>` grammar, the glob rules, what `rwc:*` grants — is [the token specification](../../auth/v1/README.md), section 3. A reimplementation of *this* format can carry a token table faithfully without implementing that grammar at all; it needs the grammar only to answer requests with the table.

A token may carry more than one scope, and the array is what makes that expressible. The golden journal's second token is that case:

```json
{
  "version": "v1",
  "stream": "_meta",
  "seq": "4",
  "type": "token_create",
  "token_id": "tok_writer_02",
  "token_hash": "sha256:5453e0186b8b6f1d4852424e8ae33ecf685ce338a44862fc8db2acddc7b40d2a",
  "scopes": [
    "rw:blog-*",
    "r:docs"
  ],
  "timestamp": "2026-08-31T00:09:00Z",
  "signature": "ed25519:dc42713cefbac3aeaa9b2d1d606053190f313abb5192f312e169a9d7d5f3ad79411b7b457d3ea4abea3aa4911a79c92da29f73d2fed6e9ebd02120f649422c04"
}
```

Byte for byte, again:
[`fixtures/v1/streams/_meta/tx/00000000000000000004.json`](fixtures/v1/streams/_meta/tx/00000000000000000004.json).
It is the same token the auth specification publishes as `tok_writer_02`, hash and scopes included; those are the whole of the agreement between the two fixture sets. It is also signed by `K1`, the key the `_meta` sequence 2 rotation activated — this record was written after that rotation, and the key active at a meta sequence is what verifies it (see the payload note below).

#### Canonical Token Creation Signing Payload
The signature is computed over deterministic UTF-8 bytes structured as follows:
```
walden-token-create:v1\n
stream:_meta\n
seq:<seq>\n
token_id:<token_id>\n
token_hash:<token_hash>\n
scope:<scope-1>\n
scope:<scope-2>\n
timestamp:<timestamp>\n
```
Each line terminates with a newline (`\n`, `0x0A`). `<seq>` is the decimal sequence number with no leading zeros, unchanged by the encoding rule of section 1.1. One `scope:` line is emitted per entry in `scopes`, in array order, exactly as section 5.3 emits one `segment:` line per segment and section 7.2 one `ref:` line per ref — so the signature covers the count and the order, and a scope cannot be appended to a minted token without invalidating it. This framing is unambiguous only because section 4.3's field table already refuses a scope string containing a control character: without that rule, a scope carrying its own `\nscope:` could be split into what looks like two `scope:` lines once inside this payload, letting a second scope be added to a token without changing the signed bytes — the same way section 5.2's character restrictions on ref names are what make the `update:` line above safe for the same idiom.

**`token_hash` is written verbatim, with no lowercasing.** This is the one place this payload deliberately diverges from the Canonical Marker Signing Payload (section 7.2) and the Canonical Ref-Transaction Signing Payload (section 5.3), which both fold the hex fields they carry to lowercase in the payload. `token_hash` needs no such folding: section 4.3's field table already refuses a non-lowercase hash rather than accepting and normalizing one, so there is no case ambiguity here for lowercasing to paper over, and folding it in the payload anyway would just be a second, silent path to the same class of defect. `token_id`, each `scope` string, and `timestamp` are likewise written exactly as the record carries them.

A token record signed at meta sequence *N* is verified against the key that was active at sequence *N*, not against a key it names itself: unlike a ref-transaction record or the marker, this record carries no `key_epoch`. Section 8's replay of `_meta` is always contiguous from genesis — `_meta` is never compacted (section 7.1's Scope bullet states `_meta` is not subject to pack snapshotting, and section 8 step 3 excludes it from the marker sweep by name) — so a reader reaching sequence *N* already knows which key rotation, if any, was most recently applied, exactly as it knows which key verifies a `key_rotation` record itself. There is no floor to seed either: a token record is one event at one sequence, not a summary of history a resumed replay skipped.

### 4.4 Token Revocation Records (`token_revoke`)

Revoking a token appends a `token_revoke` record naming the token that is being withdrawn.

- **Location:** `v1/streams/_meta/tx/<seq>.json` (where `<seq> >= 1`)
- **Stream:** `_meta`
- **Type:** `"token_revoke"`

```json
{
  "version": "v1",
  "stream": "_meta",
  "seq": "3",
  "type": "token_revoke",
  "token_id": "tok_admin_01",
  "token_hash": "sha256:b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb",
  "timestamp": "2026-08-31T00:08:00Z",
  "signature": "ed25519:b18b4702fc2732d315f89d3ccd57d8339b9c5983eeffe39bc8087b76ae80f2c1a2efeb5a0d76b8b0a56be5ee4a046cfaa4ef7f5bd6f9a8dd665792f188306b00"
}
```

This is the golden journal's own revocation, byte for byte:
[`fixtures/v1/streams/_meta/tx/00000000000000000003.json`](fixtures/v1/streams/_meta/tx/00000000000000000003.json). It is signed by `K1`, the key the sequence 2 rotation activated one sequence earlier — the same key that verifies this record is verified against for the reason the payload note below states.

| Field | Type | Description |
| :--- | :--- | :--- |
| `version` | string | Format version; MUST be `"v1"`. |
| `stream` | string | MUST be `"_meta"`. |
| `seq` | string | Strictly monotonic sequence number ($k \ge 1$) in exact decimal form (section 1.1). |
| `type` | string | MUST be `"token_revoke"`. |
| `token_id` | string | The identifier of the token being revoked, under the same rules section 4.3 states for it. A reader matches on this field. |
| `token_hash` | string | The same `sha256:<64-lowercase-hex>` the creating record carried for that identifier, repeated here. |
| `timestamp` | string | ISO-8601 / RFC 3339 UTC timestamp of revocation. |
| `signature` | string | Ed25519 signature formatted as `ed25519:<128-hex>`, generated by the key active at this meta sequence (section 8, step 2) over the Canonical Token Revocation Signing Payload (below). |

The record names the token twice on purpose. The identifier is what a reader matches on; the hash is what a *server* keys its table by, so repeating it lets a revocation be applied — and read by a human — against the table as it is actually held. Repeating it also makes disagreement visible: a revocation whose hash is not the one recorded for that identifier does not describe the token it claims to, and a reader refuses it rather than revoking something on a guess.

A revocation carries no `scopes`. It withdraws a grant; it does not describe one.

#### Canonical Token Revocation Signing Payload
The signature is computed over deterministic UTF-8 bytes structured as follows:
```
walden-token-revoke:v1\n
stream:_meta\n
seq:<seq>\n
token_id:<token_id>\n
token_hash:<token_hash>\n
timestamp:<timestamp>\n
```
Each line terminates with a newline (`\n`, `0x0A`). `<seq>` is the decimal sequence number with no leading zeros, unchanged by the encoding rule of section 1.1. `token_hash` is written verbatim, with no lowercasing, and `token_id` and `timestamp` are likewise written exactly as the record carries them — see section 4.3's payload note for why `token_hash` is not folded the way sections 5.3 and 7.2 fold an object id.

As with a `token_create` record, this record carries no `key_epoch` and is verified against the key active at its own meta sequence rather than a key it names itself; section 4.3's payload note states the reason once for both record types.

### 4.5 Rebuilding the Token Table

A reader replaying `_meta` from genesis forward holds the token table when it reaches the head. The rules are the whole of it:

1. **Start empty.** A journal with no token records rebuilds to no tokens.
2. **A record whose signature does not verify never reaches the table.** `token_create` and `token_revoke` are verified against the key active at their own meta sequence (section 4.3's payload note) before section 8's replay applies either to the table. A `signature` that is absent or not formatted as `ed25519:<128-hex>` is a field-rule violation, refused under section 8.1's rule 13 with `<reason>` naming the field; a well-formed signature that does not verify against the active key is refused under rule 19. Either way, the reader stops rather than skipping the record or guessing at what it would have granted.
3. **A record that violates its own field rules never reaches the table.** The constraints stated in the field tables of sections 4.3 and 4.4 are normative — the `token_id` character class and 255-byte cap, `token_hash` as `sha256:<64-lowercase-hex>`, `signature` present and formatted as `ed25519:<128-hex>`, and, for a creation, a `scopes` array carrying at least one entry with no entry empty, none repeated, and none containing an ASCII control character (`0x00`-`0x1F` or `0x7F`, the newline included). A record violating any of them is refused before it is applied (section 8.1, rule 13); the reader does not apply it, and does not repair it.
4. **`token_create`** inserts a row: `token_id` → (`token_hash`, `scopes`), live. A record naming a `token_id` the table already holds is a reused identifier, which this format forbids; the reader refuses (section 8.1, rule 10).
5. **`token_revoke`** finds the row named by `token_id` and marks it revoked. An identifier the table does not hold is unchainable, exactly as an unchainable rotation is: the reader refuses (rule 11), and does not create the row. A `token_hash` that disagrees with the one the row carries is likewise refused (rule 12).
6. **Rows are never removed.** The journal is append-only, and what a replay rebuilds is the history of a token rather than a snapshot of a mutable file. A revoked row is kept, revoked.
7. **The table is the whole identity model.** There are no accounts, owners, or expiries to rebuild, because there are none to record. A row is a hash to look a request up by and the scopes to answer it with.

**These records are signed, and the guarantee of section 2.2 reaches the token table because of it.** A `token_create` or `token_revoke` is verified against the key active at its own meta sequence before either is applied, exactly as a key rotation or a ref transaction is verified before it is trusted. A party who can append to `_meta` in the bucket can still append a `token_create` naming a hash of their own choosing and the scopes `rwc:*`, but the replay above never reaches the table with it: the signature does not verify against the active key, rule 19 refuses it in one line, and the replay stops. What the bucket's own access control now defends is a narrower thing than a working credential — a party without the signing key can litter `_meta` with records a reader will never apply, but cannot mint one that authorizes anything.

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
  "seq": "0",
  "type": "ref_update",
  "key_epoch": "0",
  "segments": [
    "db89aeed94af475ae97ce5fe75618d404f017d23e0aa61ce1c7abd11707dbbab"
  ],
  "updates": [
    {
      "ref": "refs/heads/main",
      "old_oid": "0000000000000000000000000000000000000000",
      "new_oid": "63ed45846ea17a17cc2c2b3ddc54e37dd402ae96"
    }
  ],
  "timestamp": "2026-08-31T00:02:00Z",
  "signature": "ed25519:e3663b676f671095e4b8653ddc1419b2349d39a8adab7f28b1cb6574bc62963ec2f03996af92d34d6e2fab685c365a180d411053af476d4b319fe6a9359a8805"
}
```

This is the golden journal's own first record, byte for byte:
[`fixtures/v1/streams/repo-alpha/tx/00000000000000000000.json`](fixtures/v1/streams/repo-alpha/tx/00000000000000000000.json).
The segment it names is a real packfile in the fixture tree, `new_oid` is the
commit that packfile carries, and the signature verifies against key epoch 0
in the chain — the genesis key, since this record predates any rotation.

| Field | Type | Description |
| :--- | :--- | :--- |
| `version` | string | Format version; MUST be `"v1"`. |
| `stream` | string | Stream identifier (`<stream-id>`). |
| `seq` | string | Strictly monotonic unsigned 64-bit sequence number ($k \ge 0$) in exact decimal form (section 1.1). |
| `type` | string | MUST be `"ref_update"`. |
| `key_epoch` | string | Index into the signing key chain, in exact decimal form (section 1.1), naming the key that signed this record. `0` is the genesis key; each `key_rotation` record on `_meta` increments it by one. A hint, not authority: section 8 verifies the chain from genesis and trusts the named key only because it is already in that verified chain. A record with no `key_epoch` at all is read as epoch `0`, identically to an explicit `"key_epoch": "0"`; a writer producing v1 records MUST always emit the field explicitly rather than relying on this default. |
| `segments` | array of strings | List of zero or more 64-character lowercase hexadecimal SHA-256 digests of newly written packfiles. May be empty (`[]`) for operations not introducing new objects (e.g. branch deletion, fast-forward to existing commit, tag deletion). |
| `updates` | array of objects | List of one or more ref update triples defining atomic ref transitions. MUST NOT contain duplicate ref names within the same transaction. |
| `timestamp` | string | ISO-8601 / RFC 3339 UTC timestamp of transaction creation (e.g. `"2026-08-31T00:02:00Z"`). |
| `signature` | string | Ed25519 signature formatted as `ed25519:<128-hex>`, signed by the key named by `key_epoch` over the Canonical Ref-Transaction Signing Payload. |

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
- **No Unicode Normalization:** Unicode normalization algorithms (such as NFC or NFD conversion) MUST NOT be applied to ref names. Applying Unicode normalization alters the raw byte sequence and permanently breaks signature verification. The golden journal carries a ref name that is deliberately not NFC-invariant — `refs/heads/caf` + U+0065 + U+0301 (decomposed), on [`repo-alpha`'s seq 1 record](fixtures/v1/streams/repo-alpha/tx/00000000000000000001.json) and in [its marker's ref set](fixtures/v1/streams/repo-alpha/marker.json) — for exactly this reason: swapping it for its precomposed NFC form (`refs/heads/caf` + U+00E9) breaks both signatures, which is this paragraph's claim, executed.
- **Character Restrictions:** Ref names must not contain ASCII control characters (`0x00`–`0x1F`, `0x7F`), space (`0x20`), `~`, `^`, `:`, `?`, `*`, `[`, `\`, `@{`, `//`, trailing slashes, leading/trailing component dots, end with `.lock`, or have any slash-delimited component ending with `.lock`.

### 5.3 Canonical Ref-Transaction Signing Payload
The transaction's Ed25519 signature is computed over a deterministic byte stream structured with line-oriented prefixes:

```
walden-ref-update:v1\n
stream:<stream>\n
seq:<seq>\n
key_epoch:<key_epoch>\n
timestamp:<timestamp>\n
segment:<sha256-1>\n
segment:<sha256-2>\n
update:<ref-1> <old_oid-1> <new_oid-1>\n
update:<ref-2> <old_oid-2> <new_oid-2>\n
```

1. **Header Line:** `walden-ref-update:v1\n`
2. **Stream Line:** `stream:<stream>\n` where `<stream>` is the exact stream ID string.
3. **Sequence Line:** `seq:<seq>\n` where `<seq>` is the decimal sequence number with no leading zeros (e.g. `0`, `1`, `42`) — the same text the JSON string carries, so the encoding rule of section 1.1 leaves signatures untouched.
4. **Key Epoch Line:** `key_epoch:<key_epoch>\n` where `<key_epoch>` is the decimal key epoch with no leading zeros — the same text the JSON string carries. Covered by the signature like every other line here: `key_epoch` cannot be altered on a written record without invalidating it.
5. **Timestamp Line:** `timestamp:<timestamp>\n` where `<timestamp>` is the RFC 3339 UTC timestamp string.
6. **Segment Lines:** For each SHA-256 hash in `segments` (in array order), a line formatted as `segment:<lowercase-64-hex>\n`. If `segments` is empty, zero segment lines are emitted.
7. **Update Lines:** For each update triple in `updates` (in array order), a line formatted as `update:<ref> <lowercase-old_oid> <lowercase-new_oid>\n`.
8. **Newline Termination:** Every line MUST terminate with a single newline byte (`\n`, `0x0A`).

### 5.4 Rules for Unknown Fields (Forward Compatibility)
To support forward compatibility and extensible metadata:
1. **Ignored During Deserialization:** Readers parsing v1 records MUST ignore unrecognized JSON object keys.
2. **Excluded from Canonical Payload:** Unknown fields MUST NOT be included in the Canonical Ref-Transaction Signing Payload. The canonical payload is strictly composed of the fields defined in Section 5.3 (`stream`, `seq`, `key_epoch`, `timestamp`, `segments`, `updates`).
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

## 7. Compaction Snapshots and the Replay-from-Here Marker (`marker.json`)

### 7.1 Background Compaction and the Published Marker Contract
Compaction is an internal performance optimization, but the marker it publishes is a **contract** — a reader or materialization engine has to know what it may assume when it encounters a marker in object storage.

A background task periodically consolidates all reachable Git objects across historical pack segments into a consolidated snapshot packfile per stream, and publishes a "replay from here" marker (`marker.json`). This prevents repository materialization and disaster recovery from having to replay the entire history of thousands of individual transactions and pack segments from sequence `0`.

- **Marker Location:** `v1/streams/<stream-id>/marker.json`
- **Snapshot Packfile Location:** `v1/streams/<stream-id>/snapshots/<sha256>.pack`
- **Scope:** Snapshots and markers are published per repository stream. The `_meta` stream records small, rare server configuration events (genesis, token tables, key rotations) and is not subject to pack snapshotting.

### 7.2 JSON Schema and Field Specification
`marker.json` is a UTF-8 JSON document stored at the root of the stream prefix. It is a
**signed record**: unsigned, a marker holding authoritative branch tips would
be a direct history-rewrite vector for anyone who can write to the bucket — precisely
the threat the server signing identity exists to detect, and the reason ref-transaction
records are signed at all.

```json
{
  "version": "v1",
  "stream": "repo-alpha",
  "sequence": "3",
  "key_epoch": "1",
  "key_epoch_floor": "1",
  "snapshot": "cd04837137cbca78f87a66055eb1ec4a598842618fa6cdb126295c6cda9b6638",
  "refs": [
    {
      "ref": "refs/heads/café",
      "oid": "63ed45846ea17a17cc2c2b3ddc54e37dd402ae96"
    },
    {
      "ref": "refs/heads/main",
      "oid": "fe75a8a9eea356bbe01fdf92d95d448190ad7942"
    },
    {
      "ref": "refs/tags/v0.1",
      "oid": "63ed45846ea17a17cc2c2b3ddc54e37dd402ae96"
    }
  ],
  "timestamp": "2026-08-31T01:00:00Z",
  "signature": "ed25519:0d96768618efdfcdbd282a0252ce336236019045812dd8e9385b25b26f8a3f1dd36b0daee8cdb950266b8fcf4ee893bd2d72af4541f33a0bca0ae598f0a3d605"
}
```

This is the golden journal's own marker, byte for byte:
[`fixtures/v1/streams/repo-alpha/marker.json`](fixtures/v1/streams/repo-alpha/marker.json).
Note that `snapshot` names an object under `snapshots/`, not under `segments/`:
the two are separate key spaces, and a digest that resolves in one has no
meaning in the other. The baseline moved to sequence 3 — past the key rotation
at `_meta` sequence 2 — precisely so this one marker could demonstrate both
halves of this section at once: `refs/tags/v0.1` is created at sequence 1 and
never touched again, so it is recoverable only because this marker carries the
ref set, and `key_epoch_floor` is `1` because sequence 3 is the record that
carried epoch 1. `refs/heads/caf` + U+0065 + U+0301 — a ref name that is
deliberately not NFC-invariant (section 5.2) — is created on the same seq 1
record and sorts first in this array by the raw bytes of its name; it is never
touched again either, so it is recoverable only from this marker in exactly
the way `refs/tags/v0.1` is.

| Field | Type | Description |
| :--- | :--- | :--- |
| `version` | string | Format version; MUST be `"v1"`. |
| `stream` | string | Stream identifier matching `^[a-zA-Z0-9._-]+$` (max 255 bytes). |
| `sequence` | string | Unsigned 64-bit sequence number ($k \ge 0$) in exact decimal form (section 1.1), representing the latest ref transaction fully incorporated into the snapshot pack. |
| `key_epoch` | string | Index into the signing key chain, in exact decimal form (section 1.1), naming the key that signed *this marker* — stamped at compaction time. Section 5.1's semantics apply word for word: a hint, not authority, refused if it falls outside the chain verified from genesis. |
| `key_epoch_floor` | string | The highest `key_epoch` carried by any record on this stream at sequence $\le$ `sequence`, in exact decimal form (section 1.1). It is what a replay resuming from this marker seeds `LastEpoch` with (section 8, rule 15). `key_epoch_floor` MUST be $\le$ `key_epoch`: compaction lags key rotation, so a rotation can land between the baseline and the marker's publication, and a marker signed by a key older than the history it claims to summarize is refused rather than repaired. |
| `snapshot` | string | Exactly 64 lowercase hexadecimal characters representing the SHA-256 digest of the consolidated snapshot packfile bytes verbatim (`^[0-9a-f]{64}$`). |
| `refs` | array of objects | The authoritative ref set as of `sequence` — **not a delta** — as an array of Ref Objects (below). MAY be `[]`: a stream whose every ref has been deleted has an empty ref set, and that is authoritative state, not a missing field. |
| `timestamp` | string | ISO-8601 / RFC 3339 UTC timestamp when the snapshot was generated and published (e.g. `"2026-08-31T01:00:00Z"`). |
| `signature` | string | Ed25519 signature formatted as `ed25519:<128-hex>`, signed by the key named by `key_epoch` over the Canonical Marker Signing Payload (below). |

#### Ref Object (`refs[]`)
Each object in the `refs` array names one ref and the object id it stood at, as of
`sequence`:

| Field | Type | Description |
| :--- | :--- | :--- |
| `ref` | string | The full Git ref name. **Encoding is section 5.2's, unchanged and by reference:** a plain JSON string holding the raw byte sequence, no normalization, no new escaping scheme. If that encoding is ever revisited, `updates[].ref` and this field move together. |
| `oid` | string | 40-character (SHA-1) or 64-character (SHA-256) lowercase hex object ID the ref points at. Never the all-zero OID: a ref that does not exist is absent from the array, not present pointing at zeros. |

Rules, stated here rather than left implied:

1. **An array of objects, not a JSON object map.** A map has no defined key order and no
   defined behavior for duplicate keys, and this array is signed — the canonical payload
   below needs a deterministic byte order, which only an array gives it.
2. **Sorted ascending by the raw bytes of `ref`.** Readers MUST refuse a `refs` array that
   is not sorted this way.
3. **No duplicate ref name, and no zero OID.** Readers MUST refuse either.
4. **Uniform OID length.** Every `oid` in one marker's `refs` is the same length: mixed
   SHA-1 and SHA-256 object IDs in a single marker are refused, matching section 5.1's
   rule for `updates[]`.
5. **`refs` MAY be `[]`.** An empty ref set is a stream with nothing left standing, and
   that is what compaction observed, not an omission.

#### Canonical Marker Signing Payload
The marker's Ed25519 signature is computed over a deterministic byte stream, styled on
sections 4.2 and 5.3:

```
walden-marker:v1\n
stream:<stream>\n
sequence:<sequence>\n
key_epoch:<key_epoch>\n
key_epoch_floor:<key_epoch_floor>\n
timestamp:<timestamp>\n
snapshot:<lowercase-64-hex>\n
ref:<ref-1> <lowercase-oid-1>\n
ref:<ref-2> <lowercase-oid-2>\n
```

1. **Header Line:** `walden-marker:v1\n`
2. **Stream Line:** `stream:<stream>\n` where `<stream>` is the exact stream ID string.
3. **Sequence Line:** `sequence:<sequence>\n`, decimal, no leading zeros — the same text
   the JSON string carries (section 1.1).
4. **Key Epoch Line:** `key_epoch:<key_epoch>\n`, decimal, no leading zeros. Covered by
   the signature like every other line here: it cannot be altered on a written marker
   without invalidating it.
5. **Key Epoch Floor Line:** `key_epoch_floor:<key_epoch_floor>\n`, decimal, no leading
   zeros. This is what makes the floor unforgeable: the only way to raise it on a
   verified chain is a marker whose signature — which covers this line — actually
   verifies.
6. **Timestamp Line:** `timestamp:<timestamp>\n`, the RFC 3339 UTC timestamp string.
7. **Snapshot Line:** `snapshot:<lowercase-64-hex>\n`, the snapshot pack's digest,
   lowercased.
8. **Ref Lines:** For each entry in `refs`, in array order (which rule 2 above already
   requires to be sorted ascending), a line `ref:<ref> <lowercase-oid>\n`. Zero ref lines
   are emitted for an empty `refs` array.
9. **Newline Termination:** Every line MUST terminate with a single newline byte (`\n`,
   `0x0A`).
10. **Unknown Fields Excluded:** Per section 5.4's rule, restated for the marker: unknown
    JSON fields are never part of this payload.

#### Forward Compatibility & Unknown Fields
In accordance with Walden's forward compatibility principles:
1. **Deserialization Tolerance:** Readers MUST ignore unrecognized JSON keys when parsing `marker.json`.
2. **Writers:** Writers generating format v1 markers MUST NOT emit undefined keys.

### 7.3 The Core Guarantees & Invariants

From the reader's side, a published marker provides three non-negotiable guarantees:

#### 1. The Publish-Last Invariant (Referential Integrity)
> **Guarantee 1:** *Every object a published marker references already exists in storage.*

The background compactor MUST strictly upload and verify the consolidated snapshot packfile at `v1/streams/<stream-id>/snapshots/<sha256>.pack` **BEFORE** creating or overwriting `v1/streams/<stream-id>/marker.json`.

- **Atomic Publication Order:**
  1. Compactor builds snapshot packfile locally.
  2. Compactor computes SHA-256 digest `<sha256>`.
  3. Compactor uploads snapshot packfile to `snapshots/<sha256>.pack` and verifies the upload (HTTP 200 OK).
  4. Compactor writes or updates `marker.json` pointing to `<sha256>` and `sequence`.
- **Crash Safety:** If a server process crashes, network partitions, or storage writes fail prior to step 4, the orphaned packfile in `snapshots/` is harmless. Readers will continue to find the previous `marker.json` (or replay from genesis/seq 0) and will never observe a `marker.json` pointing to a non-existent snapshot packfile.
- **Reader Assumption:** When a reader observes `marker.json`, it may definitively assume that `snapshots/<sha256>.pack` is present, durable, and complete.

#### 2. The Superseded Segments & Historical Transactions Invariant
> **Guarantee 2:** *Superseded segments and historical transaction records may still be present in storage and MUST be ignored rather than treated as corruption.*

Compaction is purely an acceleration mechanism. It does **not** synchronously purge historical pack segments (`segments/<sha256>.pack`) or earlier transaction records (`tx/<seq>.json`).

- **Paranoia as Policy:** Object storage is cheap, and paranoia is on brand. Walden preserves older segments and transaction files for weeks, months, or indefinitely to support auditability, historical verification, and disaster recovery.
- **Reader Obligation:** When a reader initializes state from a snapshot at `sequence = N`, any pack segment files under `segments/` or transaction files under `tx/` with sequence $s \le N$ remaining in storage are valid historical artifacts. Readers **MUST NOT** reject the journal, fail validation, or treat the presence of superseded records as duplicate writes, replay conflicts, or storage corruption. Readers simply begin active sequential replay at sequence $N + 1$.

#### 3. The Ref-Set Referential Integrity Invariant
> **Guarantee 3:** *Every object the marker's ref set names is carried by the snapshot pack the same marker names.*

A ref in `refs` pointing at an object the snapshot does not carry would be indistinguishable, to a reader that trusts the marker, from a ref genuinely reachable at the baseline — except that applying the snapshot and then trying to set that ref would fail. Readers MUST refuse a marker with this property outright (section 7.6).

This adds no second ordering constraint beyond Guarantee 1's. The compactor still builds the snapshot from the exact ref state it is snapshotting, uploads and verifies the pack, and publishes the marker last — the ref set and the epoch floor travel *inside* the marker rather than as a separate object, so there is nothing new to sequence between: the snapshot pack is one write, the marker (now carrying more fields) is the second and still last.

### 7.4 Snapshot Packfile Framing & Storage Rules
Consolidated snapshot packfiles follow identical byte framing and verification rules as standard pack segments:
1. **Verbatim Bytes:** Stored verbatim without proprietary encapsulation or transformation.
2. **Key Derivation:** `v1/streams/<stream-id>/snapshots/<sha256>.pack`.
3. **HTTP Headers & S3 Metadata:**
   - `Content-Type`: `application/x-git-packed-objects`
   - `x-amz-meta-walden-stream`: `<stream-id>`
   - `x-amz-meta-walden-hash`: `<sha256>` (lowercase 64-hex)
4. **Header Validation:** Must begin with `PACK`, specify version 2 or 3, object count $\ge 0$, and meet minimum size requirements ($\ge 32$ bytes for SHA-1 repos, $\ge 44$ bytes for SHA-256 repos).

### 7.5 Step-by-Step Reader Verification & Replay Algorithm

When initializing or materializing a repository from the journal, a reader MUST execute the following procedure:

```
┌────────────────────────────────────────────────────────┐
│ 1. Check for marker.json                               │
│    GET v1/streams/<stream-id>/marker.json              │
└───────────────────────────┬────────────────────────────┘
                            │
             ┌──────────────┴──────────────┐
             ▼                             ▼
       [Marker Found]               [Marker Absent]
             │                             │
             ▼                             ▼
┌───────────────────────────┐ ┌───────────────────────────┐
│ 2. Parse Marker Structure │ │ Start replay from seq 0   │
│    marker.json            │ │ (tx/00000000000000000000) │
└────────────┬──────────────┘ │ Refs = {}                 │
             │                │ LastEpoch = 0             │
             ▼                └─────────────┬─────────────┘
┌───────────────────────────┐              │
│ 3. Verify Marker Signature│              │
│    against the key named  │              │
│    by key_epoch (section  │              │
│    8) — before trusting   │              │
│    any other field on it  │              │
└────────────┬──────────────┘              │
             │                             │
             ▼                             │
┌───────────────────────────┐              │
│ 4. Fetch Snapshot Pack    │              │
│    snapshots/<hash>.pack  │              │
│    Verify SHA-256 & PACK  │              │
└────────────┬──────────────┘              │
             │                             │
             ▼                             │
┌───────────────────────────┐              │
│ 5. Apply Snapshot Pack    │              │
│    Baseline Seq S = seq   │              │
│    Refs = marker.refs     │              │
│    LastEpoch =            │              │
│      marker.key_epoch_    │              │
│      floor                │              │
└────────────┬──────────────┘              │
             │                             │
             ▼                             │
┌──────────────────────────────────────────▼──────────────┐
│ 6. Sequential Replay of tx/ Starting at S + 1           │
│    - Ignore any tx <= S and superseded segments         │
│    - Assert strictly contiguous sequence: S+1, S+2, ... │
│    - Verify signature against the key named by          │
│      record.key_epoch (section 8)                       │
│    - Assert record.key_epoch >= LastEpoch               │
│    - Fetch & verify referenced segments/<hash>.pack     │
│    - Apply ref updates onto Refs (from the marker's     │
│      set, or {} with no marker) and no others           │
└─────────────────────────────────────────────────────────┘
```

1. **Query Marker:** Issue a `GET` request for `v1/streams/<stream-id>/marker.json`.
2. **If Marker Present:**
   - **Parse Marker Structure:** Parse JSON and verify `version == "v1"`, `stream == <stream-id>`, valid `sequence`, `key_epoch`, `key_epoch_floor` with `key_epoch_floor <= key_epoch`, valid 64-hex `snapshot` hash, a well-formed `refs` array (section 7.2's rules), and valid UTC `timestamp`. Every field is required; a marker missing any of them is refused (section 7.6) before signature verification is even attempted.
   - **Verify Marker Signature — before trusting any other field:** Resolve the key named by `key_epoch` in the chain verified from genesis forward (section 8, which must already have replayed `_meta` in full before any marker is trusted), and verify the Ed25519 signature against the Canonical Marker Signing Payload (section 7.2). An epoch outside the chain, or a signature that does not verify, is refused immediately — nothing past this step reads a field off an unverified marker.
   - **Download Snapshot:** Fetch `v1/streams/<stream-id>/snapshots/<snapshot-hash>.pack`.
   - **Verify Snapshot:** Compute SHA-256 over downloaded bytes; assert equality with `marker.snapshot`. Verify `PACK` header and Git checksum. Assert every OID in `marker.refs` resolves inside this snapshot pack (Guarantee 3, section 7.3).
   - **Apply Snapshot:** Index and unpack the snapshot packfile into the bare repository object database.
   - **Set Replay Baseline:** Set baseline sequence $S = \text{marker.sequence}$, `Refs = marker.refs` (exactly those refs, and no others — not merged with anything, since the marker's ref set is authoritative, not a delta), and `LastEpoch = marker.key_epoch_floor`.
   - **List Tail Transactions:** Perform a `LIST` on `v1/streams/<stream-id>/tx/` with `start-after` set to `v1/streams/<stream-id>/tx/<S:020d>.json`.
   - **Sequential Replay:** For each transaction record in ascending order ($S+1, S+2, \dots$):
     - Assert that sequence numbers are strictly contiguous with no gaps.
     - Verify the Ed25519 signature against the key named by the record's `key_epoch` (section 8), not against whichever key happens to be active now.
     - Assert `record.key_epoch >= LastEpoch` (section 8, rule 15), which the marker's `key_epoch_floor` seeded above rather than leaving at `0`.
     - Fetch referenced segments from `segments/<sha256>.pack` and apply ref updates onto `Refs`.
3. **If Marker Absent:**
   - Set baseline sequence $S = -1$, `Refs = {}`, and `LastEpoch = 0`.
   - Replay all transaction records sequentially from sequence `0` (`tx/00000000000000000000.json`) forward, tracking `Refs` from empty rather than from a marker's set.

A reader following this algorithm from the genesis path and from the marker path arrives at identical ref state for the same stream — the acceptance test this section exists to satisfy, and the one `TestFixtureReplay` runs against the golden journal.

### 7.6 Single-Line Refusal Message Formats

When verification or download fails during marker or snapshot handling, Walden aborts immediately and emits a strictly formatted single-line refusal (`<what>: <why> (<fix>)`):

1. **Missing Snapshot Packfile:**
   ```
   refusal: replay failed: missing snapshot pack <sha256> on stream <stream-id> (verify object storage bucket integrity or restore from backup)
   ```
2. **Snapshot Hash Mismatch:**
   ```
   refusal: replay failed: snapshot hash mismatch for <sha256> on stream <stream-id> (computed <actual-sha256>) (snapshot pack in object storage is corrupt)
   ```
3. **Corrupt Snapshot Packfile:**
   ```
   refusal: replay failed: corrupt snapshot pack <sha256> on stream <stream-id> (<reason>) (packfile header is malformed)
   ```
4. **Corrupt Marker JSON:**
   ```
   refusal: replay failed: corrupt marker on stream <stream-id> (<reason>) (marker.json in object storage is malformed)
   ```
5. **Invalid Marker Fields:** A malformed ref set (bad ref name, zero OID, duplicate, out of order, mixed OID lengths), a missing required field, or `key_epoch_floor` above `key_epoch` — every one of these refuses under this same line, with `<reason>` naming the rule that failed; none of them gets its own refusal:
   ```
   refusal: replay failed: invalid marker on stream <stream-id> (<reason>) (marker.json in object storage is invalid)
   ```
6. **Marker Signature Mismatch:** If a marker's signature does not verify against the key its own `key_epoch` names:
   ```
   refusal: replay failed: signature mismatch for marker on stream <stream-id> at sequence <N>
   ```
7. **Marker Names an Unknown Key Epoch:** If a marker's `key_epoch` is not a valid index into the chain verified from genesis forward — worded to match rule 14's ref-transaction equivalent (section 8.1) — the reader MUST NOT fall back to the active key. It MUST abort immediately:
   ```
   refusal: replay failed: marker on stream <stream-id> names unknown key epoch <E>
   ```
8. **Marker Ref Not in Snapshot:** If a marker names a ref pointing at an object the snapshot pack it also names does not carry (Guarantee 3, section 7.3):
   ```
   refusal: replay failed: marker on stream <stream-id> names <ref> at <oid>, which the snapshot pack does not carry (marker.json in object storage is invalid)
   ```

---

## 8. Reader Verification Algorithm

Every reader or recovery engine verifying a journal MUST execute the following deterministic algorithm:

```
┌────────────────────────────────────────────────────────┐
│ 1. Read Genesis: _meta/tx/00000000000000000000.json    │
│    Chain = [genesis.public_key]     (epoch 0)          │
│    LastMetaSeq = 0                                     │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ 2. Sequential Replay of _meta Stream                   │
│    For each tx at LastMetaSeq + 1:                     │
│    ├── type == "key_rotation":                         │
│    │     Assert old_public_key == Chain[-1]            │
│    │     Verify signature with Chain[-1] over payload  │
│    │     Chain = Chain + [new_public_key]  (epoch++)   │
│    │     LastMetaSeq = seq                             │
│    ├── type == "token_create" or "token_revoke":       │
│    │     Verify record fields (sections 4.3, 4.4)      │
│    │     Verify signature with Chain[-1] over payload  │
│    │     Apply to the token table (section 4.5)        │
│    │     LastMetaSeq = seq                             │
│    └── other meta records:                             │
│          Verify contiguous sequence                    │
│          LastMetaSeq = seq                             │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ 3. Verify Repository Streams & Ref Transactions        │
│    For each stream matching ^[a-zA-Z0-9._-]+$          │
│    OTHER THAN _meta:                                   │
│    ├── Check for marker.json:                          │
│    │     If present: verify marker (sig & epoch),      │
│    │       verify+apply snapshot, refs = marker.refs,  │
│    │       S = marker.sequence                         │
│    │     If absent: S = -1, refs = {}                  │
│    ├── Verify sequence starting at S + 1 with no gaps  │
│    ├── LastEpoch = marker.key_epoch_floor, else 0      │
│    ├── For each ref transaction at seq S+1, S+2, ...:  │
│    │     Verify type == "ref_update"                   │
│    │     Verify ref format and OID transition rules    │
│    │     For each segment in record.segments:          │
│    │       Fetch segment from segments/<sha256>.pack   │
│    │       Verify SHA-256(bytes) == <sha256>           │
│    │       Verify packfile header (PACK, len >= 32)    │
│    │     Assert record.key_epoch < len(Chain)          │
│    │     Assert record.key_epoch >= LastEpoch          │
│    │     Compute Canonical Ref-Transaction Payload     │
│    │     Verify Ed25519 signature against              │
│    │       Chain[record.key_epoch]                     │
│    │     LastEpoch = record.key_epoch                  │
│    └── Track ref states from marker.refs (or {}) fwd   │
└────────────────────────────────────────────────────────┘
```

Step 3 excludes `_meta` from the stream sweep: `_meta` carries `genesis`, `key_rotation`, `token_create`, and `token_revoke` records, never `ref_update`, and step 2 already replays it in full. `_meta` itself matches `^[a-zA-Z0-9._-]+$` — the same pattern a repository stream ID matches — so a reader that does not exclude it by name would otherwise try to verify meta records as ref transactions and fail on the first one (see section 9.1).

Verifying the marker itself needs `Chain`, so it happens only after step 2's full `_meta` replay — the ordering section 7.5 states explicitly and this section has so far only implied. A marker is trusted only once its signature verifies against the key its own `key_epoch` names in that chain (section 7.5, 7.6); nothing about `S`, `refs`, or `LastEpoch` is read off it before that.

`record.key_epoch` is a hint, not authority: it selects a position in `Chain`, and `Chain` is trusted only because step 2 verified it from genesis forward. An epoch outside `Chain` (rule 14) is refused outright — never a reason to fall back to `Chain[-1]` or to any other key.

Rule 15's floor is real, but it is narrower than "a retired key can never validate a ref update again": `LastEpoch` is tracked per stream (step 3), and a stream this replay has not yet seen carry an epoch above `0` gives rule 15 nothing to compare against. A leaked genesis key `K0` still validates a `key_epoch: 0` record — signed and accepted — on any such stream, in a full, uncompacted replay from genesis: a stream that happened to stop before the rotation, or one that does not exist yet and that an attacker holding `K0` creates after the rotation for exactly this purpose. Rule 15 only compares a record's epoch against epochs this replay has already verified on that same stream, so a stream with nothing yet verified on it — old or brand new — has no floor above `0` to enforce. No ticket tracks this gap: closing it would need a floor that is not scoped per stream, which rule 15 does not attempt and which is a larger change than this section's mechanism.

So rule 15 delivers the non-decreasing guarantee only per stream, and only for records after the point — genesis, or a marker baseline whose `key_epoch_floor` seeded the floor (section 7.2) — where a given replay first sees that stream carry an epoch above `0`. A stream that never reaches that point in a given replay gets no protection from this rule at all.

### 8.1 Verification Failure Rules
1. **Unchainable Rotation:** If `record.old_public_key != Chain[-1]` (the currently active key, the last element of `Chain`), the rotation does not chain to genesis. The reader MUST abort immediately with a single-line error:
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
4. **Sequence Gap:** If sequence numbers are not strictly contiguous ($S+1, S+2, \dots$), the reader MUST abort immediately:
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
7. **Missing Snapshot:** If a referenced snapshot pack does not exist in storage:
   ```
   refusal: replay failed: missing snapshot pack <sha256> on stream <id> (verify object storage bucket integrity or restore from backup)
   ```
8. **Snapshot Hash Mismatch:** If downloaded snapshot pack bytes fail SHA-256 verification:
   ```
   refusal: replay failed: snapshot hash mismatch for <sha256> on stream <id> (computed <actual>) (snapshot pack in object storage is corrupt)
   ```
9. **Never Guess:** Readers MUST never skip unverified, unchainable, or missing records. Partial or guessed recovery is strictly prohibited.
10. **Reused Token Identifier:** If a `token_create` names a `token_id` the rebuilt table already holds:
    ```
    refusal: replay failed: token create at seq <N> reuses token id <token-id>
    ```
11. **Unknown Token Revoked:** If a `token_revoke` names a `token_id` the rebuilt table does not hold, the revocation does not chain to a creation:
    ```
    refusal: replay failed: token revoke at seq <N> names unknown token <token-id>
    ```
12. **Token Hash Disagreement:** If a `token_revoke` carries a `token_hash` that is not the one recorded for that `token_id`:
    ```
    refusal: replay failed: token revoke at seq <N> disagrees with the hash recorded for token <token-id>
    ```
13. **Malformed Token Record:** If a `token_create` or `token_revoke` violates any field rule of section 4.3 or 4.4 — the `token_id` character class or 255-byte cap, the `token_hash` format, a `scopes` array that is empty, holds an empty string, repeats one, or contains a scope with an ASCII control character (`0x00`-`0x1F` or `0x7F`, the newline included), or a `signature` field that is absent or not formatted as `ed25519:<128-hex>` — the record is refused before it is applied to the token table (section 4.5, rule 3), with `<reason>` naming the field rule that failed:
    ```
    refusal: replay failed: invalid token record at seq <N> (<reason>)
    ```
    A `token_hash` that is not `sha256:<64-lowercase-hex>` is refused under this rule and not repaired, which is also what keeps a raw bearer token out of the journal: a record carrying one where the hash belongs does not parse as a hash, and a writer that emits it is refused rather than publishing the secret.
14. **Unknown Key Epoch:** If a `ref_update` record's `key_epoch` is not a valid index into `Chain` (that is, `key_epoch >= len(Chain)`), the reader MUST NOT fall back to `Chain[-1]` or any other key. It MUST abort immediately with a single-line error:
    ```
    refusal: replay failed: ref update on stream <id> at seq <N> names unknown key epoch <E>
    ```
15. **Key Epoch Regression:** If a `ref_update` record's `key_epoch` is lower than the `key_epoch` already verified *in this replay* on a prior record of the *same stream*, the reader MUST abort immediately with a single-line error:
    ```
    refusal: replay failed: ref update on stream <id> at seq <N> names key epoch <E> below epoch <F> already seen on this stream
    ```
    Without this check a retired key, still present earlier in `Chain`, would go on validating any record naming its epoch forever within the replay — exactly the outcome key rotation exists to end. "Already seen on this stream" means seen by `LastEpoch` in this replay (step 3) — see the caveat under step 3 above. This rule cannot, by itself, stop a retired key from validating a record placed on a stream this replay has not yet seen carry a higher epoch — including a stream the attacker creates after the rotation for exactly that reason — which needs a floor that is not scoped per stream, and this rule does not provide one.
16. **Marker Signature Mismatch:** If a marker's signature does not verify against the key its own `key_epoch` names, the reader MUST abort immediately, before trusting any other field on the marker:
    ```
    refusal: replay failed: signature mismatch for marker on stream <id> at sequence <N>
    ```
17. **Marker Names an Unknown Key Epoch:** If a marker's `key_epoch` is not a valid index into `Chain`, the reader MUST NOT fall back to `Chain[-1]` or any other key — worded to match rule 14's ref-transaction equivalent:
    ```
    refusal: replay failed: marker on stream <id> names unknown key epoch <E>
    ```
18. **Marker Ref Not in Snapshot:** If a marker names a ref pointing at an object the snapshot pack it also names does not carry (Guarantee 3, section 7.3):
    ```
    refusal: replay failed: marker on stream <id> names <ref> at <oid>, which the snapshot pack does not carry (marker.json in object storage is invalid)
    ```
19. **Token Record Signature Mismatch:** If a `token_create` or `token_revoke` record's signature does not verify against the key active at its own meta sequence (`Chain[-1]` at the point the replay reaches it — section 4.3's payload note explains why this is `Chain[-1]` and not a named `key_epoch`), the reader MUST abort immediately, before the record is applied to the token table:
    ```
    refusal: replay failed: signature mismatch for token record at seq <N>
    ```

---

## 9. Stream Model and Key Space Layout (Ruling 2)

### 9.1 Stream Partitioning
- **Repository Streams:** Each repo is one stream with caller-chosen ID matching `^[a-zA-Z0-9._-]+$` (max 255 bytes). Sequence starts at `0` upon first push.
- **The Meta Stream (`_meta`):** Reserved for server identity, key rotations, and token mutations. It carries no `ref_update` records and, although its name matches `^[a-zA-Z0-9._-]+$` like any repository stream, it is excluded by name from the repository-stream sweep of section 8 step 3 — section 8 step 2 already replays it in full.
- **Per-Stream Fencing:** Fencing leases are strictly isolated per stream. A conditional append conflict on repo stream $A$ fences stream $A$ on that instance, with zero effect on repo stream $B$ or on `_meta`.

### 9.2 Key Space Layout
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

The boot-time compare-and-swap probe (section 11.6) writes and then deletes a
transient key at `v1/probe/<32-hex>`, outside this `v1/streams/<stream-id>/`
tree entirely. A reader ignores anything outside `v1/streams/`, so the probe
key is invisible to materialization and to a stream `LIST`.

---

## 10. Lexicographical Ordering Guarantees

| Key Category | Key Pattern | Lexicographically Ordered by Sequence? | Reader Invariants |
| :--- | :--- | :---: | :--- |
| **Transaction Records** | `v1/streams/<stream-id>/tx/<seq>.json` | **YES** | Strictly ascending numerical order. Replay order matches lexicographical listing order. |
| **Pack Segments** | `v1/streams/<stream-id>/segments/<sha256>.pack` | **NO** | Random cryptographic hash order. Referenced by hash in transactions. |
| **Compaction Snapshots** | `v1/streams/<stream-id>/snapshots/<sha256>.pack` | **NO** | Resolved via `marker.json`. |
| **Replay Marker** | `v1/streams/<stream-id>/marker.json` | **N/A** | Direct GET. |
| **Stream Directory** | `v1/streams/<stream-id>/` | **NO** (Alphabetical) | Stream listing order does not imply creation order. |

---

## 11. Fencing, Conditional Append, and the Compare-and-Swap (CAS) Requirement (Ruling 5)

### 11.1 Compare-and-Swap (CAS) as a Non-Negotiable Storage Requirement

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

### 11.2 S3-Compatible Provider Support Matrix

The following matrix documents the compatibility of major S3-compatible object storage providers with walden's compare-and-swap requirement.

**This table is documentation, not enforcement.** It exists so an operator can choose a provider before deploying; walden's enforcement of the requirement above is a boot-time probe of the bucket itself rather than this table — a hostname is not a capability. See section 11.6.

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

### 11.3 Out of Scope Declaration (No Fallback Coordination)

**Explicitly out of scope, now and forever for format v1 (and not a follow-up ticket):** any fallback path for non-CAS storage providers — such as:
- Distributed lock objects or lock-file dances in object storage
- Lease files, renewal loops, or heartbeat files
- Two-phase commit or consensus sidecars
- External distributed coordinators (e.g. etcd, Consul, ZooKeeper, DynamoDB, Redis)

#### Rationale
Building fallback coordination paths is how a hundred correctness-critical lines of code become five hundred lines of brittle failure modes. *"Works on fewer providers, correctly"* beats *"works everywhere, probably."*

Walden deliberately chooses standard-library maximalism and an absolute minimum surface area for correctness. If industry demand ever materializes for storage backends that lack native CAS, that is a v2 conversation with an explicit format revision, never a v1 compromise.

---

### 11.4 Writer Obligations and Fencing Lifecycle

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

#### 6. Resending a Conditional Append
- A writer MAY resend a conditional append only while every earlier attempt at that key is known not to have been applied. That is the case when the request never fully reached storage, or when storage rejected it before evaluation: `408`, `400` `RequestTimeout`, `409` `ConditionalRequestConflict`, `429`, or `503`.
- After an attempt whose outcome is unknown, the writer MUST NOT resend it. That includes a connection lost or timed out after the full request was sent, and a `500`, `502`, or `504`. The reason: a resend's `412` could be its own earlier write, and item 2's "definitive proof" would then be false.
- The writer MUST NOT `GET` the key or `LIST` the stream to find out. That is guessing, and it is forbidden by item 4.
- The writer MUST transition the stream to permanently fenced (item 3) and refuse the write. Restart re-materializes from the journal, which is the authority on whether the record landed.

---

### 11.5 Single-Line Refusal Message Formats

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
6. **Bucket Fails the Boot Compare-and-Swap Probe:**
   ```
   invalid journal: <provider> does not support compare-and-swap (CAS) conditional writes (choose a bucket provider that supports conditional writes, per spec/journal/v1 section 11.2)
   ```
   This is a different condition from item 5, not the same one reworded. It is refused at
   boot, once the boot-time compare-and-swap probe of section 11.6 proves the bucket does
   not honor `If-None-Match: *` — so it names the `WALDEN_JOURNAL` knob rather than opening
   with `refusal:`, and it names the provider. `<provider>` is the name from the support
   matrix of section 11.2 when the journal URL's host resolves to a known one, or the
   endpoint's `host[:port]` otherwise, since a self-hosted endpoint (MinIO, Ceph RGW,
   Garage) has no provider name to give. This is a real check against the real bucket, not
   a guess from the hostname: section 11.2's table is advice for choosing a provider before
   deploying, never itself the enforcement.
7. **Conditional Append With Unknown Outcome (Repository Stream):**
   ```
   refusal: push failed: stream <stream-id> append at seq <seq> has unknown outcome (instance is fenced for this stream; restart walden process to re-materialize from journal)
   ```
   Per section 11.4 item 6: the writer could not prove whether the append at `seq` landed,
   so it fences the stream exactly as it would for item 2's `412`, rather than resend or
   re-read the key to find out.
8. **Conditional Append With Unknown Outcome (Meta Stream):**
   ```
   refusal: meta operation failed: stream _meta append at seq <seq> has unknown outcome (instance is fenced for this stream; restart walden process to re-materialize from journal)
   ```
   The meta-stream counterpart to item 7, the same way item 3 is to item 1 and item 4 is to
   item 2.

These eight messages, the `If-None-Match: *` precondition, and the derivation of the append target key are pinned by [`fixtures/conditional_append.json`](fixtures/conditional_append.json).

---

### 11.6 Boot-Time Compare-and-Swap Probe

Before enabling the journal, a writer MUST probe the bucket itself to confirm
the compare-and-swap contract of section 11.1, rather than trust the
support-matrix table of section 11.2, which is advice for choosing a
provider and not enforcement. The probe is the sole gate: a writer MUST NOT
infer compare-and-swap support from the journal URL's hostname.

1. Choose a fresh key `v1/probe/<32 lowercase hex characters>`, outside
   `v1/streams/` (section 9.2), with the hex suffix drawn from a
   cryptographically random source. A fresh key per boot means two writers
   starting against the same journal prefix at the same time never race the
   same probe key.
2. `PUT` the key with `If-None-Match: *`. This attempt MUST succeed; any
   other outcome (an error status, an unreachable endpoint, or an ambiguous
   outcome per section 11.4 item 6) fails the probe and MUST refuse boot,
   though not necessarily with item 6 of section 11.5 — this first write's
   failure means the bucket or the credentials are wrong, not that
   compare-and-swap is unsupported, since nothing has yet proven the target
   key existed.
3. `PUT` the same key again, with the same `If-None-Match: *` header. This
   second attempt MUST come back `412 Precondition Failed`. A `412` is the
   proof the probe exists to collect: the writer proceeds, and the journal
   is enabled.
4. A `200` (or any other success) on the second write is proof the bucket
   silently overwrote instead of honouring the precondition. The writer
   MUST refuse to enable the journal, with the single-line message of
   section 11.5 item 6.
5. As with any conditional append (section 11.4 item 6), a writer MUST NOT
   resend a probe write whose outcome is unknown, and MUST NOT `GET` or
   `LIST` the key to find out. An ambiguous second write is refused the same
   way a definite failure is: never as proof of a `412` it did not actually
   observe.
6. Once the probe has run — pass or refuse — the writer MUST attempt to
   delete the probe key. A failed delete MUST NOT itself refuse boot: it is
   a one-line warning, and the writer proceeds (or, if the probe otherwise
   refused, stays refused) regardless. A stranded probe key is litter, never
   a durability problem, and nothing under `v1/streams/` is ever deleted by
   this or any other operation.

This probe is the only enforcement of section 11.1 a writer performs. It
also doubles as a credentials and reachability check: a wrong access key, an
unreachable endpoint, or missing write permission on the prefix all surface
here, at boot, before the server binds a listening port or accepts a push.

---

## 12. Replay and Materialization Rules

To materialize or restore a repository stream from the journal:

1. **Locate Marker:** Check for `v1/streams/<stream-id>/marker.json`.
   - If present: Parse `marker.json` per Section 7 and **verify its signature against the key its own `key_epoch` names, before trusting any other field on it.** Load and verify the referenced snapshot packfile from `v1/streams/<stream-id>/snapshots/<sha256>.pack`, apply it, **set exactly the marker's `refs` and no others**, **seed the epoch floor from `marker.key_epoch_floor`**, and initialize repository state at `marker.sequence`.
   - If absent: Begin replay from `seq = 00000000000000000000` with an empty ref set and an epoch floor of `0`.
2. **Scan Transactions:** Perform a paginated `LIST` under `v1/streams/<stream-id>/tx/` with `start-after` set to the last materialized sequence (e.g. `v1/streams/<stream-id>/tx/<sequence:020d>.json`).
3. **Verify Continuity:**
   - Verify that sequence numbers are strictly contiguous ($s_0+1, s_0+2, \dots$).
   - Any gap indicates journal truncation or missing objects and MUST cause materialization to abort loudly with a one-line error.
4. **Apply and Verify:** Apply ref updates in sequence order, fetching required pack segments by content hash. Superseded segments or historical transactions ($s \le \text{marker.sequence}$) present in storage but not referenced in active replay MUST be ignored per Section 7.3, Guarantee 2.

---

## 13. Reimplementation Grant

This specification is published with an unconditional reimplementation grant. Anyone may implement this signing identity model, genesis record, key rotation protocol, token table records, ref-transaction record format, pack segment content addressing, stream layout, and reader/writer semantics in any programming language, for any purpose, without restriction and without asking.

A complete golden journal covering every ruling in this document — genesis, rotation and a token table created and revoked, both stream shapes, all four ref-transaction cases, real content-addressed packfiles, post-compaction snapshot and marker state, and the conditional-append targets and refusals of Section 11 — is published alongside it in [`fixtures/`](fixtures/) under the same grant.
