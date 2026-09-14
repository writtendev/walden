# Journal Format v1 Golden Fixtures

The `v1/` subtree here is a small, complete walden journal, and its paths are the object storage keys of spec section 9.2 verbatim: copy the `v1/` directory to the root of a bucket and a reader deriving keys from the specification finds every object exactly where it looks for it. Beside it sits one table of conditional-append targets and refusals, which pins behavior that has no on-disk representation in a journal. Together they pin down the five rulings of [the format specification](../README.md): the server signing identity, born as the genesis record and rotated in place, and the token table that is created and revoked beside it on the meta stream (spec sections 3 and 4), the stream model and key layout (section 9), ref-transaction records (section 5), pack segments and content addressing (section 6), and conditional append, fencing, and the compare-and-swap requirement (section 11).

Everything here is real, not illustrative. Every SHA-256 in a filename is the digest of that file's bytes, and every `token_hash` on the meta stream is the real SHA-256 of the raw token [the auth fixtures](../../../auth/v1/fixtures/builtin_tokens.json) publish under that identifier, with the scopes published beside it. Hash and scopes are the whole of that agreement, and a cross-check between the two sets should be scoped to them: the auth set is a conformance table of tokens to authorize against, not a snapshot of the table this journal rebuilds to, so it publishes tokens this journal never creates and carries its own `revoked` flags. For revocation state the journal is authoritative — it revokes `tok_admin_01` at meta sequence 3, and `builtin_tokens.json` still publishes that token unrevoked, as its own table. Every packfile came out of the real `git` binary, and git unpacks every one of them again: the journal is replayed into a scratch repository on each test run, from sequence 0 and from the marker both. Both replays resolve every object ID their ref transactions name against the objects the packs actually carry, and `git fsck` is clean on the object database each one leaves behind. Both replays also reconstruct ref state and arrive at the same map: the replay from sequence 0 builds it up from an empty ref set, and the replay from the marker seeds it from the marker's own `refs` field before replaying the tail — which is what lets it recover `refs/tags/v0.1`, a ref last touched at sequence 1 that no transaction after the marker baseline ever mentions again. Every signature verifies against the signing key that was active when its record was written — see the journal timeline below — over the canonical payloads of spec sections 4.2, 4.3, 4.4, 5.3, and 7.2, and the marker itself is one more signed record in that set, not an exception to it.

## Reimplementation Grant

These fixtures, like the specification they pin down, are published with an unconditional reimplementation grant. Anyone may use them to build, test, or certify an implementation of the walden journal format, in any language, for any purpose, without restriction and without asking. This mirrors section 13 of the [format specification](../README.md).

## Directory Structure

Everything under `v1/` is bucket contents; the two files beside it are documentation and a behavior table, and belong to no journal.

```
fixtures/
├── README.md
├── conditional_append.json                   # CAS precondition, tx key derivation, fencing refusals
└── v1/                                       # ── the bucket tree: paths below are object keys ──
    └── streams/
        ├── _meta/
        │   └── tx/
        │       ├── 00000000000000000000.json # Genesis record: the server's root signing identity
        │       ├── 00000000000000000001.json # Token create: tok_admin_01, one scope (rwc:*)
        │       ├── 00000000000000000002.json # Key rotation, chained to and signed by the outgoing key
        │       ├── 00000000000000000003.json # Token revoke: tok_admin_01
        │       └── 00000000000000000004.json # Token create: tok_writer_02, two scopes
        ├── repo-alpha/                       # A repository stream under a human-chosen name
        │   ├── tx/
        │   │   ├── 00000000000000000000.json # First push into an empty repository
        │   │   ├── 00000000000000000001.json # Fast-forward main, create feature, tag v0.1,
        │   │   │                             #   and a non-ASCII ref (refs/heads/caf +
        │   │   │                             #   U+0065 + U+0301, decomposed)
        │   │   ├── 00000000000000000002.json # Branch delete: no new objects, empty segments array
        │   │   ├── 00000000000000000003.json # Force update of main, signed by the rotated key
        │   │   └── 00000000000000000004.json # main advances again, past the marker baseline
        │   ├── segments/                     # Four content-addressed packfiles: the branch
        │   │                                 #   delete introduced no objects, so of the five
        │   │                                 #   pushes only four carried a pack
        │   ├── snapshots/                    # One consolidated snapshot pack
        │   └── marker.json                   # Signed; carries refs/heads/caf + U+0065 +
        │                                     #   U+0301 (decomposed), refs/heads/main, and
        │                                     #   refs/tags/v0.1 as of sequence 3, and the
        │                                     #   epoch floor; replay from seq 4
        └── 9f2c1d7a-4e6b-4a10-8c3f-2b5d81e0a7c4/  # The same thing under an opaque identifier
            ├── tx/
            │   └── 00000000000000000000.json # First push: create a branch and a tag together
            └── segments/                     # One content-addressed packfile
```

## The Journal in Order

The two repository streams and the meta stream advance independently. Read in timestamp order, the fixture journal is one instance's whole life:

| Time | Stream | Seq | What happened |
| :--- | :--- | ---: | :--- |
| `00:00:00Z` | `_meta` | 0 | Journal initialized; the server mints and records its signing key `K0`. |
| `00:01:00Z` | `_meta` | 1 | An admin token is created: `tok_admin_01`, hashed, carrying the single scope `rwc:*`, signed by `K0`. |
| `00:02:00Z` | `repo-alpha` | 0 | First push into an empty repository: `refs/heads/main` created from the zero OID. |
| `00:03:00Z` | `repo-alpha` | 1 | One transaction moves `refs/heads/main`, creates `refs/heads/feature`, tags the commit main is leaving behind as `refs/tags/v0.1`, and creates `refs/heads/caf` + U+0065 + U+0301 (decomposed) — a ref name that is deliberately not NFC-invariant (rule 5 below). Neither `refs/tags/v0.1` nor this ref is ever touched again. |
| `00:04:00Z` | `repo-alpha` | 2 | `refs/heads/feature` is deleted; no objects arrive, so `segments` is `[]`. |
| `00:05:00Z` | `9f2c1d7a-…` | 0 | A second repository's first push, on a stream whose counter starts over at zero. |
| `00:06:00Z` | `_meta` | 2 | The signing key rotates from `K0` to `K1`, signed by `K0`. |
| `00:07:00Z` | `repo-alpha` | 3 | A force update rewrites `refs/heads/main`, signed by `K1`. This is also the marker's baseline sequence below. |
| `00:08:00Z` | `_meta` | 3 | The admin token is revoked, by identifier and by the hash it was created with, signed by `K1`. |
| `00:09:00Z` | `_meta` | 4 | A narrower token replaces it: `tok_writer_02`, carrying two scopes, signed by `K1`. |
| `00:10:00Z` | `repo-alpha` | 4 | `refs/heads/main` advances again, past the marker baseline, still signed by `K1`. |
| `01:00:00Z` | `repo-alpha` | — | Compaction publishes a snapshot through sequence 3 and then a signed `marker.json` carrying `refs/heads/caf` + U+0065 + U+0301 (decomposed), `refs/heads/main`, and `refs/tags/v0.1` as they stood at sequence 3, and an epoch floor of `1`. |

A ref transaction is verified against the signing key that was active when it was written, named explicitly by the record's own `key_epoch` rather than inferred from timing: the rotation at `_meta` sequence 2 activates `K1` (epoch 1) for what follows it and does not invalidate the history `K0` (epoch 0) signed. The marker is verified the same way, against the key its own `key_epoch` names.

## Key Space and Identity Conformance Rules

Every object key is `v1/streams/<stream-id>/…`, exactly as spec section 9.2 derives it. The `v1/` component is part of the key, not a directory this repository added for tidiness.

1. **Transaction Keys (`tx/`):** Must strictly match `^[0-9]{20}\.json$`. Zero-indexed, strictly monotonic, and sequential, with no gaps.
2. **Genesis Record (`_meta/tx/00000000000000000000.json`):** Declares the root Ed25519 public key. No signature field, and it is the only unsigned record in this tree: it is the root of trust, not a claim about one, and there is no prior key in the journal to sign it with. Every other record here — key rotation, token table mutation, ref transaction, marker — carries a signature.
3. **Key Rotation (`_meta/tx/…`):** Carries `old_public_key`, `new_public_key`, and a signature by `old_public_key` over the canonical rotation payload. A rotation whose `old_public_key` is not the active key does not chain and must be refused.
4. **Token Table Records (`_meta/tx/…`):** `token_create` carries the token's identifier, the `sha256:<64-lowercase-hex>` the server stores in place of the raw token, the scopes it was minted with as an array — one entry at sequence 1, two at sequence 4, because a token may carry more than one — and a signature by the key active at that meta sequence over the canonical payload of spec section 4.3. `token_revoke` names the token by identifier, repeats the hash it was created with, and carries the same kind of signature over spec section 4.4's payload. Replaying the meta stream rebuilds the whole token table from these records alone, verifying each signature against the chain before applying it (spec section 8, step 2; section 8.1, rule 19).
5. **Ref-Transaction Records (`<stream>/tx/…`):** Carry `key_epoch` (which key in the signing chain signed this record — `0` on every record here except `repo-alpha` seq 3 and seq 4, which carry `1`, signed after the rotation), `segments`, `updates` (ref update triples with ref names as raw byte sequences), `timestamp`, and a signature by the key `key_epoch` names over the canonical ref-update payload. One of `repo-alpha` seq 1's four ref names is deliberately not NFC-invariant: `refs/heads/caf` + U+0065 LATIN SMALL LETTER E + U+0301 COMBINING ACUTE ACCENT (decomposed), rather than the visually identical `refs/heads/caf` + U+00E9 LATIN SMALL LETTER E WITH ACUTE (precomposed NFC). This is not a typo to be tidied up: it exists so that an implementation which normalizes ref names — silently, as several language runtimes do by default — fails this fixture's signature checks instead of passing every fixture in the tree while carrying a defect that only shows up the first time an operator pushes a non-ASCII branch name. The precomposed form never appears anywhere in this tree; the two spellings render identically but are different byte sequences, and readers and writers alike must treat ref names as opaque bytes, never as text to be normalized.
6. **Segment Keys (`segments/`):** Must strictly match `^[0-9a-f]{64}\.pack$`. Content-addressed by SHA-256 of the raw packfile bytes verbatim.
7. **Snapshot Keys (`snapshots/`):** Must strictly match `^[0-9a-f]{64}\.pack$`. Content-addressed by SHA-256 of the consolidated pack bytes. The snapshot pack must be uploaded and verified before `marker.json` is published (the Publish-Last Invariant).
8. **Marker (`marker.json`):** A signed record declaring the replay baseline `sequence`, the `snapshot` hash, the authoritative `refs` set as of that sequence, and the `key_epoch` / `key_epoch_floor` pair a resumed replay verifies and seeds its epoch floor from. `repo-alpha` carries a marker at sequence 3 — past the key rotation — so sequences 0 through 3 and the segments they reference are superseded; they remain in this fixture tree on purpose, and a reader must ignore them and resume at sequence 4 rather than treat them as corruption. The marker's `refs` carry `refs/heads/caf` + U+0065 + U+0301 (decomposed, sorting first by raw bytes), `refs/heads/main` (as of sequence 3), and `refs/tags/v0.1` (created at sequence 1 and never touched again): a reader applying the snapshot and setting exactly these refs recovers `refs/tags/v0.1` and the non-ASCII ref without ever seeing the transactions that created them, which is the entire point of the ref set living in the marker rather than nowhere — and, for the non-ASCII ref, a second signed surface independent of the ref transaction that created it, so the same byte-preservation claim is checked twice. `key_epoch_floor` is `1`, the highest epoch any record at or before sequence 3 carries, and seeds the resumed replay's rule-15 floor so a forged record naming the retired epoch `0` at sequence 4 is refused exactly as it would be had the replay never been compacted. The opaque stream carries no marker, which means replay starts at sequence 0 with an empty ref set and an epoch floor of `0`.
9. **Conditional Append & Single-Writer Fencing:** `conditional_append.json` pins the precondition (`If-None-Match: *`, conflict `412 PreconditionFailed`), the deterministic append target `v1/streams/<stream-id>/tx/<seq:020d>.json` — including sequence 42 and the maximum unsigned 64-bit sequence — and the exact one-line refusals of spec section 11.5. A storage precondition conflict permanently fences that one stream on that one writer, which then refuses further writes to it without retrying, re-reading the head, or guessing.

   Each row of `tx_keys` carries its `seq` as a decimal **string**. The table exists to pin key derivation across the whole 64-bit range, and a JSON number cannot carry that: a parser that reads numbers as IEEE doubles — JavaScript's, and everything built on it — reads `18446744073709551615` as `18446744073709552000` and derives a key that does not match the one printed beside it, failing a correct implementation against a correct fixture. A string is read exactly by every conformant parser. Journal records encode their own `seq`, and `marker.json` its `sequence`, the same way and for the same reason (spec sections 3.1, 4.1, 4.3, 4.4, 5.1 and 7.2), so **no sequence anywhere in this tree is a JSON number** — every one of them is the exact decimal form of a 64-bit unsigned integer, in quotes.

## Regenerating

The fixtures are generated, not hand-edited:

```
WALDEN_REGENERATE_FIXTURES=1 go test ./internal/journal -run TestRegenerateFixtures
```

**Regenerating is two steps, and the command above is only the first.** The format specification quotes seven of these fixtures as its worked examples, and two of those examples — the ref-transaction record of [section 5.1](../README.md#51-json-schema-and-field-specification) and `marker.json` in [section 7.2](../README.md#72-json-schema-and-field-specification) — carry pack digests inside them. If your `git` packs these objects differently from the `git` that produced the committed packs, the digests move, and the specification is then quoting records that no longer exist. `TestSpecExamplesMatchFixtures` fails until the examples in `../README.md` are brought back into line by hand, and it names the file and the line to fix.

That copy is deliberately manual. The examples are prose the author is answerable for, and a regenerator that silently rewrote them would also erase the only signal in the suite that a repack has happened at all — see the note under `TestSpecExamplesMatchFixtures`.

Signing keys, record timestamps, and git author and committer dates are all fixed, so the records and the commit OIDs reproduce exactly. The packfile bytes, however, come from whichever `git` binary is on the path, and packing is toolchain-dependent: **the committed pack bytes were generated with git 2.50.1.** That is not the git walden itself ships — the container image pins git 2.47.2 (`Dockerfile`) — and the two need not agree: these packs are a published artifact of the format, produced once by the generator, not something a walden build emits. The discrepancy is stated here so it is read rather than discovered. A different git version may pack the same objects differently, which changes the content-addressed segment and snapshot names — and therefore the digests the transaction records and `marker.json` carry — without making either set wrong. Regenerating with a different git is a real change to the fixtures, not a no-op, so review the resulting diff rather than assuming it is noise.
