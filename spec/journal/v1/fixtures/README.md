# Journal Format v1 Golden Fixtures

The `v1/` subtree here is a small, complete walden journal, and its paths are the object storage keys of spec section 9.2 verbatim: copy the `v1/` directory to the root of a bucket and a reader deriving keys from the specification finds every object exactly where it looks for it. Beside it sits one table of conditional-append targets and refusals, which pins behavior that has no on-disk representation in a journal. Together they pin down the five rulings of [the format specification](../README.md): the server signing identity, born as the genesis record and rotated in place (spec sections 3 and 4), the stream model and key layout (section 9), ref-transaction records (section 5), pack segments and content addressing (section 6), and conditional append, fencing, and the compare-and-swap requirement (section 11).

Everything here is real, not illustrative. Every SHA-256 in a filename is the digest of that file's bytes. Every packfile came out of the real `git` binary, and git unpacks every one of them again: the journal is replayed into a scratch repository on each test run, from sequence 0 and from the marker both. Both replays resolve every object ID their ref transactions name against the objects the packs actually carry, and `git fsck` is clean on the object database each one leaves behind. The replay from sequence 0 also reconstructs ref state and writes it out, so the refs land where the journal says they land; the replay from the marker does not, because a marker carries a baseline sequence and a snapshot and no ref state to check against. Every signature verifies against the signing key that was active when its record was written — see the journal timeline below — over the canonical payloads of spec sections 4.2 and 5.3.

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
        │       ├── 00000000000000000001.json # Token table mutation (token_create, rwc:*)
        │       ├── 00000000000000000002.json # Key rotation, chained to and signed by the outgoing key
        │       └── 00000000000000000003.json # Token table mutation (token_revoke)
        ├── repo-alpha/                       # A repository stream under a human-chosen name
        │   ├── tx/
        │   │   ├── 00000000000000000000.json # First push into an empty repository
        │   │   ├── 00000000000000000001.json # Fast-forward main and create feature, atomically
        │   │   ├── 00000000000000000002.json # Branch delete: no new objects, empty segments array
        │   │   └── 00000000000000000003.json # Force update of main, signed by the rotated key
        │   ├── segments/                     # Three content-addressed packfiles: the branch
        │   │                                 #   delete introduced no objects, so of the four
        │   │                                 #   pushes only three carried a pack
        │   ├── snapshots/                    # One consolidated snapshot pack
        │   └── marker.json                   # Replay from sequence 1 forward
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
| `00:01:00Z` | `_meta` | 1 | An admin token is created. |
| `00:02:00Z` | `repo-alpha` | 0 | First push into an empty repository: `refs/heads/main` created from the zero OID. |
| `00:03:00Z` | `repo-alpha` | 1 | One transaction moves `refs/heads/main` and creates `refs/heads/feature`. |
| `00:04:00Z` | `repo-alpha` | 2 | `refs/heads/feature` is deleted; no objects arrive, so `segments` is `[]`. |
| `00:05:00Z` | `9f2c1d7a-…` | 0 | A second repository's first push, on a stream whose counter starts over at zero. |
| `00:06:00Z` | `_meta` | 2 | The signing key rotates from `K0` to `K1`, signed by `K0`. |
| `00:07:00Z` | `repo-alpha` | 3 | A force update rewrites `refs/heads/main`, signed by `K1`. |
| `00:08:00Z` | `_meta` | 3 | The admin token is revoked. |
| `01:00:00Z` | `repo-alpha` | — | Compaction publishes a snapshot through sequence 1 and then `marker.json`. |

A ref transaction is verified against the signing key that was active when it was written: the rotation at `_meta` sequence 2 activates `K1` for what follows it and does not invalidate the history `K0` signed.

## Key Space and Identity Conformance Rules

Every object key is `v1/streams/<stream-id>/…`, exactly as spec section 9.2 derives it. The `v1/` component is part of the key, not a directory this repository added for tidiness.

1. **Transaction Keys (`tx/`):** Must strictly match `^[0-9]{20}\.json$`. Zero-indexed, strictly monotonic, and sequential, with no gaps.
2. **Genesis Record (`_meta/tx/00000000000000000000.json`):** Declares the root Ed25519 public key. No signature field; it is the root of trust, not a claim about one.
3. **Key Rotation (`_meta/tx/…`):** Carries `old_public_key`, `new_public_key`, and a signature by `old_public_key` over the canonical rotation payload. A rotation whose `old_public_key` is not the active key does not chain and must be refused.
4. **Ref-Transaction Records (`<stream>/tx/…`):** Carry `segments`, `updates` (ref update triples with ref names as raw byte sequences), `timestamp`, and a signature by the active server signing key over the canonical ref-update payload.
5. **Segment Keys (`segments/`):** Must strictly match `^[0-9a-f]{64}\.pack$`. Content-addressed by SHA-256 of the raw packfile bytes verbatim.
6. **Snapshot Keys (`snapshots/`):** Must strictly match `^[0-9a-f]{64}\.pack$`. Content-addressed by SHA-256 of the consolidated pack bytes. The snapshot pack must be uploaded and verified before `marker.json` is published (the Publish-Last Invariant).
7. **Marker (`marker.json`):** Declares the replay baseline `sequence` and `snapshot` hash. `repo-alpha` carries a marker at sequence 1, so sequences 0 and 1 and the segments they reference are superseded — they remain in this fixture tree on purpose, and a reader must ignore them and resume at sequence 2 rather than treat them as corruption. The opaque stream carries no marker, which means replay starts at sequence 0.
8. **Conditional Append & Single-Writer Fencing:** `conditional_append.json` pins the precondition (`If-None-Match: *`, conflict `412 PreconditionFailed`), the deterministic append target `v1/streams/<stream-id>/tx/<seq:020d>.json` — including sequence 42 and the maximum unsigned 64-bit sequence — and the exact one-line refusals of spec section 11.5. A storage precondition conflict permanently fences that one stream on that one writer, which then refuses further writes to it without retrying, re-reading the head, or guessing.

   Each row of `tx_keys` carries its `seq` as a decimal **string**. The table exists to pin key derivation across the whole 64-bit range, and a JSON number cannot carry that: a parser that reads numbers as IEEE doubles — JavaScript's, and everything built on it — reads `18446744073709551615` as `18446744073709552000` and derives a key that does not match the one printed beside it, failing a correct implementation against a correct fixture. A string is read exactly by every conformant parser. This is a property of this one table, which is a conformance harness rather than journal content; journal records encode their own `seq` as a JSON number, as spec section 5.1 defines.

## Regenerating

The fixtures are generated, not hand-edited:

```
WALDEN_REGENERATE_FIXTURES=1 go test ./internal/journal -run TestRegenerateFixtures
```

**Regenerating is two steps, and the command above is only the first.** The format specification quotes four of these fixtures as its worked examples, and two of those examples — the ref-transaction record of [section 5.1](../README.md) and `marker.json` in section 7.2 — carry pack digests inside them. If your `git` packs these objects differently from the `git` that produced the committed packs, the digests move, and the specification is then quoting records that no longer exist. `TestSpecExamplesMatchFixtures` fails until the examples in `../README.md` are brought back into line by hand, and it names the file and the line to fix.

That copy is deliberately manual. The examples are prose the author is answerable for, and a regenerator that silently rewrote them would also erase the only signal in the suite that a repack has happened at all — see the note under `TestSpecExamplesMatchFixtures`.

Signing keys, record timestamps, and git author and committer dates are all fixed, so the records and the commit OIDs reproduce exactly. The packfile bytes, however, come from whichever `git` binary is on the path, and packing is toolchain-dependent: **the committed pack bytes were generated with git 2.50.1.** That is not the git walden itself ships — the container image pins git 2.47.2 (`Dockerfile`) — and the two need not agree: these packs are a published artifact of the format, produced once by the generator, not something a walden build emits. The discrepancy is stated here so it is read rather than discovered. A different git version may pack the same objects differently, which changes the content-addressed segment and snapshot names — and therefore the digests the transaction records and `marker.json` carry — without making either set wrong. Regenerating with a different git is a real change to the fixtures, not a no-op, so review the resulting diff rather than assuming it is noise.
