# Journal Format v1 Golden Fixtures

This directory holds a small, complete walden journal exactly as it would sit in an object storage bucket, plus one table of conditional-append targets and refusals that has no on-disk representation. Together they pin down the five rulings of [the format specification](../README.md): the server signing identity (spec section 2), the stream model and key layout (section 9), ref-transaction records (section 5), pack segments and content addressing (section 6), and conditional append, fencing, and the compare-and-swap requirement (section 11).

Everything here is real, not illustrative. Every SHA-256 in a filename is the digest of that file's bytes. Every packfile came out of the real `git` binary and parses with `git index-pack`. Every signature verifies against the public key the genesis record declares, over the canonical payloads of spec sections 4.2 and 5.3.

## Reimplementation Grant

These fixtures, like the specification they pin down, are published with an unconditional reimplementation grant. Anyone may use them to build, test, or certify an implementation of the walden journal format, in any language, for any purpose, without restriction and without asking. This mirrors section 13 of the [format specification](../README.md).

## Directory Structure

```
fixtures/
├── README.md
├── conditional_append.json               # CAS precondition, tx key derivation, fencing refusals
└── streams/
    ├── _meta/
    │   └── tx/
    │       ├── 00000000000000000000.json # Genesis record: the server's root signing identity
    │       ├── 00000000000000000001.json # Token table mutation (token_create, rwc:*)
    │       ├── 00000000000000000002.json # Key rotation, chained to and signed by the outgoing key
    │       └── 00000000000000000003.json # Token table mutation (token_revoke)
    ├── repo-alpha/                        # A repository stream under a human-chosen name
    │   ├── tx/
    │   │   ├── 00000000000000000000.json # First push into an empty repository
    │   │   ├── 00000000000000000001.json # Fast-forward main and create feature, atomically
    │   │   ├── 00000000000000000002.json # Branch delete: no new objects, empty segments array
    │   │   └── 00000000000000000003.json # Force update of main, signed by the rotated key
    │   ├── segments/                     # Three content-addressed packfiles, one per push
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

1. **Transaction Keys (`tx/`):** Must strictly match `^[0-9]{20}\.json$`. Zero-indexed, strictly monotonic, and sequential, with no gaps.
2. **Genesis Record (`_meta/tx/00000000000000000000.json`):** Declares the root Ed25519 public key. No signature field; it is the root of trust, not a claim about one.
3. **Key Rotation (`_meta/tx/…`):** Carries `old_public_key`, `new_public_key`, and a signature by `old_public_key` over the canonical rotation payload. A rotation whose `old_public_key` is not the active key does not chain and must be refused.
4. **Ref-Transaction Records (`<stream>/tx/…`):** Carry `segments`, `updates` (ref update triples with ref names as raw byte sequences), `timestamp`, and a signature by the active server signing key over the canonical ref-update payload.
5. **Segment Keys (`segments/`):** Must strictly match `^[0-9a-f]{64}\.pack$`. Content-addressed by SHA-256 of the raw packfile bytes verbatim.
6. **Snapshot Keys (`snapshots/`):** Must strictly match `^[0-9a-f]{64}\.pack$`. Content-addressed by SHA-256 of the consolidated pack bytes. The snapshot pack must be uploaded and verified before `marker.json` is published (the Publish-Last Invariant).
7. **Marker (`marker.json`):** Declares the replay baseline `sequence` and `snapshot` hash. `repo-alpha` carries a marker at sequence 1, so sequences 0 and 1 and the segments they reference are superseded — they remain in this fixture tree on purpose, and a reader must ignore them and resume at sequence 2 rather than treat them as corruption. The opaque stream carries no marker, which means replay starts at sequence 0.
8. **Conditional Append & Single-Writer Fencing:** `conditional_append.json` pins the precondition (`If-None-Match: *`, conflict `412 PreconditionFailed`), the deterministic append target `v1/streams/<stream-id>/tx/<seq:020d>.json` — including sequence 42 and the maximum unsigned 64-bit sequence — and the exact one-line refusals of spec section 11.5. A storage precondition conflict permanently fences that one stream on that one writer, which then refuses further writes to it without retrying, re-reading the head, or guessing.

## Regenerating

The fixtures are generated, not hand-edited:

```
WALDEN_REGENERATE_FIXTURES=1 go test ./internal/journal -run TestRegenerateFixtures
```

Signing keys, record timestamps, and git author and committer dates are all fixed, so the records and the commit OIDs reproduce exactly. The packfile bytes come from whichever `git` binary is on the path; a different git version may pack the same objects differently, which would change the content-addressed segment names without making either set wrong.
