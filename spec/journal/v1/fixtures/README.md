# Journal Format v1 Golden Fixtures

This directory contains reference fixture files demonstrating the journal format v1 layout, key paths, stream coordinate model, cryptographic identity chain, ref transaction records, content-addressed pack segments, and conditional CAS append targets.

## Directory Structure

```
fixtures/
├── README.md
└── streams/
    ├── _meta/
    │   └── tx/
    │       ├── 00000000000000000000.json  # Genesis record (root signing identity)
    │       ├── 00000000000000000001.json  # Token mutation (rwc:* admin token)
    │       └── 00000000000000000002.json  # Key rotation record (chained to genesis)
    └── repo-alpha/
        ├── tx/
        │   ├── 00000000000000000000.json  # Ref transaction (initial push: refs/heads/main)
        │   ├── 00000000000000000001.json  # Ref transaction (multi-ref update: update main, create feature)
        │   └── 00000000000000000002.json  # Ref transaction (zero segments: delete feature)
        ├── segments/
        │   └── 2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db.pack
        ├── snapshots/
        │   └── 2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db.pack
        └── marker.json
```

## Key Space and Identity Conformance Rules

1. **Transaction Keys (`tx/`):** Must strictly match `^[0-9]{20}\.json$`. Zero-indexed, strictly monotonic, and sequential.
2. **Genesis Record (`_meta/tx/00000000000000000000.json`):** Declares root Ed25519 public key. No signature field.
3. **Key Rotation (`_meta/tx/...`):** Carries `old_public_key`, `new_public_key`, and valid signature from `old_public_key` over canonical rotation payload.
4. **Ref-Transaction Records (`<stream>/tx/...`):** Carries `segments`, `updates` (ref update triples with raw byte ref names), `timestamp`, and valid signature from active server signing key over canonical ref update payload.
5. **Segment Keys (`segments/`):** Must strictly match `^[0-9a-f]{64}\.pack$`. Content-addressed by SHA-256 of raw packfile bytes verbatim.
6. **Snapshot Keys (`snapshots/`):** Must strictly match `^[0-9a-f]{64}\.pack$`. Content-addressed by SHA-256 of consolidated pack bytes. The snapshot pack MUST be uploaded and verified before `marker.json` is published (Publish-Last Invariant).
7. **Marker (`marker.json`):** Declares replay baseline `sequence` and `snapshot` hash. Superseded historical segments and earlier transaction records ($s \le \text{marker.sequence}$) are valid historical artifacts and MUST be ignored during replay rather than treated as corruption.
8. **Conditional Append & Single-Writer Fencing:** Every write to `tx/<seq>.json` is conditioned on `If-None-Match: *`. Storage precondition conflicts (HTTP 412) permanently fence the stream on the writer without retrying or guessing.
