# Journal Format v1 Golden Fixtures

This directory contains reference fixture files demonstrating the journal format v1 layout, key paths, and stream coordinate model.

## Directory Structure

```
fixtures/
├── README.md
└── streams/
    ├── _meta/
    │   └── tx/
    │       ├── 00000000000000000000.json
    │       └── 00000000000000000001.json
    └── repo-alpha/
        ├── tx/
        │   └── 00000000000000000000.json
        ├── segments/
        │   └── 4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638.pack
        ├── snapshots/
        │   └── 4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638.pack
        └── marker.json
```

## Key Space Conformance Rules

1. **Transaction Keys (`tx/`):** Must strictly match `^[0-9]{20}\.json$`. Zero-indexed and sequential.
2. **Segment Keys (`segments/`):** Must strictly match `^[0-9a-f]{64}\.pack$`. Content-addressed by SHA-256 of packfile bytes.
3. **Snapshot Keys (`snapshots/`):** Must strictly match `^[0-9a-f]{64}\.pack$`. Content-addressed by SHA-256 of consolidated pack bytes.
4. **Marker (`marker.json`):** Points to the compacted baseline snapshot and sequence.
