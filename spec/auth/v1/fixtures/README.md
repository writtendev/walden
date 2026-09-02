# Auth Format v1 Golden Fixtures

This directory contains reference golden fixture files demonstrating Walden auth format v1 conformance for:
1. **`identifiers.json`**: Repository identifier syntax, flat namespace validation, length bounds, and refusal mapping.
2. **`scopes.json`**: Scope vocabulary parsing, action set validation (`r`, `w`, `c`), canonicalization, and glob matching evaluation.
3. **`builtin_tokens.json`**: Built-in bearer tokens, SHA-256 hash storage representation, and permission resolution.
4. **`capability_tokens.json`**: Delegated capability token envelopes, canonical signing payloads, Ed25519 signatures, expiry evaluations, and tampering detection.

## Conformance Testing

Every implementation of Walden format v1 MUST pass all test cases defined in these fixture files without modification.

walden holds itself to that in `internal/auth/fixtures_test.go`, which pins the file list above, pins how many cases each file carries, pins what each case is expected to mean in the test rather than recomputing it from the case itself, and refuses a fixture field no test reads. A file added here therefore has to be read by a test, a case removed from one fails the suite rather than quietly shrinking it, and a case edited in place fails rather than carrying its own expectation along with it. The examples in [the specification](../README.md) are held to these fixtures by the same tests, so the prose and the tables cannot drift apart either.
