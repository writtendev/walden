# Auth Format v1 Golden Fixtures

This directory contains reference golden fixture files demonstrating Walden auth format v1 conformance for:
1. **`identifiers.json`**: Repository identifier syntax, flat namespace validation, length bounds, and refusal mapping.
2. **`scopes.json`**: Scope vocabulary parsing, action set validation (`r`, `w`, `c`), canonicalization, and glob matching evaluation.
3. **`builtin_tokens.json`**: Built-in bearer tokens, SHA-256 hash storage representation, and permission resolution.
4. **`capability_tokens.json`**: Delegated capability token envelopes, canonical signing payloads, Ed25519 signatures, expiry evaluations, and tampering detection.

## Conformance Testing

Every implementation of Walden format v1 MUST pass all test cases defined in these fixture files without modification.
