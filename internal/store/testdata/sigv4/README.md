# SigV4 test vectors

`suite/` is a verbatim copy of the `v4` cases from the AWS signing test
suite:

- Upstream repository: https://github.com/awslabs/aws-c-auth
- Path: `tests/aws-signing-test-suite/v4`
- Commit: `c4bc791ac6985eedb503e882cd450cc5b344c2f2`
- License: Apache License 2.0 (same as walden; see the upstream `LICENSE`
  file, not reproduced here)

Fetched once and committed; walden's test suite never downloads these at
test time. File names inside each case directory are unchanged from
upstream (`context.json`, `request.txt`, `header-*.txt`, `query-*.txt`).
walden signs with the `Authorization` header only, so only the `header-*`
files are exercised by `sigv4_test.go`; the `query-*` files (presigned-URL
vectors) are kept for fidelity with upstream but are not read by any test.

The S3 header-auth, streaming, and presigned-URL (`UNSIGNED-PAYLOAD`)
examples used elsewhere in `sigv4_test.go` are transcribed by hand from the
AWS S3 API Reference:

- "Signature Calculations for the Authorization Header: Transferring
  Payload in a Single Chunk (AWS Signature Version 4)"
  https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
- "Signature Calculations for the Authorization Header: Transferring
  Payload in Multiple Chunks (Chunked Upload) (AWS Signature Version 4)"
  https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
- "Authenticating Requests: Using Query Parameters (AWS Signature Version
  4)"
  https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
