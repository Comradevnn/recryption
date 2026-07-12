# Recryption

A zero-retention identity verification protocol: Ed25519-signed badges, HMAC-SHA256
duplicate detection, and revocation-on-claim-change — without server-side retention of
any identity document data.

Extracted from and used by [In Good Company](https://github.com/Comradevnn/In-Good-Company).

## Status
Early-stage spec, not yet packaged for use. See `spec/` for the protocol design.

## What this does NOT do
Manual-entry verification only — no ML document authenticity checks, no OCR, no liveness
detection. See threat model in `spec/` for exactly what this protects against.