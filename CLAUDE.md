# Recryption

TypeScript library implementing three reusable identity-verification primitives:
Ed25519 badge issuance/verification, HMAC-SHA256 duplicate-document detection, and
revocation-on-claim-change.

The authoritative design is spec/identity-verification-protocol.md — consult it before
changing any crypto, key-lifecycle, pepper, or revocation behavior, and do not re-litigate
the decisions recorded in its decisions log (D1–D5).
spec/identity-verification-encryption-spec.md is the original app-specific spec this
library was extracted from, kept for historical context only — do not edit it.

## Commands

- `npm test` — run the vitest suite
- `npm run build` — compile to dist/

## Conventions

- Stored-record field names match the spec's snake_case shapes (key_id, claims_digest,
  pepper_id) even though the surrounding TypeScript is camelCase.
- The library never persists secrets: private keys stay behind the Signer callback
  (KMS/HSM side), peppers are supplied per-call from the deploying app's secret store.
- Storage is pluggable: apps implement the *Store interfaces over their own database;
  in-memory reference implementations live in tests/helpers.ts.
