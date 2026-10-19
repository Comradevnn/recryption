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

## Orchestration (Opus 5.5 as orchestrator)

When a session runs Opus 5.5 as orchestrator, delegate with the Agent tool and set `model`:

- **haiku** — read-only work: searching the repo or spec, summarizing files, inventorying
  exports, checking test output. Haiku never edits files.
- **sonnet** — all code writing: modules under src/, tests, build/config changes.
- **Opus (orchestrator)** — decisions, sub-agent verification, final synthesis, and anything
  touching crypto, key lifecycle, peppers, or revocation. Read the relevant section of
  spec/identity-verification-protocol.md yourself before delegating such work, and do not
  hand sub-agents a task that would reopen decisions D1–D5.

Rules for delegation:

- Brief each sub-agent self-contained: goal, exact files, what "done" looks like, what not
  to touch (never spec/identity-verification-encryption-spec.md).
- Sub-agent reports are claims, not proof. Verify by reading the diff and running
  `npm test` and `npm run build` before reporting work as done.
- Never let two sonnet agents edit the same file concurrently; split by module.
- Sub-agents must not commit, push, or add secrets (keys, peppers) to code or tests; use
  generated test keys and the helpers in tests/helpers.ts.
