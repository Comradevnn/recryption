# Recryption

A zero-retention identity-verification library: Ed25519-signed badges, HMAC-SHA256
duplicate detection, and revocation-on-claim-change — without server-side retention of
any identity document data. It's a library a deploying app embeds, not (yet) a
cross-platform protocol — see decision D1 in the spec.

Extracted from and used by [In Good Company](https://github.com/Comradevnn/In-Good-Company).

## Status
Early-stage TypeScript library implementing the spec's three primitives (key lifecycle,
badge issuance/verification, duplicate detection) with a full test suite. Not yet
published to npm. See `spec/identity-verification-protocol.md` for the design and its
decisions log.

- `npm test` — run the suite
- `npm run build` — compile to `dist/`

## Usage

```ts
import { BadgeService, KeyManager } from "recryption";
import * as ed from "@noble/ed25519";

// Storage is pluggable: implement KeyStore and BadgeStore over your own
// database (in-memory reference implementations live in tests/helpers.ts).
const keys = new KeyManager(myKeyStore);
const badges = new BadgeService(myBadgeStore, keys, {
  // Claims-digest source fields (spec §3.1): the verified *values* in your
  // user store — badges auto-revoke if these later change.
  sourceFields: ["legal_name", "dob"],
  resolveSourceFields: async (subjectId) => db.getVerifiedFields(subjectId),
});

// Demo keypair — in production the private key lives in your KMS/HSM and the
// signer callback invokes it; the library never sees private key material.
const privateKey = ed.utils.randomPrivateKey();
const publicKeyHex = Buffer.from(await ed.getPublicKeyAsync(privateKey)).toString("hex");
const signer = async (message: Buffer) =>
  Buffer.from(await ed.signAsync(new Uint8Array(message), privateKey));

// Install the first signing key.
const key = await keys.rotate(publicKeyHex);

// Issue a badge over app-verified outcomes.
const badge = await badges.issue(
  { subject_id: "user-123", claims: { name_verified: true, dob_verified: true } },
  signer,
);

// Verify: Ed25519 signature + key status + badge status + claims digest,
// pull-checked on every call (spec D4).
const result = await badges.verify(badge); // { ok: true, payload: { ... } }

// Planned rotation: the old key retires but still verifies old badges.
await keys.rotate(nextPublicKeyHex);
await badges.verify(badge); // still { ok: true, ... }

// Compromise response: revoked keys fail immediately; reissue the survivors.
await keys.revoke(key.key_id);
await badges.verify(badge); // { ok: false, reason: "key_revoked" }
await badges.reissueAll(key.key_id, nextSigner);
```

## What this does NOT do
Manual-entry verification only — no ML document authenticity checks, no OCR, no liveness
detection. See threat model in `spec/` for exactly what this protects against.