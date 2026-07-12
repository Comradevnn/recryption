import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  BadgeService,
  CanonicalizationError,
  InvalidBadgeTransitionError,
  NoActiveKeyError,
  SignerMismatchError,
  UnknownBadgeError,
  canonicalJson,
  type JsonValue,
  type SignedBadge,
} from "../src/badge.js";
import { KeyManager } from "../src/keys.js";
import { InMemoryBadgeStore, InMemoryKeyStore, makeKeypairSigner } from "./helpers.js";

type SubjectRecord = Record<string, JsonValue>;

/**
 * Wires a full issuance stack: key manager with one active key, badge service
 * whose claims digest covers legal_name + dob (source values), and mutable
 * subject records that also carry derived booleans (NOT digest-covered).
 */
async function setup() {
  const subjects = new Map<string, SubjectRecord>([
    ["alice", { legal_name: "Alice Example", dob: "1990-01-15", name_verified: true }],
    ["bob", { legal_name: "Bob Sample", dob: "1985-06-02", name_verified: true }],
  ]);
  const keyStore = new InMemoryKeyStore();
  const keys = new KeyManager(keyStore);
  const { publicKeyHex, signer } = makeKeypairSigner();
  const key = await keys.rotate(publicKeyHex);
  const store = new InMemoryBadgeStore();
  const service = new BadgeService(store, keys, {
    sourceFields: ["legal_name", "dob"],
    resolveSourceFields: async (id) => subjects.get(id) ?? {},
  });
  return { subjects, keyStore, keys, key, signer, store, service };
}

describe("canonicalJson (spec §1.2)", () => {
  it("sorts keys recursively and emits no whitespace", () => {
    expect(canonicalJson({ b: 1, a: { d: [2, "x"], c: true } })).toBe(
      '{"a":{"c":true,"d":[2,"x"]},"b":1}',
    );
  });

  it("rejects non-integer numbers and undefined values", () => {
    expect(() => canonicalJson({ a: 1.5 })).toThrow(CanonicalizationError);
    expect(() => canonicalJson({ a: undefined })).toThrow(CanonicalizationError);
  });
});

describe("BadgeService.issue (spec §1.2)", () => {
  it("builds the payload per spec and stores a valid record plus the signed badge", async () => {
    const { service, signer, key, store } = await setup();
    const badge = await service.issue(
      { subject_id: "alice", claims: { name_verified: true, document_type: "drivers_license" } },
      signer,
    );

    expect(badge.payload.v).toBe(1);
    expect(badge.payload.verification_method).toBe("manual");
    expect(badge.payload.key_id).toBe(key.key_id);
    expect(badge.sig).toMatch(/^[0-9a-f]{128}$/);

    const expectedDigest = createHash("sha256")
      .update(canonicalJson({ dob: "1990-01-15", legal_name: "Alice Example" }), "utf8")
      .digest("hex");
    expect(badge.payload.claims_digest).toBe(expectedDigest);

    const record = await store.get(badge.payload.badge_id);
    expect(record).toMatchObject({ status: "valid", revoked_reason: null, key_id: key.key_id });
    expect(await store.getSigned(badge.payload.badge_id)).toEqual(badge);
  });

  it("rejects a signer that does not match the active key", async () => {
    const { service } = await setup();
    const rogue = makeKeypairSigner();
    await expect(
      service.issue({ subject_id: "alice", claims: {} }, rogue.signer),
    ).rejects.toThrow(SignerMismatchError);
  });

  it("refuses to issue with no active key (post-compromise window)", async () => {
    const { service, keys, key, signer } = await setup();
    await keys.revoke(key.key_id);
    await expect(service.issue({ subject_id: "alice", claims: {} }, signer)).rejects.toThrow(
      NoActiveKeyError,
    );
  });
});

describe("BadgeService.verify (spec §1.4)", () => {
  it("verifies a freshly issued badge", async () => {
    const { service, signer } = await setup();
    const badge = await service.issue({ subject_id: "alice", claims: { name_verified: true } }, signer);
    expect(await service.verify(badge)).toEqual({ ok: true, payload: badge.payload });
  });

  it("retired-key badges still pass; revoked-key badges fail immediately (D3)", async () => {
    const { service, keys, key, signer } = await setup();
    const badge = await service.issue({ subject_id: "alice", claims: {} }, signer);

    await keys.rotate(makeKeypairSigner().publicKeyHex); // planned rotation: key is now retired
    expect((await service.verify(badge)).ok).toBe(true);

    await keys.revoke(key.key_id); // compromise response: no grace period
    expect(await service.verify(badge)).toEqual({ ok: false, reason: "key_revoked" });
  });

  it("fails a tampered payload with bad_signature", async () => {
    const { service, signer } = await setup();
    const badge = await service.issue({ subject_id: "alice", claims: { name_verified: false } }, signer);
    const tampered: SignedBadge = {
      ...badge,
      payload: { ...badge.payload, claims: { name_verified: true } },
    };
    expect(await service.verify(tampered)).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("fails unknown badge_ids — signature validity alone is never a pass (D4)", async () => {
    const { service, signer, store } = await setup();
    const badge = await service.issue({ subject_id: "alice", claims: {} }, signer);
    store.deleteRecord(badge.payload.badge_id);
    expect(await service.verify(badge)).toEqual({ ok: false, reason: "unknown_badge" });
  });

  it("rejects unsupported payload versions", async () => {
    const { service, signer } = await setup();
    const badge = await service.issue({ subject_id: "alice", claims: {} }, signer);
    const v2 = { ...badge, payload: { ...badge.payload, v: 2 as unknown as 1 } };
    expect(await service.verify(v2)).toEqual({ ok: false, reason: "unsupported_version" });
  });

  it("fails badges issued well after their key retired (spec §1.4 step 7)", async () => {
    const { service, keys, keyStore, key, signer } = await setup();
    const badge = await service.issue({ subject_id: "alice", claims: {} }, signer);
    await keys.rotate(makeKeypairSigner().publicKeyHex);

    // Backdate retirement to 48h before issuance — beyond the 24h tolerance.
    const retired = (await keyStore.get(key.key_id))!;
    const backdated = new Date(Date.parse(badge.payload.issued_at) - 48 * 60 * 60 * 1000);
    await keyStore.save({ ...retired, retired_at: backdated.toISOString() });

    expect(await service.verify(badge)).toEqual({ ok: false, reason: "issued_after_retirement" });
  });
});

describe("revocation on claim change (spec §3)", () => {
  it("editing a source field invalidates the badge via the lazy backstop, and auto-revokes it", async () => {
    const { service, signer, subjects, store } = await setup();
    const badge = await service.issue({ subject_id: "alice", claims: { name_verified: true } }, signer);

    subjects.set("alice", { ...subjects.get("alice")!, legal_name: "Alice Renamed" });

    // No on_claims_changed call — step 6 of verify catches it anyway.
    expect(await service.verify(badge)).toEqual({ ok: false, reason: "claims_changed" });
    expect((await store.get(badge.payload.badge_id))?.revoked_reason).toBe("claim_change");

    // Second verification hits the already-revoked record at step 5.
    expect(await service.verify(badge)).toEqual({
      ok: false,
      reason: "badge_revoked",
      revoked_reason: "claim_change",
    });
  });

  it("a derived-boolean change does NOT invalidate the badge (digest covers source values only)", async () => {
    const { service, signer, subjects } = await setup();
    const badge = await service.issue({ subject_id: "alice", claims: { name_verified: true } }, signer);

    subjects.set("alice", { ...subjects.get("alice")!, name_verified: false });

    expect((await service.verify(badge)).ok).toBe(true);
  });

  it("on_claims_changed eagerly revokes at write time, leaving other subjects untouched", async () => {
    const { service, signer, subjects } = await setup();
    const aliceBadge = await service.issue({ subject_id: "alice", claims: {} }, signer);
    const bobBadge = await service.issue({ subject_id: "bob", claims: {} }, signer);

    subjects.set("alice", { ...subjects.get("alice")!, dob: "1990-01-16" });
    const revoked = await service.onClaimsChanged("alice");

    expect(revoked).toHaveLength(1);
    expect(revoked[0]).toMatchObject({
      badge_id: aliceBadge.payload.badge_id,
      status: "revoked",
      revoked_reason: "claim_change",
    });
    expect(await service.verify(aliceBadge)).toEqual({
      ok: false,
      reason: "badge_revoked",
      revoked_reason: "claim_change",
    });
    expect((await service.verify(bobBadge)).ok).toBe(true);
  });

  it("on_claims_changed is a no-op when the digest still matches", async () => {
    const { service, signer } = await setup();
    await service.issue({ subject_id: "alice", claims: {} }, signer);
    expect(await service.onClaimsChanged("alice")).toEqual([]);
  });

  it("fails closed when source data disappears entirely", async () => {
    const { service, signer, subjects } = await setup();
    const badge = await service.issue({ subject_id: "alice", claims: {} }, signer);
    subjects.delete("alice");
    expect(await service.verify(badge)).toEqual({ ok: false, reason: "claims_changed" });
  });
});

describe("BadgeService.revokeBadge (manual, terminal)", () => {
  it("revokes with reason 'manual' and never un-revokes", async () => {
    const { service, signer } = await setup();
    const badge = await service.issue({ subject_id: "alice", claims: {} }, signer);

    await service.revokeBadge(badge.payload.badge_id);
    expect(await service.verify(badge)).toEqual({
      ok: false,
      reason: "badge_revoked",
      revoked_reason: "manual",
    });
    await expect(service.revokeBadge(badge.payload.badge_id)).rejects.toThrow(
      InvalidBadgeTransitionError,
    );
    await expect(service.revokeBadge("no-such-badge")).rejects.toThrow(UnknownBadgeError);
  });
});

describe("BadgeService.reissueAll (spec §1.4 — key-compromise remediation)", () => {
  it("reissues still-matching badges under the new key and skips changed claims", async () => {
    const { service, keys, key, signer, subjects, store } = await setup();
    const aliceBadge = await service.issue({ subject_id: "alice", claims: { name_verified: true } }, signer);
    const bobBadge = await service.issue({ subject_id: "bob", claims: { name_verified: true } }, signer);

    subjects.set("bob", { ...subjects.get("bob")!, legal_name: "Bob Renamed" });

    const replacement = makeKeypairSigner();
    const newKey = await keys.rotate(replacement.publicKeyHex);
    await keys.revoke(key.key_id);

    const { reissued, skipped } = await service.reissueAll(key.key_id, replacement.signer);

    expect(reissued).toHaveLength(1);
    expect(skipped).toEqual([{ badge_id: bobBadge.payload.badge_id, reason: "claims_changed" }]);

    const fresh = reissued[0]!;
    expect(fresh.payload.subject_id).toBe("alice");
    expect(fresh.payload.key_id).toBe(newKey.key_id);
    expect(fresh.payload.claims).toEqual(aliceBadge.payload.claims);
    expect(fresh.payload.claims_digest).toBe(aliceBadge.payload.claims_digest);
    expect(fresh.payload.badge_id).not.toBe(aliceBadge.payload.badge_id);
    expect(await service.verify(fresh)).toEqual({ ok: true, payload: fresh.payload });

    // The old badge is dead twice over: revoked key, and record revoked as key_compromise.
    expect(await service.verify(aliceBadge)).toEqual({ ok: false, reason: "key_revoked" });
    expect((await store.get(aliceBadge.payload.badge_id))?.revoked_reason).toBe("key_compromise");
  });
});
