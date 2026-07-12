import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_RETIREMENT_TOLERANCE_MS,
  InvalidKeyError,
  InvalidKeyTransitionError,
  KeyManager,
  deriveKeyId,
  issuedAfterRetirement,
  type SigningKey,
} from "../src/keys.js";
import { InMemoryKeyStore } from "./helpers.js";

const newPublicKey = () => randomBytes(32).toString("hex");

describe("deriveKeyId", () => {
  it("is the first 16 bytes of SHA-256(public_key), lowercase hex (spec D3)", () => {
    const pub = "ab".repeat(32);
    const expected = createHash("sha256")
      .update(Buffer.from(pub, "hex"))
      .digest("hex")
      .slice(0, 32);
    expect(deriveKeyId(pub)).toBe(expected);
    expect(deriveKeyId(pub)).toMatch(/^[0-9a-f]{32}$/);
  });

  it("normalizes hex case", () => {
    const pub = newPublicKey();
    expect(deriveKeyId(pub.toUpperCase())).toBe(deriveKeyId(pub));
  });

  it("rejects malformed key material", () => {
    expect(() => deriveKeyId("abcd")).toThrow(InvalidKeyError);
  });
});

describe("KeyManager.rotate", () => {
  it("installs the first key as active", async () => {
    const manager = new KeyManager(new InMemoryKeyStore());
    const key = await manager.rotate(newPublicKey());
    expect(key.status).toBe("active");
    expect(key.key_id).toBe(deriveKeyId(key.public_key));
  });

  it("retires the previous active key and keeps exactly one active", async () => {
    const store = new InMemoryKeyStore();
    const manager = new KeyManager(store);
    const first = await manager.rotate(newPublicKey());
    const second = await manager.rotate(newPublicKey());

    const retired = await store.get(first.key_id);
    expect(retired?.status).toBe("retired");
    expect(retired?.retired_at).toBeDefined();

    const active = (await store.list()).filter((k) => k.status === "active");
    expect(active).toHaveLength(1);
    expect(active[0]!.key_id).toBe(second.key_id);
  });

  it("rejects re-registering an already-known key", async () => {
    const manager = new KeyManager(new InMemoryKeyStore());
    const pub = newPublicKey();
    await manager.rotate(pub);
    await expect(manager.rotate(pub)).rejects.toThrow(InvalidKeyError);
  });
});

describe("KeyManager.revoke", () => {
  it("revokes a retired key without clearing retired_at (transitions never clear *_at)", async () => {
    const store = new InMemoryKeyStore();
    const manager = new KeyManager(store);
    const first = await manager.rotate(newPublicKey());
    await manager.rotate(newPublicKey());

    const revoked = await manager.revoke(first.key_id);
    expect(revoked.status).toBe("revoked");
    expect(revoked.revoked_at).toBeDefined();
    expect(revoked.retired_at).toBeDefined();
  });

  it("revoking the active key leaves no active key until the next rotate()", async () => {
    const manager = new KeyManager(new InMemoryKeyStore());
    const key = await manager.rotate(newPublicKey());
    await manager.revoke(key.key_id);
    expect(await manager.getActiveKey()).toBeUndefined();

    const replacement = await manager.rotate(newPublicKey());
    expect(replacement.status).toBe("active");
  });

  it("is one-way: revoking a revoked key is an illegal transition", async () => {
    const manager = new KeyManager(new InMemoryKeyStore());
    const key = await manager.rotate(newPublicKey());
    await manager.revoke(key.key_id);
    await expect(manager.revoke(key.key_id)).rejects.toThrow(InvalidKeyTransitionError);
  });

  it("rejects unknown keys", async () => {
    const manager = new KeyManager(new InMemoryKeyStore());
    await expect(manager.revoke("0".repeat(32))).rejects.toThrow(InvalidKeyError);
  });
});

describe("KeyManager.lookupForVerification (spec §1.4 steps 2–3)", () => {
  it("fails unknown keys", async () => {
    const manager = new KeyManager(new InMemoryKeyStore());
    expect(await manager.lookupForVerification("0".repeat(32))).toEqual({
      ok: false,
      reason: "unknown_key",
    });
  });

  it("passes retired keys — old badges still verify after planned rotation", async () => {
    const manager = new KeyManager(new InMemoryKeyStore());
    const first = await manager.rotate(newPublicKey());
    await manager.rotate(newPublicKey());

    const result = await manager.lookupForVerification(first.key_id);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.key.status).toBe("retired");
  });

  it("fails revoked keys immediately — no grace period", async () => {
    const manager = new KeyManager(new InMemoryKeyStore());
    const key = await manager.rotate(newPublicKey());
    await manager.revoke(key.key_id);

    expect(await manager.lookupForVerification(key.key_id)).toEqual({
      ok: false,
      reason: "key_revoked",
    });
  });

  it("fails when stored key material does not match its key_id", async () => {
    const store = new InMemoryKeyStore();
    const manager = new KeyManager(store);
    const key = await manager.rotate(newPublicKey());
    await store.save({ ...key, public_key: newPublicKey() });

    expect(await manager.lookupForVerification(key.key_id)).toEqual({
      ok: false,
      reason: "key_id_mismatch",
    });
  });
});

describe("issuedAfterRetirement (spec §1.4 step 7)", () => {
  const retiredAt = "2026-07-01T00:00:00.000Z";
  const key: SigningKey = {
    key_id: "0".repeat(32),
    public_key: "0".repeat(64),
    status: "retired",
    created_at: "2025-01-01T00:00:00.000Z",
    retired_at: retiredAt,
  };
  const hoursAfter = (h: number) =>
    new Date(Date.parse(retiredAt) + h * 60 * 60 * 1000).toISOString();

  it("passes small rotation overlaps (multi-instance deployments MUST NOT fail these)", () => {
    expect(issuedAfterRetirement(key, hoursAfter(1))).toBe(false);
    expect(issuedAfterRetirement(key, hoursAfter(23))).toBe(false);
  });

  it("fails issuance beyond the default 24h tolerance", () => {
    expect(issuedAfterRetirement(key, hoursAfter(25))).toBe(true);
  });

  it("respects a custom tolerance and can be disabled with null", () => {
    expect(issuedAfterRetirement(key, hoursAfter(2), 60 * 60 * 1000)).toBe(true);
    expect(issuedAfterRetirement(key, hoursAfter(1000), null)).toBe(false);
  });

  it("never fails keys that are not retired", () => {
    const active = { ...key, status: "active" as const, retired_at: undefined };
    expect(issuedAfterRetirement(active, hoursAfter(1000))).toBe(false);
  });

  it("default tolerance is 24 hours", () => {
    expect(DEFAULT_RETIREMENT_TOLERANCE_MS).toBe(24 * 60 * 60 * 1000);
  });
});

describe("KeyManager.health (spec §1.5 — advisory only)", () => {
  it("warns when the active key exceeds the max age, without blocking anything", async () => {
    const store = new InMemoryKeyStore();
    const manager = new KeyManager(store);
    const key = await manager.rotate(newPublicKey());
    await store.save({ ...key, created_at: "2023-01-01T00:00:00.000Z" });

    const warnings = await manager.health(new Date("2026-07-12T00:00:00.000Z"));
    expect(warnings).toEqual([
      expect.objectContaining({ code: "active_key_over_max_age", key_id: key.key_id }),
    ]);
  });

  it("is quiet for a healthy young key", async () => {
    const manager = new KeyManager(new InMemoryKeyStore());
    await manager.rotate(newPublicKey());
    expect(await manager.health()).toEqual([]);
  });

  it("warns on zero active keys (post-compromise window)", async () => {
    const manager = new KeyManager(new InMemoryKeyStore());
    const key = await manager.rotate(newPublicKey());
    await manager.revoke(key.key_id);

    const warnings = await manager.health();
    expect(warnings).toEqual([expect.objectContaining({ code: "no_active_key" })]);
  });

  it("flags an invariant breach if the store somehow holds two active keys", async () => {
    const store = new InMemoryKeyStore();
    const manager = new KeyManager(store);
    const key = await manager.rotate(newPublicKey());
    const rogue = { ...key, key_id: "f".repeat(32), public_key: newPublicKey() };
    await store.save(rogue);

    const warnings = await manager.health();
    expect(warnings).toEqual([expect.objectContaining({ code: "multiple_active_keys" })]);
  });
});
