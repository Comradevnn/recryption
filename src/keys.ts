/**
 * Key lifecycle for Ed25519 badge signing.
 *
 * Implements spec §1.1 (key record, invariants, rotation operations), the key-lookup
 * half of §1.4 (steps 2–3 and the step-7 freshness policy), and the advisory health
 * check of §1.5, per decision D3.
 *
 * The library never receives or holds a raw private key: signing happens through the
 * Signer callback so key material can live in a KMS/HSM (spec §1.1). This module
 * manages public keys and lifecycle status only.
 */
import { createHash } from "node:crypto";

/** UTC ISO-8601 timestamp string (spec §0). */
export type IsoTimestamp = string;

export type KeyStatus = "active" | "retired" | "revoked";

/**
 * Spec §1.1 SigningKey record. Binary values are lowercase hex (spec §0):
 * public_key is the 32-byte Ed25519 public key as 64 hex chars; key_id is the
 * first 16 bytes of SHA-256(public_key) as 32 hex chars (spec D3).
 */
export interface SigningKey {
  key_id: string;
  public_key: string;
  status: KeyStatus;
  created_at: IsoTimestamp;
  retired_at?: IsoTimestamp;
  revoked_at?: IsoTimestamp;
}

/**
 * Caller-supplied signing callback (spec §1.1): receives the exact bytes to sign,
 * returns the 64-byte Ed25519 signature. The private key stays on the caller's side.
 */
export type Signer = (message: Buffer) => Promise<Buffer>;

/**
 * Portable storage shape the deploying app maps onto its own database (spec §0).
 * `save` inserts or replaces by key_id.
 */
export interface KeyStore {
  get(keyId: string): Promise<SigningKey | undefined>;
  getActive(): Promise<SigningKey | undefined>;
  list(): Promise<SigningKey[]>;
  save(key: SigningKey): Promise<void>;
}

export class RecryptionError extends Error {}

/** Malformed key material or duplicate registration. */
export class InvalidKeyError extends RecryptionError {}

/** Attempted key-status change outside the legal one-way transitions (spec §1.1). */
export class InvalidKeyTransitionError extends RecryptionError {}

/** The "exactly one active key" invariant does not hold after a mutation (spec §1.1). */
export class ActiveKeyInvariantError extends RecryptionError {}

/** Spec §1.4 step 7: default tolerance for badges issued shortly after their key retired. */
export const DEFAULT_RETIREMENT_TOLERANCE_MS = 24 * 60 * 60 * 1000;

/** Spec §1.5 / D3: advisory maximum active-key age before health() warns. */
export const DEFAULT_MAX_KEY_AGE_MS = 2 * 365 * 24 * 60 * 60 * 1000;

function parsePublicKeyHex(publicKeyHex: string): Buffer {
  if (!/^[0-9a-fA-F]{64}$/.test(publicKeyHex)) {
    throw new InvalidKeyError("public_key must be 64 hex chars (32-byte Ed25519 public key)");
  }
  return Buffer.from(publicKeyHex.toLowerCase(), "hex");
}

/**
 * Spec D3 key_id format: lowercase hex SHA-256 of the public key, truncated to
 * 16 bytes (32 hex chars). Deriving the id from the key material makes it
 * self-verifying: a verifier can confirm a fetched key matches the id a badge names.
 */
export function deriveKeyId(publicKeyHex: string): string {
  return createHash("sha256").update(parsePublicKeyHex(publicKeyHex)).digest("hex").slice(0, 32);
}

export type KeyLookupFailure = "unknown_key" | "key_revoked" | "key_id_mismatch";

export type KeyLookupResult =
  | { ok: true; key: SigningKey }
  | { ok: false; reason: KeyLookupFailure };

/**
 * Spec §1.4 step 7 freshness policy. Small issuance/rotation overlaps are expected
 * in multi-instance deployments and MUST pass (spec D3); only issuance beyond the
 * tolerance after retirement fails. Pass toleranceMs: null to disable the check.
 */
export function issuedAfterRetirement(
  key: SigningKey,
  issuedAt: IsoTimestamp,
  toleranceMs: number | null = DEFAULT_RETIREMENT_TOLERANCE_MS,
): boolean {
  if (toleranceMs === null || key.retired_at === undefined) return false;
  return Date.parse(issuedAt) > Date.parse(key.retired_at) + toleranceMs;
}

export interface KeyHealthWarning {
  code: "active_key_over_max_age" | "multiple_active_keys" | "no_active_key";
  key_id?: string;
  message: string;
}

export interface KeyManagerOptions {
  /** Advisory threshold for health() (spec §1.5). Default 2 years. */
  maxKeyAgeMs?: number;
}

export class KeyManager {
  private readonly maxKeyAgeMs: number;

  constructor(
    private readonly store: KeyStore,
    options: KeyManagerOptions = {},
  ) {
    this.maxKeyAgeMs = options.maxKeyAgeMs ?? DEFAULT_MAX_KEY_AGE_MS;
  }

  /**
   * Spec §1.1 rotate(): register the app-supplied new public key as active and
   * retire the previous active key. With no current active key (first install, or
   * after the active key was revoked in a compromise response) it installs the new
   * key without retiring anything.
   *
   * The spec calls for these writes to happen "in one transaction"; with a pluggable
   * KeyStore the library can only sequence them and re-check the invariant afterwards
   * — back the store with a transactional database and wrap this call if concurrent
   * rotation is possible in your deployment.
   */
  async rotate(newPublicKeyHex: string): Promise<SigningKey> {
    const publicKey = parsePublicKeyHex(newPublicKeyHex).toString("hex");
    const keyId = deriveKeyId(publicKey);
    if (await this.store.get(keyId)) {
      throw new InvalidKeyError(`key ${keyId} is already registered`);
    }
    const now = new Date().toISOString();
    const previous = await this.store.getActive();
    if (previous) {
      await this.store.save({ ...previous, status: "retired", retired_at: now });
    }
    const key: SigningKey = {
      key_id: keyId,
      public_key: publicKey,
      status: "active",
      created_at: now,
    };
    await this.store.save(key);
    const active = (await this.store.list()).filter((k) => k.status === "active");
    if (active.length !== 1) {
      throw new ActiveKeyInvariantError(
        `expected exactly 1 active key after rotation, found ${active.length}`,
      );
    }
    return key;
  }

  /**
   * Spec §1.1 revoke(): {active, retired} → revoked, one-way. Takes effect on the
   * next verification — which, per D4, is every verification; no grace period (D3).
   * Revoking the active key leaves no active key until rotate() installs a new one;
   * issuance fails in that window, which is the intended compromise-response state.
   */
  async revoke(keyId: string): Promise<SigningKey> {
    const key = await this.store.get(keyId);
    if (!key) throw new InvalidKeyError(`unknown key ${keyId}`);
    if (key.status === "revoked") {
      throw new InvalidKeyTransitionError(`key ${keyId} is already revoked`);
    }
    const revoked: SigningKey = {
      ...key,
      status: "revoked",
      revoked_at: new Date().toISOString(),
    };
    await this.store.save(revoked);
    return revoked;
  }

  /** The active signing key for new issuance, if one exists. */
  async getActiveKey(): Promise<SigningKey | undefined> {
    return this.store.getActive();
  }

  /**
   * Spec §1.4 steps 2–3: the key-lookup half of badge verification. Retired keys
   * still verify old badges; revoked keys fail immediately; the stored key material
   * must match the key_id it claims to identify.
   */
  async lookupForVerification(keyId: string): Promise<KeyLookupResult> {
    const key = await this.store.get(keyId);
    if (!key) return { ok: false, reason: "unknown_key" };
    if (key.status === "revoked") return { ok: false, reason: "key_revoked" };
    if (deriveKeyId(key.public_key) !== key.key_id) {
      return { ok: false, reason: "key_id_mismatch" };
    }
    return { ok: true, key };
  }

  /** Spec §1.5 advisory health check — warnings only, never blocks issuance. */
  async health(now: Date = new Date()): Promise<KeyHealthWarning[]> {
    const warnings: KeyHealthWarning[] = [];
    const active = (await this.store.list()).filter((k) => k.status === "active");
    if (active.length === 0) {
      warnings.push({
        code: "no_active_key",
        message: "no active key: issuance will fail until rotate() installs one",
      });
    } else if (active.length > 1) {
      warnings.push({
        code: "multiple_active_keys",
        message: `invariant breach: ${active.length} active keys (expected exactly 1)`,
      });
    }
    for (const key of active) {
      if (now.getTime() - Date.parse(key.created_at) > this.maxKeyAgeMs) {
        warnings.push({
          code: "active_key_over_max_age",
          key_id: key.key_id,
          message: `active key ${key.key_id} exceeds the configured maximum age; consider planned rotation`,
        });
      }
    }
    return warnings;
  }
}
