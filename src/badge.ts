/**
 * Ed25519 badge issuance & verification, and revocation-on-claim-change —
 * spec §1.2 (payload), §1.3 (badge record), §1.4 (verification order,
 * reissue_all), §3 (claims digest, eager + lazy enforcement).
 */
import * as ed from "@noble/ed25519";
import { createHash, randomUUID } from "node:crypto";
import {
  DEFAULT_RETIREMENT_TOLERANCE_MS,
  RecryptionError,
  issuedAfterRetirement,
  type IsoTimestamp,
  type KeyManager,
  type Signer,
} from "./keys.js";

// @noble/ed25519 v2 needs a SHA-512 implementation wired in for its sync API.
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...messages) => {
    const hash = createHash("sha512");
    for (const message of messages) hash.update(message);
    return new Uint8Array(hash.digest());
  };
}

export type JsonValue = null | boolean | string | number | JsonValue[] | { [key: string]: JsonValue };

export class CanonicalizationError extends RecryptionError {}
export class NoActiveKeyError extends RecryptionError {}
export class SignerMismatchError extends RecryptionError {}
export class MissingSourceFieldError extends RecryptionError {}
export class UnknownBadgeError extends RecryptionError {}
export class InvalidBadgeTransitionError extends RecryptionError {}

/**
 * Spec §1.2 canonical JSON: keys sorted (recursively), no insignificant
 * whitespace, numbers as integers only. The verifier must re-derive the exact
 * signed bytes, so this is the single source of truth for both sides.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isSafeInteger(value)) {
        throw new CanonicalizationError(`numbers must be integers (spec §1.2), got ${value}`);
      }
      return String(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
      const record = value as Record<string, unknown>;
      const parts = Object.keys(record)
        .sort()
        .map((key) => {
          if (record[key] === undefined) {
            throw new CanonicalizationError(`undefined is not representable (key "${key}")`);
          }
          return `${JSON.stringify(key)}:${canonicalJson(record[key])}`;
        });
      return `{${parts.join(",")}}`;
    }
    default:
      throw new CanonicalizationError(`unsupported type: ${typeof value}`);
  }
}

/** Spec §1.2 BadgePayload — the exact bytes that get signed, as canonical JSON. */
export interface BadgePayload {
  v: 1;
  badge_id: string;
  subject_id: string;
  claims: Record<string, JsonValue>;
  claims_digest: string;
  verification_method: "manual"; // fixed in this version (D2)
  key_id: string;
  issued_at: IsoTimestamp;
}

/** The stored/transported badge: payload plus its Ed25519 signature as hex (spec §0, §1.2). */
export interface SignedBadge {
  payload: BadgePayload;
  sig: string;
}

export type BadgeStatus = "valid" | "revoked";
export type RevokedReason = "claim_change" | "manual" | "key_compromise";

/** Spec §1.3 Badge record — the server-side, pull-checked half (D4). */
export interface BadgeRecord {
  badge_id: string;
  subject_id: string;
  key_id: string;
  claims_digest: string;
  status: BadgeStatus;
  revoked_reason: RevokedReason | null;
  issued_at: IsoTimestamp;
  revoked_at?: IsoTimestamp;
}

/**
 * Portable storage shape the deploying app maps onto its own database (spec §0).
 * `save` inserts or replaces by badge_id; the listValid* methods return only
 * status "valid" records.
 *
 * The signed-badge archive (saveSigned/getSigned) goes beyond the spec's §1.3
 * record: reissue_all needs each badge's original claims, which live only in
 * the signed payload — see the flagged note in the module summary.
 */
export interface BadgeStore {
  get(badgeId: string): Promise<BadgeRecord | undefined>;
  save(record: BadgeRecord): Promise<void>;
  saveSigned(badge: SignedBadge): Promise<void>;
  getSigned(badgeId: string): Promise<SignedBadge | undefined>;
  listValidBySubject(subjectId: string): Promise<BadgeRecord[]>;
  listValidByKey(keyId: string): Promise<BadgeRecord[]>;
}

export type VerifyFailureReason =
  | "unsupported_version"
  | "unknown_key"
  | "key_revoked"
  | "key_id_mismatch"
  | "bad_signature"
  | "unknown_badge"
  | "badge_revoked"
  | "claims_changed"
  | "issued_after_retirement";

export type VerifyResult =
  | { ok: true; payload: BadgePayload }
  | { ok: false; reason: VerifyFailureReason; revoked_reason?: RevokedReason };

export interface BadgeServiceOptions {
  /**
   * Spec §3.1: the registered list of source-field names the claims digest
   * covers — the underlying verified values (legal name, DOB, …), never the
   * derived booleans, since "name_verified: true" doesn't change when the
   * name itself does.
   */
  sourceFields: string[];
  /**
   * Returns the subject's *current* source values from the app's own user
   * store. May return extra fields (ignored) or omit fields (treated as a
   * claims change — fail closed).
   */
  resolveSourceFields: (subjectId: string) => Promise<Record<string, JsonValue | undefined>>;
  /** Spec §1.4 step 7 tolerance; null disables the check. Default 24h. */
  retirementToleranceMs?: number | null;
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function hexToBytes(hex: string): Uint8Array | undefined {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return undefined;
  return new Uint8Array(Buffer.from(hex, "hex"));
}

export function canonicalPayloadBytes(payload: BadgePayload): Buffer {
  return Buffer.from(canonicalJson(payload), "utf8");
}

export class BadgeService {
  private readonly sourceFields: string[];
  private readonly resolveSourceFields: BadgeServiceOptions["resolveSourceFields"];
  private readonly retirementToleranceMs: number | null;

  constructor(
    private readonly badgeStore: BadgeStore,
    private readonly keyManager: KeyManager,
    options: BadgeServiceOptions,
  ) {
    if (options.sourceFields.length === 0) {
      throw new MissingSourceFieldError("at least one source field must be registered (spec §3.1)");
    }
    this.sourceFields = [...options.sourceFields];
    this.resolveSourceFields = options.resolveSourceFields;
    this.retirementToleranceMs =
      options.retirementToleranceMs === undefined
        ? DEFAULT_RETIREMENT_TOLERANCE_MS
        : options.retirementToleranceMs;
  }

  /**
   * Spec §3.1: SHA-256 over the canonical JSON of {field: current_value} for
   * exactly the registered source fields. Throws if a field is missing —
   * issuance must not proceed on incomplete source data.
   */
  async computeClaimsDigest(subjectId: string): Promise<string> {
    const values = await this.resolveSourceFields(subjectId);
    const picked: Record<string, JsonValue> = {};
    for (const field of this.sourceFields) {
      const value = values[field];
      if (value === undefined) {
        throw new MissingSourceFieldError(`source field "${field}" missing for subject ${subjectId}`);
      }
      picked[field] = value;
    }
    return sha256Hex(canonicalJson(picked));
  }

  /** Missing source data reads as "claims changed" (fail closed) instead of throwing. */
  private async tryComputeClaimsDigest(subjectId: string): Promise<string | undefined> {
    try {
      return await this.computeClaimsDigest(subjectId);
    } catch (error) {
      if (error instanceof MissingSourceFieldError) return undefined;
      throw error;
    }
  }

  /**
   * Spec §1.2 issuance: builds the payload, signs it via the caller-supplied
   * Signer (the private key never enters the library), and stores the §1.3
   * record plus the signed badge. The returned signature is checked against
   * the active key before anything is stored, so a mis-wired signer callback
   * fails here instead of minting badges that can never verify.
   */
  async issue(
    params: { subject_id: string; claims: Record<string, JsonValue> },
    signer: Signer,
  ): Promise<SignedBadge> {
    const activeKey = await this.keyManager.getActiveKey();
    if (!activeKey) {
      throw new NoActiveKeyError("no active signing key: run rotate() first (spec §1.1)");
    }
    const payload: BadgePayload = {
      v: 1,
      badge_id: randomUUID(),
      subject_id: params.subject_id,
      claims: params.claims,
      claims_digest: await this.computeClaimsDigest(params.subject_id),
      verification_method: "manual",
      key_id: activeKey.key_id,
      issued_at: new Date().toISOString(),
    };
    const bytes = canonicalPayloadBytes(payload);
    const sig = new Uint8Array(await signer(bytes));
    if (!ed.verify(sig, new Uint8Array(bytes), hexToBytes(activeKey.public_key)!)) {
      throw new SignerMismatchError(
        `signer did not produce a valid signature for the active key ${activeKey.key_id}`,
      );
    }
    const signed: SignedBadge = { payload, sig: Buffer.from(sig).toString("hex") };
    await this.badgeStore.save({
      badge_id: payload.badge_id,
      subject_id: payload.subject_id,
      key_id: payload.key_id,
      claims_digest: payload.claims_digest,
      status: "valid",
      revoked_reason: null,
      issued_at: payload.issued_at,
    });
    await this.badgeStore.saveSigned(signed);
    return signed;
  }

  /**
   * Spec §1.4 verification, in the spec's exact order. Signature validity alone
   * is never a pass: steps 5–6 are the pull-based half (D4), and step 6 is the
   * lazy claims-change backstop that auto-revokes on mismatch (§3.2).
   */
  async verify(badge: SignedBadge): Promise<VerifyResult> {
    const { payload } = badge;

    // 1. Version.
    if (payload.v !== 1) return { ok: false, reason: "unsupported_version" };

    // 2–3. Key lookup: revoked fails immediately, retired still verifies (D3).
    const keyLookup = await this.keyManager.lookupForVerification(payload.key_id);
    if (!keyLookup.ok) return { ok: false, reason: keyLookup.reason };
    const key = keyLookup.key;

    // 4. Ed25519 signature over the canonical payload bytes.
    let signatureValid = false;
    try {
      const sig = hexToBytes(badge.sig);
      const pub = hexToBytes(key.public_key);
      signatureValid =
        sig !== undefined &&
        pub !== undefined &&
        ed.verify(sig, new Uint8Array(canonicalPayloadBytes(payload)), pub);
    } catch {
      signatureValid = false;
    }
    if (!signatureValid) return { ok: false, reason: "bad_signature" };

    // 5. Badge record — the pull check (D4).
    const record = await this.badgeStore.get(payload.badge_id);
    if (!record) return { ok: false, reason: "unknown_badge" };
    if (record.status === "revoked") {
      return { ok: false, reason: "badge_revoked", revoked_reason: record.revoked_reason ?? undefined };
    }

    // 6. Claim-change backstop (§3.2): recompute against current source values.
    const currentDigest = await this.tryComputeClaimsDigest(payload.subject_id);
    if (currentDigest !== payload.claims_digest) {
      await this.revokeRecord(record, "claim_change");
      return { ok: false, reason: "claims_changed" };
    }

    // 7. Optional freshness policy (default 24h tolerance; null disables).
    if (issuedAfterRetirement(key, payload.issued_at, this.retirementToleranceMs)) {
      return { ok: false, reason: "issued_after_retirement" };
    }

    // 8. ok.
    return { ok: true, payload };
  }

  /**
   * Spec §3.2 eager path: call from the app's profile-update flow. Recomputes
   * the digest and immediately revokes every valid badge it no longer matches,
   * so revocation lands at write time instead of first-use time. Returns the
   * badges it revoked.
   */
  async onClaimsChanged(subjectId: string): Promise<BadgeRecord[]> {
    const currentDigest = await this.tryComputeClaimsDigest(subjectId);
    const revoked: BadgeRecord[] = [];
    for (const record of await this.badgeStore.listValidBySubject(subjectId)) {
      if (record.claims_digest !== currentDigest) {
        revoked.push(await this.revokeRecord(record, "claim_change"));
      }
    }
    return revoked;
  }

  /**
   * Manual revocation (spec §1.3's "manual" reason). One-way and terminal —
   * a badge is never un-revoked; re-verification issues a new badge (§3.2).
   */
  async revokeBadge(badgeId: string): Promise<BadgeRecord> {
    const record = await this.badgeStore.get(badgeId);
    if (!record) throw new UnknownBadgeError(`unknown badge ${badgeId}`);
    if (record.status === "revoked") {
      throw new InvalidBadgeTransitionError(`badge ${badgeId} is already revoked`);
    }
    return this.revokeRecord(record, "manual");
  }

  /**
   * Spec §1.4 bulk re-issuance — the D3 remediation for key compromise. For
   * every still-valid badge under the given key whose claims digest still
   * matches, issues a fresh badge under the current active key and revokes the
   * old record with reason "key_compromise". Badges whose claims changed (or
   * whose signed payload is no longer archived) are skipped and reported.
   * Rotate a new active key in before calling this.
   */
  async reissueAll(
    keyId: string,
    signer: Signer,
  ): Promise<{
    reissued: SignedBadge[];
    skipped: { badge_id: string; reason: "claims_changed" | "missing_signed_badge" }[];
  }> {
    const reissued: SignedBadge[] = [];
    const skipped: { badge_id: string; reason: "claims_changed" | "missing_signed_badge" }[] = [];
    for (const record of await this.badgeStore.listValidByKey(keyId)) {
      const signed = await this.badgeStore.getSigned(record.badge_id);
      if (!signed) {
        skipped.push({ badge_id: record.badge_id, reason: "missing_signed_badge" });
        continue;
      }
      const currentDigest = await this.tryComputeClaimsDigest(record.subject_id);
      if (currentDigest !== record.claims_digest) {
        skipped.push({ badge_id: record.badge_id, reason: "claims_changed" });
        continue;
      }
      const fresh = await this.issue(
        { subject_id: record.subject_id, claims: signed.payload.claims },
        signer,
      );
      await this.revokeRecord(record, "key_compromise");
      reissued.push(fresh);
    }
    return { reissued, skipped };
  }

  private async revokeRecord(record: BadgeRecord, reason: RevokedReason): Promise<BadgeRecord> {
    const revoked: BadgeRecord = {
      ...record,
      status: "revoked",
      revoked_reason: reason,
      revoked_at: new Date().toISOString(),
    };
    await this.badgeStore.save(revoked);
    return revoked;
  }
}
