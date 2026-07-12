/**
 * HMAC-SHA256 duplicate-document detection — spec §2, decision D5.
 *
 * The pepper is a deploying-app-supplied secret the library validates but never
 * generates, persists, or logs (D5). Every stored hash is stamped with the
 * pepper_id that produced it; lookups run against the current pepper and every
 * configured previous pepper (dual-pepper lookup), while writes always use the
 * current pepper only (single-pepper write). The plaintext document number exists
 * only inside checkDuplicate() and is never stored, logged, or returned (§2.3).
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { RecryptionError, type IsoTimestamp } from "./keys.js";

/** Spec §2.1: a versioned pepper. The secret comes from the app's secret store. */
export interface Pepper {
  pepper_id: string;
  secret: Uint8Array;
}

/** Spec §2.1 PepperConfig: one current pepper, any number of previous ones. */
export interface PepperConfig {
  current: Pepper;
  previous?: Pepper[];
}

/** Spec §2.2 DocumentHash record. doc_hmac is lowercase hex (spec §0). */
export interface DocumentHash {
  doc_hmac: string;
  pepper_id: string;
  subject_id: string;
  created_at: IsoTimestamp;
}

/**
 * Portable storage shape the deploying app maps onto its own database (spec §0).
 * `save` inserts or replaces by doc_hmac. `deleteByPepperId` returns the number
 * of rows removed (compromise rotation logs it, §2.4).
 */
export interface DocumentHashStore {
  findByHmac(docHmac: string): Promise<DocumentHash | undefined>;
  save(record: DocumentHash): Promise<void>;
  delete(docHmac: string): Promise<void>;
  deleteByPepperId(pepperId: string): Promise<number>;
  countByPepperId(pepperId: string): Promise<number>;
}

/** The fields that make up the normalized document identity (spec §2.2). */
export interface DocumentFields {
  document_type: string;
  issuing_country: string;
  document_number: string;
}

/** Spec §2.3 result shape. existing_subject_id is present only on a duplicate. */
export type DuplicateCheckResult =
  | { duplicate: true; existing_subject_id: string }
  | { duplicate: false };

export class InvalidPepperConfigError extends RecryptionError {}
export class InvalidDocumentError extends RecryptionError {}

/** Thrown when a destructive operation is called without its confirmation flag. */
export class DestructiveOperationNotConfirmedError extends RecryptionError {}

const MIN_PEPPER_BYTES = 32;
const MIN_ASCII_ONLY_PEPPER_BYTES = 48;

function isPrintableAsciiOnly(secret: Uint8Array): boolean {
  return secret.every((b) => b >= 0x20 && b <= 0x7e);
}

function validatePepper(pepper: Pepper, role: string): void {
  if (typeof pepper.pepper_id !== "string" || pepper.pepper_id.length === 0) {
    throw new InvalidPepperConfigError(`${role} pepper needs a non-empty pepper_id`);
  }
  const s = pepper.secret;
  if (!(s instanceof Uint8Array) || s.length < MIN_PEPPER_BYTES) {
    throw new InvalidPepperConfigError(
      `${role} pepper "${pepper.pepper_id}": secret must be at least ${MIN_PEPPER_BYTES} bytes (spec §2.1)`,
    );
  }
  if (s.every((b) => b === s[0])) {
    throw new InvalidPepperConfigError(
      `${role} pepper "${pepper.pepper_id}": secret is a repeated single byte — rejected as trivially weak (D5)`,
    );
  }
  if (s.length < MIN_ASCII_ONLY_PEPPER_BYTES && isPrintableAsciiOnly(s)) {
    throw new InvalidPepperConfigError(
      `${role} pepper "${pepper.pepper_id}": printable-ASCII-only secrets under ` +
        `${MIN_ASCII_ONLY_PEPPER_BYTES} bytes are rejected as likely human-chosen (spec §2.1); ` +
        `use random bytes from a CSPRNG`,
    );
  }
}

function secretsEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Spec §2.1 startup validation. Called by the detector constructor and both rotations. */
export function validatePepperConfig(config: PepperConfig): void {
  validatePepper(config.current, "current");
  const previous = config.previous ?? [];
  previous.forEach((p, i) => validatePepper(p, `previous[${i}]`));

  const ids = [config.current, ...previous].map((p) => p.pepper_id);
  if (new Set(ids).size !== ids.length) {
    throw new InvalidPepperConfigError(`pepper_ids must be unique, got: ${ids.join(", ")}`);
  }
  for (const p of previous) {
    if (secretsEqual(p.secret, config.current.secret)) {
      throw new InvalidPepperConfigError(
        `previous pepper "${p.pepper_id}" has the same secret as the current pepper`,
      );
    }
  }
}

/**
 * Spec §2.2 normalized document identity:
 * document_type ":" issuing_country ":" uppercase(strip_non_alphanumeric(document_number)).
 *
 * Type and country are case-folded (trim + lowercase) beyond the spec's literal
 * formula so that "US" vs "us" can't split one physical document into two
 * identities — serving §2.2's stated goal that the same document always produces
 * the same HMAC. ":" is rejected inside type/country because it delimits the
 * three segments of the preimage.
 */
export function normalizeDocumentIdentity(fields: DocumentFields): string {
  const type = fields.document_type.trim().toLowerCase();
  const country = fields.issuing_country.trim().toLowerCase();
  if (type.length === 0 || country.length === 0) {
    throw new InvalidDocumentError("document_type and issuing_country are required");
  }
  if (type.includes(":") || country.includes(":")) {
    throw new InvalidDocumentError(
      "document_type and issuing_country must not contain ':' (identity delimiter)",
    );
  }
  const number = fields.document_number.replace(/[^0-9a-zA-Z]/g, "").toUpperCase();
  if (number.length === 0) {
    throw new InvalidDocumentError("document_number contains no alphanumeric characters");
  }
  return `${type}:${country}:${number}`;
}

function hmacHex(secret: Uint8Array, normalizedIdentity: string): string {
  return createHmac("sha256", secret).update(normalizedIdentity, "utf8").digest("hex");
}

export interface PepperHealthWarning {
  code: "droppable_previous_pepper";
  pepper_id: string;
  message: string;
}

export class DuplicateDetector {
  private readonly config: PepperConfig;

  constructor(
    private readonly store: DocumentHashStore,
    config: PepperConfig,
  ) {
    validatePepperConfig(config);
    this.config = { current: config.current, previous: config.previous ?? [] };
  }

  /**
   * Spec §2.3 check-and-record. Dual-pepper lookup (current, then each previous),
   * single-pepper write. A same-subject match is a re-verification, not a
   * duplicate: its created_at is refreshed and, if it was stored under a previous
   * pepper, it is rewritten under the current one (the lazy migration that closes
   * rotation blind spots over time). On a true duplicate nothing is written.
   */
  async checkDuplicate(fields: DocumentFields, subjectId: string): Promise<DuplicateCheckResult> {
    const identity = normalizeDocumentIdentity(fields);
    const peppers = [this.config.current, ...(this.config.previous ?? [])];

    for (const pepper of peppers) {
      const hmac = hmacHex(pepper.secret, identity);
      const existing = await this.store.findByHmac(hmac);
      if (!existing) continue;

      if (existing.subject_id !== subjectId) {
        return { duplicate: true, existing_subject_id: existing.subject_id };
      }
      if (pepper.pepper_id !== this.config.current.pepper_id) {
        await this.store.delete(hmac);
      }
      await this.recordUnderCurrent(identity, subjectId);
      return { duplicate: false };
    }

    await this.recordUnderCurrent(identity, subjectId);
    return { duplicate: false };
  }

  private async recordUnderCurrent(identity: string, subjectId: string): Promise<void> {
    await this.store.save({
      doc_hmac: hmacHex(this.config.current.secret, identity),
      pepper_id: this.config.current.pepper_id,
      subject_id: subjectId,
      created_at: new Date().toISOString(),
    });
  }

  /**
   * Spec §1.5's pepper half, advisory only: a previous pepper with zero remaining
   * hashes is dead weight and can be dropped from config.
   */
  async health(): Promise<PepperHealthWarning[]> {
    const warnings: PepperHealthWarning[] = [];
    for (const pepper of this.config.previous ?? []) {
      if ((await this.store.countByPepperId(pepper.pepper_id)) === 0) {
        warnings.push({
          code: "droppable_previous_pepper",
          pepper_id: pepper.pepper_id,
          message: `previous pepper "${pepper.pepper_id}" has no remaining hashes and can be dropped from config`,
        });
      }
    }
    return warnings;
  }
}

/**
 * Spec §2.4 planned_rotation: push current into previous, install the new pepper
 * as current. Lossless (D5) — nothing is deleted; lookups now cost one extra HMAC
 * until the old pepper's hashes age out or migrate. Pure: returns the new config
 * for the app to persist in its own secret store and construct a new detector with.
 */
export function plannedRotation(config: PepperConfig, newPepper: Pepper): PepperConfig {
  const rotated: PepperConfig = {
    current: newPepper,
    previous: [config.current, ...(config.previous ?? [])],
  };
  validatePepperConfig(rotated);
  return rotated;
}

/** What compromise_rotation reports. Ids and counts only — never secrets (D5). */
export interface CompromiseRotationLog {
  event: "compromise_rotation";
  compromised_pepper_id: string;
  deleted_hashes: number;
  at: IsoTimestamp;
}

/**
 * Spec §2.4 compromise_rotation — the deliberately destructive path, kept separate
 * from plannedRotation so it can't be reached by accident: installs the new pepper
 * as current, DELETES every DocumentHash stored under the compromised pepper, and
 * refuses to keep the compromised secret anywhere in the resulting config. The
 * duplicate-detection blind spot this creates is accepted per D5 and closes lazily
 * as users re-verify.
 *
 * Requires confirmDestructive: true; logs what was deleted via `logger`
 * (default: console.warn as JSON).
 */
export async function compromiseRotation(params: {
  store: DocumentHashStore;
  config: PepperConfig;
  newPepper: Pepper;
  compromisedPepperId: string;
  confirmDestructive: boolean;
  logger?: (entry: CompromiseRotationLog) => void;
}): Promise<{ config: PepperConfig; deleted_hashes: number }> {
  const { store, config, newPepper, compromisedPepperId } = params;
  if (params.confirmDestructive !== true) {
    throw new DestructiveOperationNotConfirmedError(
      "compromiseRotation permanently deletes all hashes under the compromised pepper; " +
        "pass confirmDestructive: true to proceed (planned rotation is plannedRotation())",
    );
  }

  const all = [config.current, ...(config.previous ?? [])];
  const compromised = all.find((p) => p.pepper_id === compromisedPepperId);
  if (!compromised) {
    throw new InvalidPepperConfigError(`pepper "${compromisedPepperId}" is not in the config`);
  }
  if (secretsEqual(newPepper.secret, compromised.secret)) {
    throw new InvalidPepperConfigError(
      "the replacement pepper reuses the compromised secret — generate a fresh one",
    );
  }

  const survivors = all.filter((p) => p.pepper_id !== compromisedPepperId);
  const rotated: PepperConfig = { current: newPepper, previous: survivors };
  validatePepperConfig(rotated);

  const deleted = await store.deleteByPepperId(compromisedPepperId);
  const entry: CompromiseRotationLog = {
    event: "compromise_rotation",
    compromised_pepper_id: compromisedPepperId,
    deleted_hashes: deleted,
    at: new Date().toISOString(),
  };
  (params.logger ?? ((e) => console.warn(JSON.stringify(e))))(entry);

  return { config: rotated, deleted_hashes: deleted };
}
