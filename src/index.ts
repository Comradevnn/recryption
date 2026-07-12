/**
 * Recryption — reusable identity-verification primitives.
 * Design: spec/identity-verification-protocol.md (decisions D1–D5).
 *
 * Explicit named exports only: everything listed here is public API,
 * everything else is internal.
 */

// Ed25519 key lifecycle (spec §1.1, §1.4 steps 2–3 + 7, §1.5)
export {
  ActiveKeyInvariantError,
  DEFAULT_MAX_KEY_AGE_MS,
  DEFAULT_RETIREMENT_TOLERANCE_MS,
  InvalidKeyError,
  InvalidKeyTransitionError,
  KeyManager,
  RecryptionError,
  deriveKeyId,
  issuedAfterRetirement,
  type IsoTimestamp,
  type KeyHealthWarning,
  type KeyLookupFailure,
  type KeyLookupResult,
  type KeyManagerOptions,
  type KeyStatus,
  type KeyStore,
  type Signer,
  type SigningKey,
} from "./keys.js";

// Badge issuance, verification, revocation-on-claim-change (spec §1.2–1.4, §3)
export {
  BadgeService,
  CanonicalizationError,
  InvalidBadgeTransitionError,
  MissingSourceFieldError,
  NoActiveKeyError,
  SignerMismatchError,
  UnknownBadgeError,
  canonicalJson,
  canonicalPayloadBytes,
  type BadgePayload,
  type BadgeRecord,
  type BadgeServiceOptions,
  type BadgeStatus,
  type BadgeStore,
  type JsonValue,
  type RevokedReason,
  type SignedBadge,
  type VerifyFailureReason,
  type VerifyResult,
} from "./badge.js";

// HMAC-SHA256 duplicate-document detection (spec §2, D5)
export {
  DestructiveOperationNotConfirmedError,
  DuplicateDetector,
  InvalidDocumentError,
  InvalidPepperConfigError,
  compromiseRotation,
  normalizeDocumentIdentity,
  plannedRotation,
  validatePepperConfig,
  type CompromiseRotationLog,
  type DocumentFields,
  type DocumentHash,
  type DocumentHashStore,
  type DuplicateCheckResult,
  type Pepper,
  type PepperConfig,
  type PepperHealthWarning,
} from "./duplicateDetection.js";
