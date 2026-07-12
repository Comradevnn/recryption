# Recryption — Identity Verification Primitives Spec

Recryption extracts the reusable verification primitives from the "In Good Company" identity-verification design (see `identity-verification-encryption-spec.md`, kept unmodified alongside this document) into a standalone library other applications can depend on. This spec covers exactly three primitives:

1. **Ed25519 badge issuance and verification** — a deploying app signs a minimal claims payload; anyone holding the app's public key can verify it.
2. **HMAC-SHA256 duplicate-document detection** — "has this document already verified a different account?" answered without storing or revealing the document number.
3. **Revocation-on-claim-change** — a badge automatically stops verifying if the underlying verified fields it attests to are later changed.

Everything else in the original spec — capture pipeline, OCR/SDK choices, face-match, device-binding with P-256 hardware keys, envelope encryption of the retained package, event tickets — is application-level and stays out of Recryption. The original spec remains the reference for how a full app composes these primitives with those concerns.

---

## Decisions log

### D1 — RESOLVED: Recryption is a library, not a protocol.

Recryption v1 is a dependency a single deploying app embeds in its own backend. Badges issued by app A are not designed to verify against app B; there is no shared trust registry, no cross-platform badge format negotiation, no federation. Every design choice below assumes one issuer whose verifiers all trust that issuer's own published keys. **Future direction (not designed here):** a later phase may define a cross-platform interchange profile — a stable wire format, a key-discovery convention, and semantics for third-party verifiers — at which point the payload schema in §2 becomes a compatibility surface rather than an internal detail. Nothing in this version should be published as if it were that standard.

### D2 — RESOLVED: manual-entry verification only.

Matching the original app's scope decision, the verified fields a badge attests to come from the deploying app's own verification flow, which in this version means human/manual entry and comparison — Recryption receives "these fields were verified" as an input and takes no position on how the app established that. ML-based visual document authentication and specialized OCR are explicitly out of scope. **Future direction (not designed here):** a later phase may add a `verification_method` claim with defined values for automated pipelines, so relying parties can distinguish manual from ML-assisted verification; the payload reserves the field name but this version always writes `"manual"`.

### D3 — RESOLVED (decided upstream, concretized here): per-app Ed25519 keypairs with `key_id` + `active`/`retired`/`revoked` lifecycle.

Each deploying app owns its own Ed25519 keypair(s). Exactly one key is `active` at a time and is used for all new signing. Every badge embeds the `key_id` it was signed with. Planned rotation marks the old key `retired` — still trusted when verifying badges signed under it. Compromise response marks the key `revoked` — every badge signed under it fails verification immediately, with no grace period. Concrete data shape and lookup logic are in §1; the legal status transitions are `active → retired` and `{active, retired} → revoked`, and both are one-way (a revoked or retired key never returns to active — a new key is generated instead).

**Flagged concerns with this design for a general-purpose library** (recorded here rather than silently patched, since the model was decided upstream):

- **Revoking a key strands every honest badge signed under it.** For a single app that's an acceptable emergency cost; for a library it needs a supported answer, or every deploying app will improvise one. Recryption therefore ships a bulk re-issuance helper (§1.4): iterate badges by `key_id`, re-sign each still-valid badge's payload under the current active key. This is remediation tooling, not a grace period — verification under the revoked key still fails from the moment of revocation.
- **"Only one active key" has a deployment race.** In a multi-instance backend, the instant of rotation can have some instances signing under the old key. This is harmless *only because* retired keys still verify — the design is safe, but the spec must say so explicitly so implementers don't "fix" it by rejecting retired-key badges signed seconds after rotation. Badge issuance therefore records `issued_at`, and an app MAY optionally reject badges whose `issued_at` postdates their signing key's `retired_at` by more than a tolerance window (default: reject if > 24h after, to catch a stolen-but-only-retired key being quietly used) — but MUST NOT reject on small overlaps.
- **The upstream design says nothing about private-key storage.** Recryption never persists private key material itself: the library's signing interface accepts a signer callback, so the key can live in a KMS/HSM and the library only ever sees signatures. Storing the private key in the app database is explicitly unsupported.
- **No maximum key age.** The upstream design rotates only when someone decides to. The library adds a non-enforcing nudge: `key.created_at` is required, and the verification-side health check (§1.5) warns when the active key exceeds a configurable age (default 2 years). Advisory only — expiry that hard-fails would strand badges the same way revocation does.
- **`key_id` format was unspecified.** Fixed here: `key_id` is the lowercase hex SHA-256 of the public key, truncated to 16 bytes (32 hex chars). Deriving the id from the key material makes ids collision-resistant, globally unique without coordination, and self-verifying (a verifier can confirm the key it fetched matches the id the badge names).

### D4 — RESOLVED (decided upstream): pull-based revocation checking only.

A badge's signature proves what was true at issuance; only a status lookup proves it's still true. Verification in Recryption is therefore *always* signature check **plus** a current-status read (badge status, key status, claims digest — §3) at time of use. There is no push, webhook, or revocation-list delivery mechanism in this version, and verifiers MUST NOT cache a "valid" result beyond their own tolerance for stale revocations (the library exposes `max_status_age` in the verify call; default 0 = check every time). **Explicitly unsupported future option (not designed here):** push-based propagation — webhooks, signed revocation lists, or status-list bitstrings — would matter if third parties verified badges without database access; that's the D1 future phase's problem, not this version's.

### D5 — RESOLVED (the open question): the pepper is a required, versioned config value — the library enforces its shape and owns rotation mechanics, but never generates, stores, or transmits it.

The question: for a library used by unrelated deploying apps, should HMAC pepper generation/rotation be (a) guidance the library merely documents, (b) a required config value the library stays silent on, or (c) something the library manages itself?

**Decision: a hardened version of (b).** The pepper is a deploying-app-supplied secret, but the library is *not* silent on it: it validates shape at startup (≥ 32 bytes, supplied via the app's secret store, refused if it matches known-weak patterns like all-zero or ASCII-dictionary strings), requires it to arrive as a **versioned set** (`pepper_id` → secret), and stamps every stored duplicate-detection hash with the `pepper_id` that produced it.

Reasoning against the alternatives:
- **Pure guidance (a)** fails the "unrelated deploying apps" test — some fraction will hardcode a string literal, and a guessable pepper silently collapses the whole duplicate-detection guarantee back to a brute-forceable bare hash. The library can't verify entropy, but it can refuse the obviously catastrophic cases and force the versioning discipline that makes rotation survivable.
- **Library-managed generation (c)** puts Recryption in the secrets-management business — now it must decide where the secret lives, which is exactly the kind of environment-specific choice (AWS KMS vs. Vault vs. sealed secrets) a library cannot make well for unrelated apps. Worse, "the library generated it" tempts apps to let the library also persist it, and a pepper stored next to the hashes it protects is worth nothing.

**Rotation — the least-bad handling of "rotation invalidates all existing hashes":** the core constraint is that the server never holds document-number plaintext at rest, so existing hashes *cannot* be re-computed under a new pepper. Full invalidation is therefore not a bug to engineer around but a cost to schedule. Recryption handles it with **dual-pepper lookup, single-pepper write**:

1. Config accepts a `current` pepper and an optional list of `previous` peppers (each with `pepper_id`).
2. Every new hash is computed and stored under `current` only.
3. Duplicate lookup checks the incoming document number against hashes under `current` **and** every `previous` pepper — plaintext is transiently present at exactly this moment (it arrives for the check and is discarded), so computing k HMACs instead of 1 is free.
4. Old-pepper hashes age out naturally under the deploying app's retention policy, or the app drops a `previous` pepper from config once its hashes are gone — at which point those hashes are dead weight and can be deleted.

This makes **planned rotation lossless** (no duplicate-detection blind spot, no re-enrollment of users) at the cost of k HMAC computations per check. **Compromise response is the one genuinely lossy case:** if the pepper leaks *together with* the hash table, offline brute-force of document numbers is already possible, so the compromised pepper must be dropped immediately — not kept in `previous` — and its hashes deleted. The app accepts a duplicate-detection blind spot for exactly the population verified under the compromised pepper, closing lazily as users re-verify. The library ships this as an explicit `compromise_rotation` operation so the destructive path is deliberate, logged, and distinct from planned rotation.

---

## Technical spec

### 0. Library boundary

Recryption is backend-side. It defines storage schemas (as portable table/document shapes the app maps onto its own database), pure functions for hashing and payload construction, a signer/verifier interface, and status-mutation operations. It does not do networking, does not store secrets, and does not verify documents — the deploying app asserts "these claims are verified" and Recryption makes that assertion durable, checkable, and revocable.

All multi-byte encodings are UTF-8; all binary values are stored/transmitted as lowercase hex unless noted; all timestamps are UTC ISO-8601.

### 1. Ed25519 badge issuance & verification

#### 1.1 Key record

```
SigningKey {
  key_id:      string   // 32 hex chars = first 16 bytes of SHA-256(public_key)
  public_key:  bytes32  // Ed25519 public key
  status:      "active" | "retired" | "revoked"
  created_at:  timestamp
  retired_at:  timestamp?   // set on active → retired
  revoked_at:  timestamp?   // set on {active,retired} → revoked
}
```

Invariants the library enforces on every mutation:
- Exactly one key has `status = "active"` (checked transactionally on rotation).
- Transitions: `active → retired`, `active → revoked`, `retired → revoked`. Nothing else. No transition ever clears a `*_at` timestamp.
- Private key material never appears in this record or anywhere else in Recryption-managed storage. Signing is performed through a caller-supplied `sign(payload_bytes) → signature` callback so the private key can live in a KMS/HSM.

Rotation operations:
- `rotate()` — generate/register a new key (the app supplies the new public key + signer), mark it `active`, mark the previous active key `retired`, in one transaction.
- `revoke(key_id)` — set `revoked`; takes effect on the next verification of any badge naming that `key_id` (which, per D4, is every verification).

#### 1.2 Badge payload (the signed bytes)

The payload is a canonical JSON object (keys sorted, no insignificant whitespace, numbers as integers only) — canonicalization matters because the verifier must re-derive the exact signed bytes:

```
BadgePayload {
  v:              1                    // payload schema version
  badge_id:       string               // UUIDv4, assigned at issuance
  subject_id:     string               // deploying app's opaque user identifier
  claims:         { [field]: value }   // ONLY the verified fields, e.g. {"name_verified": true, "dob_verified": true, "document_type": "drivers_license", "document_expiry": "2031-04-01"}
  claims_digest:  string               // hex SHA-256 of canonical JSON of the *source* verified fields (§3.1)
  verification_method: "manual"        // fixed in this version (D2)
  key_id:         string               // the key this badge is signed under
  issued_at:      timestamp
}
```

Signature: `sig = Ed25519.sign(private_key, canonical_bytes(BadgePayload))`. The stored/transported badge is `{ payload, sig }`.

Minimization rule carried over from the original spec: `claims` holds verification *outcomes* (booleans, document type, expiry), never raw extracted fields, never the document number. The document number's only trace anywhere is the HMAC in §2.

#### 1.3 Badge record (server-side status, the pull-checked half)

```
Badge {
  badge_id:      string     // matches payload
  subject_id:    string
  key_id:        string     // denormalized from payload for bulk operations
  claims_digest: string     // denormalized from payload for the §3 comparison
  status:        "valid" | "revoked"
  revoked_reason: "claim_change" | "manual" | "key_compromise" | null
  issued_at:     timestamp
  revoked_at:    timestamp?
}
```

#### 1.4 Verification lookup logic

`verify(badge, opts) → { ok, reason? }`, executed in this order (cheapest and most-final checks first):

```
1. Parse payload; require payload.v == 1.
2. Look up SigningKey by payload.key_id.
     - not found            → fail("unknown_key")
     - status == "revoked"  → fail("key_revoked")        // D3: immediate, no grace
     - status ∈ {"active","retired"} → continue          // retired keys still verify old badges
3. Confirm key_id integrity: key_id == hex(SHA-256(public_key))[:32], else fail("key_id_mismatch").
4. Ed25519.verify(public_key, canonical_bytes(payload), sig), else fail("bad_signature").
5. Look up Badge by payload.badge_id (the pull check, D4).
     - not found            → fail("unknown_badge")
     - status == "revoked"  → fail("badge_revoked", revoked_reason)
6. Claim-change check (§3.2): recompute current claims_digest for subject_id;
     if != payload.claims_digest → auto-revoke (reason "claim_change") and fail("claims_changed").
7. Optional freshness policy: if key.retired_at and payload.issued_at > key.retired_at + tolerance
     (default 24h) → fail("issued_after_retirement").
8. ok.
```

Steps 5–6 are the pull-based half: signature validity alone is never a pass.

Bulk re-issuance helper (the D3 remediation for key compromise): `reissue_all(key_id)` iterates `Badge WHERE key_id = ? AND status = "valid"`, and for each one whose §3 claims digest still matches, constructs a fresh payload (new `badge_id`, current active `key_id`, new `issued_at`, same `subject_id`/`claims`/`claims_digest`), signs it, writes the new record, and marks the old badge `revoked` with reason `"key_compromise"`.

#### 1.5 Health check

`health()` is advisory (never blocks issuance): warns if the active key's age exceeds the configured maximum (default 2 years), if more than one active key exists (invariant breach), or if any `previous` pepper (§2) has zero remaining hashes and can be dropped from config.

### 2. HMAC-SHA256 duplicate-document detection

#### 2.1 Pepper config (per D5)

```
PepperConfig {
  current:   { pepper_id: string, secret: bytes (>= 32) }
  previous:  [ { pepper_id, secret } ]   // may be empty
}
```

Validated at startup: length, non-trivial entropy patterns (reject all-equal bytes, printable-ASCII-only secrets under 48 bytes), unique `pepper_id`s. Secrets are supplied by the app from its own secret store; Recryption never writes them anywhere.

#### 2.2 Hash record

```
DocumentHash {
  doc_hmac:    string   // hex HMAC-SHA256(pepper.secret, normalized document identity)
  pepper_id:   string   // which pepper produced doc_hmac
  subject_id:  string   // the account this document verified
  created_at:  timestamp
}
```

Normalized document identity (so the same physical document always produces the same HMAC): `document_type || ":" || issuing_country || ":" || uppercase(strip_non_alphanumeric(document_number))`. Including type and country prevents cross-type collisions (a passport number coinciding with a license number) from producing false duplicates.

#### 2.3 Check-and-record

`check_duplicate(document_fields, subject_id) → { duplicate: bool, existing_subject_id? }`:

```
1. n = normalize(document_fields)                    // plaintext exists only inside this call
2. For each pepper p in [current] + previous:
     h_p = HMAC-SHA256(p.secret, n)
     if DocumentHash(doc_hmac = h_p) exists with subject_id != caller's
        → return duplicate (do not write anything)
3. Store DocumentHash(HMAC(current, n), current.pepper_id, subject_id).
4. Discard n. The plaintext document number is never persisted, logged, or returned.
```

Same-subject re-verification (step 2 match with *equal* subject_id) is not a duplicate; the record's `created_at` is refreshed and, if it was stored under a `previous` pepper, it is rewritten under `current` — this is the lazy migration that closes rotation blind spots over time.

#### 2.4 Rotation operations

- `planned_rotation(new_pepper)` — push `current` into `previous`, install `new_pepper` as `current`. Lossless per D5; lookups now cost k HMACs until old hashes age out.
- `compromise_rotation(new_pepper, compromised_pepper_id)` — install `new_pepper` as `current`, **delete** all `DocumentHash` rows with the compromised `pepper_id`, and refuse to keep the compromised secret in `previous`. Destructive and logged; the duplicate-detection blind spot it creates is accepted per D5.

### 3. Revocation on claim change

#### 3.1 Claims digest

The deploying app registers, per badge type, the list of **source fields** the badge's claims are derived from (e.g. the user's verified legal name, DOB, document type, document expiry as held in the app's own user store). The digest is `SHA-256(canonical JSON of {field: current_value})` over exactly those fields, computed at issuance and embedded in the payload as `claims_digest`.

The digest deliberately covers the *source* values, not the badge's boolean outcomes — "name_verified: true" doesn't change when a user edits their name, but the name itself does, and that's precisely the event that must kill the badge.

#### 3.2 Two enforcement paths, both required

- **Eager (at mutation):** the library exposes `on_claims_changed(subject_id)` for the app to call from its profile-update path. It recomputes the digest; if it differs from any valid badge's stored `claims_digest` for that subject, those badges are set `revoked` / `"claim_change"` immediately. This is the primary path — revocation lands at write time, not first-use time.
- **Lazy (at verification):** step 6 of §1.4 recomputes and compares on every verify. This is the backstop for the app forgetting to call the hook (or a claims change arriving through a path that bypasses it). Because verification is always pull-based (D4), the backstop is airtight at time of use even if the eager hook never fired.

Re-issuance after a legitimate claims change (user legally renamed, document renewed) is just a new issuance: the app re-verifies through its own (manual, per D2) process and calls issue again; the old badge stays revoked. Revocation is never reversed — `status: revoked` is terminal for a badge, matching the one-way key transitions in §1.1.

---

## Explicitly out of scope (future phases, one paragraph each, per the ground rules)

**Cross-platform interop:** badges verifying across unrelated deployments would need a published payload profile, key discovery (e.g. a `/.well-known` key set), and a revocation mechanism that works without database access — the push/status-list options D4 declined. **Automated document verification:** ML visual authentication and specialized OCR would slot in as new `verification_method` values feeding the same issuance call; nothing in the primitives changes, only what the deploying app does before calling them. **Push revocation:** webhooks or signed revocation lists become worthwhile only alongside interop, since every verifier in this version can already read the badge table.
