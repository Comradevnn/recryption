import * as ed from "@noble/ed25519";
import type { BadgeRecord, BadgeStore, SignedBadge } from "../src/badge.js";
import type { DocumentHash, DocumentHashStore } from "../src/duplicateDetection.js";
import type { KeyStore, Signer, SigningKey } from "../src/keys.js";
import "../src/badge.js"; // wires ed.etc.sha512Sync for the sync noble API

/** Reference in-memory KeyStore. Clones on read/write so tests can't alias records. */
export class InMemoryKeyStore implements KeyStore {
  private readonly keys = new Map<string, SigningKey>();

  async get(keyId: string): Promise<SigningKey | undefined> {
    const key = this.keys.get(keyId);
    return key ? { ...key } : undefined;
  }

  async getActive(): Promise<SigningKey | undefined> {
    for (const key of this.keys.values()) {
      if (key.status === "active") return { ...key };
    }
    return undefined;
  }

  async list(): Promise<SigningKey[]> {
    return [...this.keys.values()].map((k) => ({ ...k }));
  }

  async save(key: SigningKey): Promise<void> {
    this.keys.set(key.key_id, { ...key });
  }
}

/** Reference in-memory DocumentHashStore, keyed by doc_hmac. */
export class InMemoryDocumentHashStore implements DocumentHashStore {
  private readonly records = new Map<string, DocumentHash>();

  async findByHmac(docHmac: string): Promise<DocumentHash | undefined> {
    const record = this.records.get(docHmac);
    return record ? { ...record } : undefined;
  }

  async save(record: DocumentHash): Promise<void> {
    this.records.set(record.doc_hmac, { ...record });
  }

  async delete(docHmac: string): Promise<void> {
    this.records.delete(docHmac);
  }

  async deleteByPepperId(pepperId: string): Promise<number> {
    let deleted = 0;
    for (const [hmac, record] of this.records) {
      if (record.pepper_id === pepperId) {
        this.records.delete(hmac);
        deleted++;
      }
    }
    return deleted;
  }

  async countByPepperId(pepperId: string): Promise<number> {
    return [...this.records.values()].filter((r) => r.pepper_id === pepperId).length;
  }

  /** Test-only: every stored record, for plaintext-leak and shape assertions. */
  all(): DocumentHash[] {
    return [...this.records.values()].map((r) => ({ ...r }));
  }
}

/** Reference in-memory BadgeStore: status records plus the signed-badge archive. */
export class InMemoryBadgeStore implements BadgeStore {
  private readonly records = new Map<string, BadgeRecord>();
  private readonly signed = new Map<string, SignedBadge>();

  async get(badgeId: string): Promise<BadgeRecord | undefined> {
    const record = this.records.get(badgeId);
    return record ? { ...record } : undefined;
  }

  async save(record: BadgeRecord): Promise<void> {
    this.records.set(record.badge_id, { ...record });
  }

  async saveSigned(badge: SignedBadge): Promise<void> {
    this.signed.set(badge.payload.badge_id, structuredClone(badge));
  }

  async getSigned(badgeId: string): Promise<SignedBadge | undefined> {
    const badge = this.signed.get(badgeId);
    return badge ? structuredClone(badge) : undefined;
  }

  async listValidBySubject(subjectId: string): Promise<BadgeRecord[]> {
    return [...this.records.values()]
      .filter((r) => r.subject_id === subjectId && r.status === "valid")
      .map((r) => ({ ...r }));
  }

  async listValidByKey(keyId: string): Promise<BadgeRecord[]> {
    return [...this.records.values()]
      .filter((r) => r.key_id === keyId && r.status === "valid")
      .map((r) => ({ ...r }));
  }

  /** Test-only: delete a record to simulate an unknown badge. */
  deleteRecord(badgeId: string): void {
    this.records.delete(badgeId);
  }
}

/**
 * Test-only keypair + Signer. The library never sees the private key — this
 * plays the role of the app's KMS/HSM side of the Signer callback.
 */
export function makeKeypairSigner(): { publicKeyHex: string; signer: Signer } {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = ed.getPublicKey(privateKey);
  return {
    publicKeyHex: Buffer.from(publicKey).toString("hex"),
    signer: async (message: Buffer) => Buffer.from(ed.sign(new Uint8Array(message), privateKey)),
  };
}
