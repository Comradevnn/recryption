import type { DocumentHash, DocumentHashStore } from "../src/duplicateDetection.js";
import type { KeyStore, SigningKey } from "../src/keys.js";

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
