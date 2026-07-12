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
