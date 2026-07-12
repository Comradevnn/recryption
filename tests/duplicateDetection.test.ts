import { randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  DestructiveOperationNotConfirmedError,
  DuplicateDetector,
  InvalidDocumentError,
  InvalidPepperConfigError,
  compromiseRotation,
  normalizeDocumentIdentity,
  plannedRotation,
  validatePepperConfig,
  type DocumentFields,
  type Pepper,
} from "../src/duplicateDetection.js";
import { InMemoryDocumentHashStore } from "./helpers.js";

const pepper = (id: string): Pepper => ({ pepper_id: id, secret: randomBytes(32) });

const licenseUS: DocumentFields = {
  document_type: "drivers_license",
  issuing_country: "US",
  document_number: "D123-456-78",
};

describe("validatePepperConfig (spec §2.1 startup validation)", () => {
  it("accepts a random 32-byte current pepper with no previous", () => {
    expect(() => validatePepperConfig({ current: pepper("p1") })).not.toThrow();
  });

  it("rejects secrets under 32 bytes", () => {
    const short = { pepper_id: "p1", secret: randomBytes(31) };
    expect(() => validatePepperConfig({ current: short })).toThrow(InvalidPepperConfigError);
  });

  it("rejects a repeated-single-byte secret (all-zero and friends)", () => {
    const zeros = { pepper_id: "p1", secret: new Uint8Array(64) };
    expect(() => validatePepperConfig({ current: zeros })).toThrow(InvalidPepperConfigError);
  });

  it("rejects printable-ASCII-only secrets under 48 bytes, accepts them at 48+", () => {
    const ascii40 = { pepper_id: "p1", secret: Buffer.from("a".repeat(39) + "b", "utf8") };
    expect(() => validatePepperConfig({ current: ascii40 })).toThrow(InvalidPepperConfigError);

    const ascii48 = {
      pepper_id: "p1",
      secret: Buffer.from("correct horse battery staple correct horse batte", "utf8"),
    };
    expect(ascii48.secret.length).toBeGreaterThanOrEqual(48);
    expect(() => validatePepperConfig({ current: ascii48 })).not.toThrow();
  });

  it("rejects duplicate pepper_ids across current + previous", () => {
    expect(() =>
      validatePepperConfig({ current: pepper("p1"), previous: [pepper("p1")] }),
    ).toThrow(InvalidPepperConfigError);
  });

  it("rejects a previous pepper that shares the current secret", () => {
    const current = pepper("p2");
    const aliased = { pepper_id: "p1", secret: current.secret };
    expect(() => validatePepperConfig({ current, previous: [aliased] })).toThrow(
      InvalidPepperConfigError,
    );
  });
});

describe("normalizeDocumentIdentity (spec §2.2)", () => {
  it("strips punctuation/whitespace and uppercases the number", () => {
    expect(normalizeDocumentIdentity(licenseUS)).toBe("drivers_license:us:D12345678");
  });

  it("gives one identity per physical document regardless of input casing", () => {
    const shouty = {
      document_type: "DRIVERS_LICENSE",
      issuing_country: "us",
      document_number: "d123 456 78",
    };
    expect(normalizeDocumentIdentity(shouty)).toBe(normalizeDocumentIdentity(licenseUS));
  });

  it("separates document types so a passport number can't collide with a license (§2.2)", () => {
    const passport = { ...licenseUS, document_type: "passport" };
    expect(normalizeDocumentIdentity(passport)).not.toBe(normalizeDocumentIdentity(licenseUS));
  });

  it("rejects ':' in type/country (preimage delimiter) and empty numbers", () => {
    expect(() =>
      normalizeDocumentIdentity({ ...licenseUS, document_type: "a:b" }),
    ).toThrow(InvalidDocumentError);
    expect(() =>
      normalizeDocumentIdentity({ ...licenseUS, document_number: "---" }),
    ).toThrow(InvalidDocumentError);
  });
});

describe("DuplicateDetector.checkDuplicate (spec §2.3)", () => {
  it("flags the same document verified by a different account", async () => {
    const detector = new DuplicateDetector(new InMemoryDocumentHashStore(), {
      current: pepper("p1"),
    });
    expect(await detector.checkDuplicate(licenseUS, "alice")).toEqual({ duplicate: false });
    expect(await detector.checkDuplicate(licenseUS, "bob")).toEqual({
      duplicate: true,
      existing_subject_id: "alice",
    });
  });

  it("writes nothing on a duplicate", async () => {
    const store = new InMemoryDocumentHashStore();
    const detector = new DuplicateDetector(store, { current: pepper("p1") });
    await detector.checkDuplicate(licenseUS, "alice");
    await detector.checkDuplicate(licenseUS, "bob");
    expect(store.all()).toHaveLength(1);
    expect(store.all()[0]!.subject_id).toBe("alice");
  });

  it("does not flag distinct documents", async () => {
    const detector = new DuplicateDetector(new InMemoryDocumentHashStore(), {
      current: pepper("p1"),
    });
    await detector.checkDuplicate(licenseUS, "alice");
    expect(
      await detector.checkDuplicate({ ...licenseUS, document_number: "X999" }, "bob"),
    ).toEqual({ duplicate: false });
  });

  it("treats same-subject re-verification as not-a-duplicate and refreshes created_at", async () => {
    const store = new InMemoryDocumentHashStore();
    const detector = new DuplicateDetector(store, { current: pepper("p1") });
    await detector.checkDuplicate(licenseUS, "alice");

    const [record] = store.all();
    await store.save({ ...record!, created_at: "2020-01-01T00:00:00.000Z" });

    expect(await detector.checkDuplicate(licenseUS, "alice")).toEqual({ duplicate: false });
    expect(store.all()[0]!.created_at).not.toBe("2020-01-01T00:00:00.000Z");
  });

  it("never persists the plaintext document number in any stored field", async () => {
    const store = new InMemoryDocumentHashStore();
    const detector = new DuplicateDetector(store, { current: pepper("p1") });
    await detector.checkDuplicate(licenseUS, "alice");

    for (const record of store.all()) {
      for (const value of Object.values(record)) {
        expect(value).not.toContain("D12345678");
        expect(value).not.toContain(licenseUS.document_number);
      }
    }
  });
});

describe("rotation (spec §2.4, D5)", () => {
  it("plannedRotation: dual-pepper lookup still catches duplicates across one rotation", async () => {
    const store = new InMemoryDocumentHashStore();
    const p1 = pepper("p1");
    await new DuplicateDetector(store, { current: p1 }).checkDuplicate(licenseUS, "alice");

    const rotated = plannedRotation({ current: p1 }, pepper("p2"));
    expect(rotated.previous).toEqual([p1]);

    const detector = new DuplicateDetector(store, rotated);
    expect(await detector.checkDuplicate(licenseUS, "bob")).toEqual({
      duplicate: true,
      existing_subject_id: "alice",
    });
  });

  it("misses correctly once the old pepper is dropped from config — the accepted blind spot", async () => {
    const store = new InMemoryDocumentHashStore();
    const p1 = pepper("p1");
    await new DuplicateDetector(store, { current: p1 }).checkDuplicate(licenseUS, "alice");

    // p1 aged out of config entirely: its hash is unreachable by design (D5).
    const detector = new DuplicateDetector(store, { current: pepper("p3") });
    expect(await detector.checkDuplicate(licenseUS, "bob")).toEqual({ duplicate: false });
  });

  it("lazy migration: same-subject re-verification rewrites the hash under the current pepper", async () => {
    const store = new InMemoryDocumentHashStore();
    const p1 = pepper("p1");
    const p2 = pepper("p2");
    await new DuplicateDetector(store, { current: p1 }).checkDuplicate(licenseUS, "alice");

    const detector = new DuplicateDetector(store, plannedRotation({ current: p1 }, p2));
    await detector.checkDuplicate(licenseUS, "alice");

    expect(store.all()).toHaveLength(1);
    expect(store.all()[0]!.pepper_id).toBe("p2");

    // Migration closed the future blind spot: p1 can now be dropped and bob is still caught.
    const withoutP1 = new DuplicateDetector(store, { current: p2 });
    expect(await withoutP1.checkDuplicate(licenseUS, "bob")).toEqual({
      duplicate: true,
      existing_subject_id: "alice",
    });
  });

  it("compromiseRotation refuses to run without the confirmation flag", async () => {
    const p1 = pepper("p1");
    await expect(
      compromiseRotation({
        store: new InMemoryDocumentHashStore(),
        config: { current: p1 },
        newPepper: pepper("p2"),
        compromisedPepperId: "p1",
        confirmDestructive: false,
      }),
    ).rejects.toThrow(DestructiveOperationNotConfirmedError);
  });

  it("compromiseRotation deletes only the compromised pepper's hashes and logs the count", async () => {
    const store = new InMemoryDocumentHashStore();
    const p1 = pepper("p1");
    const p2 = pepper("p2");

    await new DuplicateDetector(store, { current: p1 }).checkDuplicate(licenseUS, "alice");
    const config = plannedRotation({ current: p1 }, p2);
    await new DuplicateDetector(store, config).checkDuplicate(
      { ...licenseUS, document_number: "X999" },
      "carol",
    );

    const logger = vi.fn();
    const result = await compromiseRotation({
      store,
      config,
      newPepper: pepper("p3"),
      compromisedPepperId: "p1",
      confirmDestructive: true,
      logger,
    });

    expect(result.deleted_hashes).toBe(1);
    expect(logger).toHaveBeenCalledWith(
      expect.objectContaining({
        event: "compromise_rotation",
        compromised_pepper_id: "p1",
        deleted_hashes: 1,
      }),
    );
    // Carol's p2 hash survived; the compromised pepper is gone from config.
    expect(store.all().map((r) => r.pepper_id)).toEqual(["p2"]);
    expect(result.config.current.pepper_id).toBe("p3");
    expect(result.config.previous?.map((p) => p.pepper_id)).toEqual(["p2"]);

    // The blind spot is real and accepted: alice's document no longer matches.
    const detector = new DuplicateDetector(store, result.config);
    expect(await detector.checkDuplicate(licenseUS, "bob")).toEqual({ duplicate: false });
  });

  it("compromiseRotation rejects reusing the compromised secret as the replacement", async () => {
    const p1 = pepper("p1");
    await expect(
      compromiseRotation({
        store: new InMemoryDocumentHashStore(),
        config: { current: p1 },
        newPepper: { pepper_id: "p2", secret: p1.secret },
        compromisedPepperId: "p1",
        confirmDestructive: true,
      }),
    ).rejects.toThrow(InvalidPepperConfigError);
  });
});

describe("DuplicateDetector.health (spec §1.5 pepper half)", () => {
  it("flags previous peppers with zero remaining hashes as droppable", async () => {
    const store = new InMemoryDocumentHashStore();
    const p1 = pepper("p1");
    const p2 = pepper("p2");
    const detector = new DuplicateDetector(store, plannedRotation({ current: p1 }, p2));

    expect(await detector.health()).toEqual([
      expect.objectContaining({ code: "droppable_previous_pepper", pepper_id: "p1" }),
    ]);

    // Give p1 a live hash via a fresh detector where p1 is current: no longer droppable.
    await new DuplicateDetector(store, { current: p1 }).checkDuplicate(licenseUS, "alice");
    expect(await detector.health()).toEqual([]);
  });
});
