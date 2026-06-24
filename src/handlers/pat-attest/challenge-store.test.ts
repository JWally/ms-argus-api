import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "crypto";

const MOD = "./challenge-store";
const VALKEY_MOD = "../../helpers/valkey-client";

/** In-memory fake of the two ioredis commands the store uses. */
function makeFakeValkey() {
  const map = new Map<string, string>();
  return {
    map,
    set: vi.fn(async (key: string, val: string) => {
      map.set(key, val);
      return "OK";
    }),
    getdel: vi.fn(async (key: string) => {
      const v = map.get(key) ?? null;
      map.delete(key);
      return v;
    }),
  };
}

const digestOf = (challenge: Buffer) =>
  createHash("sha256").update(challenge).digest();

afterEach(() => {
  vi.resetModules();
  vi.doUnmock(VALKEY_MOD);
  delete process.env.VALKEY_ENDPOINT;
});

describe("PAT bound-challenge store (#13)", () => {
  beforeEach(() => {
    process.env.VALKEY_ENDPOINT = "fake-valkey:6379";
  });

  it("stores a challenge and consumes it exactly once (single-use)", async () => {
    const fake = makeFakeValkey();
    vi.doMock(VALKEY_MOD, () => ({ getValkey: () => fake }));
    const { storeChallenge, consumeChallenge } = await import(MOD);

    const challenge = Buffer.from("a-bound-challenge");
    expect(await storeChallenge(challenge)).toBe(true);

    // First redemption: the exact bytes come back.
    const first = await consumeChallenge(digestOf(challenge));
    expect(first?.equals(challenge)).toBe(true);

    // Replay: the key is gone → null (this is the single-use guarantee).
    const second = await consumeChallenge(digestOf(challenge));
    expect(second).toBeNull();
  });

  it("returns null for a digest that was never stored", async () => {
    const fake = makeFakeValkey();
    vi.doMock(VALKEY_MOD, () => ({ getValkey: () => fake }));
    const { consumeChallenge } = await import(MOD);
    expect(await consumeChallenge(digestOf(Buffer.from("never")))).toBeNull();
  });

  it("is disabled (no binding) when VALKEY_ENDPOINT is unset", async () => {
    delete process.env.VALKEY_ENDPOINT;
    const fake = makeFakeValkey();
    vi.doMock(VALKEY_MOD, () => ({ getValkey: () => fake }));
    const { bindingEnabled, storeChallenge, consumeChallenge } = await import(
      MOD
    );

    expect(bindingEnabled()).toBe(false);
    expect(await storeChallenge(Buffer.from("x"))).toBe(false);
    expect(await consumeChallenge(digestOf(Buffer.from("x")))).toBeNull();
    expect(fake.set).not.toHaveBeenCalled();
    expect(fake.getdel).not.toHaveBeenCalled();
  });

  it("fails open when Valkey throws (store=false, consume=null)", async () => {
    const boom = {
      set: vi.fn(async () => {
        throw new Error("valkey down");
      }),
      getdel: vi.fn(async () => {
        throw new Error("valkey down");
      }),
    };
    vi.doMock(VALKEY_MOD, () => ({ getValkey: () => boom }));
    const { storeChallenge, consumeChallenge } = await import(MOD);

    expect(await storeChallenge(Buffer.from("x"))).toBe(false);
    expect(await consumeChallenge(digestOf(Buffer.from("x")))).toBeNull();
  });

  it("newRedemptionContext is 32 random bytes", async () => {
    vi.doMock(VALKEY_MOD, () => ({ getValkey: () => makeFakeValkey() }));
    const { newRedemptionContext } = await import(MOD);
    const a = newRedemptionContext();
    const b = newRedemptionContext();
    expect(a.length).toBe(32);
    expect(a.equals(b)).toBe(false);
  });
});
