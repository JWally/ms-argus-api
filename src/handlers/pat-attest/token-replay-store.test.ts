import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const VALKEY_MODULE = "../../helpers/valkey-client";

afterEach(() => {
  vi.resetModules();
  vi.doUnmock(VALKEY_MODULE);
  delete process.env.VALKEY_ENDPOINT;
});

describe("PAT raw-token replay ledger", () => {
  beforeEach(() => {
    process.env.VALKEY_ENDPOINT = "fake-valkey:6379";
  });

  it("claims a raw token hash exactly once", async () => {
    const used = new Set<string>();
    const set = vi.fn(async (key: string) => {
      if (used.has(key)) return null;
      used.add(key);
      return "OK";
    });
    vi.doMock(VALKEY_MODULE, () => ({ getValkey: () => ({ set }) }));
    const { claimPatTokenHash } = await import("./token-replay-store");

    expect(await claimPatTokenHash("abc")).toBe("claimed");
    expect(await claimPatTokenHash("abc")).toBe("replayed");
    expect(set).toHaveBeenCalledWith("pat:used:abc", "1", "EX", 2592000, "NX");
  });

  it("fails closed for PAT credit when Valkey is unavailable", async () => {
    vi.doMock(VALKEY_MODULE, () => ({
      getValkey: () => ({
        set: vi.fn(async () => {
          throw new Error("down");
        }),
      }),
    }));
    const { claimPatTokenHash } = await import("./token-replay-store");
    expect(await claimPatTokenHash("abc")).toBe("unavailable");
  });

  it("is unavailable when the replay ledger is not configured", async () => {
    delete process.env.VALKEY_ENDPOINT;
    vi.doMock(VALKEY_MODULE, () => ({ getValkey: vi.fn() }));
    const { claimPatTokenHash } = await import("./token-replay-store");
    expect(await claimPatTokenHash("abc")).toBe("unavailable");
  });
});
