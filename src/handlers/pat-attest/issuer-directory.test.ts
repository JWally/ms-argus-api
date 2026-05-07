import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { getActiveTokenKey, __resetCacheForTesting } from "./issuer-directory";

const VALID_DIRECTORY = {
  "issuer-request-uri": "https://issuer.example/token-request",
  "token-keys": [
    {
      "token-type": 2,
      "token-key": "MIIBUjA9BgkqhkiG9w0BAQowMA",
      "not-before": 1_700_000_000,
    },
  ],
};

function mockFetch(impl: () => Response | Promise<Response>): void {
  vi.stubGlobal("fetch", vi.fn(impl));
}

describe("getActiveTokenKey", () => {
  beforeEach(() => {
    __resetCacheForTesting();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("populates the cache from a live fetch on first call", async () => {
    mockFetch(() => new Response(JSON.stringify(VALID_DIRECTORY)));
    const key = await getActiveTokenKey();
    expect(key).not.toBeNull();
    expect(key?.spkiDer.length).toBeGreaterThan(0);
  });

  it("returns the same cached value on second call without re-fetching", async () => {
    const f = vi.fn(() => new Response(JSON.stringify(VALID_DIRECTORY)));
    vi.stubGlobal("fetch", f);
    await getActiveTokenKey();
    await getActiveTokenKey();
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("returns null when the directory fetch fails AND cache is empty", async () => {
    mockFetch(() => Promise.reject(new Error("ECONNREFUSED")));
    const key = await getActiveTokenKey();
    expect(key).toBeNull();
  });

  it("returns null when the directory has no usable key for our token-type", async () => {
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            "issuer-request-uri": "https://x/token-request",
            "token-keys": [
              { "token-type": 99, "token-key": "AA", "not-before": 1 },
            ],
          }),
        ),
    );
    const key = await getActiveTokenKey();
    expect(key).toBeNull();
  });

  it("ignores keys whose not-before is in the future", async () => {
    const future = Math.floor(Date.now() / 1000) + 86_400;
    mockFetch(
      () =>
        new Response(
          JSON.stringify({
            "issuer-request-uri": "https://x/token-request",
            "token-keys": [
              { "token-type": 2, "token-key": "AA", "not-before": future },
            ],
          }),
        ),
    );
    const key = await getActiveTokenKey();
    expect(key).toBeNull();
  });
});
