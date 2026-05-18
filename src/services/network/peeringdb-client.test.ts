import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchPeeringDbTypes } from "./peeringdb-client";

function mockFetch(impl: (...args: unknown[]) => unknown): void {
  vi.stubGlobal("fetch", vi.fn(impl));
}

function jsonResponse(body: unknown, ok = true, status = 200) {
  return {
    ok,
    status,
    statusText: ok ? "OK" : "ERR",
    json: async () => body,
  };
}

beforeEach(() => {
  vi.restoreAllMocks();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchPeeringDbTypes — parsing", () => {
  it("returns an ASN-keyed map for well-formed responses", async () => {
    mockFetch(() =>
      Promise.resolve(
        jsonResponse({
          data: [
            { asn: 7018, info_type: "NSP", ix_count: 0 },
            { asn: 9009, info_type: "Network Services", ix_count: 47 },
          ],
        }),
      ),
    );
    const map = await fetchPeeringDbTypes();
    expect(map.size).toBe(2);
    expect(map.get(7018)).toEqual({ info_type: "NSP", ix_count: 0 });
    expect(map.get(9009)).toEqual({
      info_type: "Network Services",
      ix_count: 47,
    });
  });

  it("skips empty stub records (no type and no IX presence)", async () => {
    mockFetch(() =>
      Promise.resolve(
        jsonResponse({
          data: [
            { asn: 1111, info_type: "", ix_count: 0 },
            { asn: 2222, info_type: "NSP", ix_count: 0 },
            { asn: 3333, info_type: "", ix_count: 5 },
          ],
        }),
      ),
    );
    const map = await fetchPeeringDbTypes();
    expect(map.has(1111)).toBe(false);
    expect(map.has(2222)).toBe(true);
    expect(map.has(3333)).toBe(true);
  });

  it("rejects entries with non-numeric or zero ASN", async () => {
    mockFetch(() =>
      Promise.resolve(
        jsonResponse({
          data: [
            { asn: 0, info_type: "NSP", ix_count: 1 },
            { asn: "bogus", info_type: "NSP", ix_count: 1 },
            { asn: -1, info_type: "NSP", ix_count: 1 },
            { asn: 64512, info_type: "NSP", ix_count: 1 },
          ],
        }),
      ),
    );
    const map = await fetchPeeringDbTypes();
    expect(map.size).toBe(1);
    expect(map.has(64512)).toBe(true);
  });

  it("tolerates missing/garbage individual fields without throwing", async () => {
    mockFetch(() =>
      Promise.resolve(
        jsonResponse({
          data: [
            { asn: 100, info_type: 42, ix_count: "many" },
            { asn: 200 }, // entirely absent metadata
          ],
        }),
      ),
    );
    const map = await fetchPeeringDbTypes();
    // First entry: ix_count → 0, info_type → "" — both empty so dropped
    expect(map.has(100)).toBe(false);
    expect(map.has(200)).toBe(false);
  });
});

describe("fetchPeeringDbTypes — failure tolerance", () => {
  it("returns empty map on HTTP non-2xx (does not throw)", async () => {
    mockFetch(() => Promise.resolve(jsonResponse(null, false, 503)));
    const map = await fetchPeeringDbTypes();
    expect(map.size).toBe(0);
  });

  it("returns empty map on network/timeout error", async () => {
    mockFetch(() => Promise.reject(new Error("ECONNRESET")));
    const map = await fetchPeeringDbTypes();
    expect(map.size).toBe(0);
  });

  it("returns empty map when body lacks `data` array", async () => {
    mockFetch(() => Promise.resolve(jsonResponse({ unexpected: "shape" })));
    const map = await fetchPeeringDbTypes();
    expect(map.size).toBe(0);
  });

  it("returns empty map on JSON parse failure", async () => {
    mockFetch(() =>
      Promise.resolve({
        ok: true,
        status: 200,
        statusText: "OK",
        json: async () => {
          throw new Error("invalid json");
        },
      }),
    );
    const map = await fetchPeeringDbTypes();
    expect(map.size).toBe(0);
  });
});
