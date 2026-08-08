import { describe, expect, it } from "vitest";
import type { ArgusPayload } from "../../helpers/payload-schema";
import { assertProxyEvidenceHydrated, isProxyProduct } from "./proxy-product";

function payload(overrides: Partial<ArgusPayload> = {}): ArgusPayload {
  return {
    product: "proxy_v1",
    identifiers: { session_id: "proxy-session" },
    hashes: { stable: "proxy_v1", fuzzy: "proxy_v1" },
    device: {},
    ...overrides,
  };
}

describe("proxy_v1 ingestion product", () => {
  it("selects only the explicit proxy_v1 payload", () => {
    expect(isProxyProduct(payload())).toBe(true);
    expect(isProxyProduct(payload({ product: undefined }))).toBe(false);
  });

  it("requires every authoritative probe to hydrate", () => {
    expect(() =>
      assertProxyEvidenceHydrated(
        payload({
          sigint: {
            aws_cf: { tampered: false, expired: false },
            tcp_probe: { client_ip: "203.0.113.10" },
            h2: { protocol: "h2" },
          },
        }),
      ),
    ).not.toThrow();
  });

  it.each([
    ["cf", { tcp_probe: {}, h2: {} }],
    ["tcp", { aws_cf: { tampered: false, expired: false }, h2: {} }],
    [
      "h2",
      {
        aws_cf: { tampered: false, expired: false },
        tcp_probe: {},
      },
    ],
  ])("rejects when %s evidence did not hydrate", (_name, sigint) => {
    expect(() =>
      assertProxyEvidenceHydrated(payload({ sigint } as Partial<ArgusPayload>)),
    ).toThrowError(/proxy probe redemption failed/);
  });
});
