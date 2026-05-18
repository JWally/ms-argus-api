/**
 * RDAP-client extraction tests.
 *
 * Fixtures are trimmed from real ARIN RDAP responses captured on 2026-05-18.
 * The 209.208.245.102 fixture is the canonical sub-allocated case (QTS
 * datacenter operator + BrowserStack customer) — the exact shape that
 * motivated the customerOrg/parentOrg/parentCidr enrichment.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { rdapIpLookup } from "./rdap-client";

/** Minimal RDAP fixture: top-level org registrant + customer registrant. */
const FIXTURE_QTS_BROWSERSTACK = {
  name: "QTS-209-208-245-0-24",
  ipVersion: "v4",
  startAddress: "209.208.245.0",
  endAddress: "209.208.245.255",
  cidr0_cidrs: [{ v4prefix: "209.208.245.0", length: 24 }],
  country: "US",
  links: [
    { rel: "self", href: "https://rdap.arin.net/registry/ip/209.208.245.0" },
    { rel: "up", href: "https://rdap.arin.net/registry/ip/209.208.128.0/17" },
  ],
  entities: [
    {
      handle: "QTS-9",
      roles: ["registrant"],
      vcardArray: [
        "vcard",
        [
          ["version", {}, "text", "4.0"],
          ["fn", {}, "text", "Quality Technology Services, LLC"],
          ["kind", {}, "text", "org"],
        ],
      ],
    },
    {
      handle: "C11293034",
      roles: ["registrant"],
      vcardArray: [
        "vcard",
        [
          ["version", {}, "text", "4.0"],
          ["fn", {}, "text", "BrowserStack"],
          ["kind", {}, "text", "org"],
        ],
      ],
    },
  ],
};

/** Operator-only allocation — typical AT&T residential block, no sub-tenant. */
const FIXTURE_ATT_NO_CUSTOMER = {
  name: "SBC-107-192-0-0",
  cidr0_cidrs: [{ v4prefix: "107.192.0.0", length: 11 }],
  country: "US",
  links: [
    { rel: "self", href: "https://rdap.arin.net/registry/ip/107.192.0.0" },
  ],
  entities: [
    {
      handle: "AT-88-Z",
      roles: ["registrant"],
      vcardArray: [
        "vcard",
        [
          ["version", {}, "text", "4.0"],
          ["fn", {}, "text", "AT&T Services, Inc."],
          ["kind", {}, "text", "org"],
        ],
      ],
    },
  ],
};

function mockFetchOnce(body: unknown): void {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(body),
    }),
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("rdapIpLookup — registrant split", () => {
  it("extracts customerOrg and parentOrg from a sub-allocated block", async () => {
    mockFetchOnce(FIXTURE_QTS_BROWSERSTACK);
    const info = await rdapIpLookup("209.208.245.102");
    expect(info).not.toBeNull();
    expect(info?.parentOrg).toBe("Quality Technology Services, LLC");
    expect(info?.customerOrg).toBe("BrowserStack");
    // org stays back-compat: document-order first registrant (= parent)
    expect(info?.org).toBe("Quality Technology Services, LLC");
  });

  it("leaves customerOrg null when only an operator registrant exists", async () => {
    mockFetchOnce(FIXTURE_ATT_NO_CUSTOMER);
    const info = await rdapIpLookup("107.192.0.42");
    expect(info?.parentOrg).toBe("AT&T Services, Inc.");
    expect(info?.customerOrg).toBeNull();
    expect(info?.org).toBe("AT&T Services, Inc.");
  });

  it("falls back to customerOrg for `org` when no non-customer registrant exists", async () => {
    mockFetchOnce({
      name: "ORPHAN-CUSTOMER",
      cidr0_cidrs: [{ v4prefix: "198.51.100.0", length: 24 }],
      links: [
        { rel: "self", href: "https://rdap.arin.net/registry/ip/198.51.100.0" },
      ],
      entities: [
        {
          handle: "C99999999",
          roles: ["registrant"],
          vcardArray: [
            "vcard",
            [
              ["version", {}, "text", "4.0"],
              ["fn", {}, "text", "Lone Customer LLC"],
            ],
          ],
        },
      ],
    });
    const info = await rdapIpLookup("198.51.100.7");
    expect(info?.parentOrg).toBeNull();
    expect(info?.customerOrg).toBe("Lone Customer LLC");
    expect(info?.org).toBe("Lone Customer LLC");
  });
});

describe("rdapIpLookup — parentCidr extraction", () => {
  it("pulls the parent CIDR from links[rel=up]", async () => {
    mockFetchOnce(FIXTURE_QTS_BROWSERSTACK);
    const info = await rdapIpLookup("209.208.245.102");
    expect(info?.parentCidr).toBe("209.208.128.0/17");
  });

  it("returns null when no up-link is present", async () => {
    mockFetchOnce(FIXTURE_ATT_NO_CUSTOMER);
    const info = await rdapIpLookup("107.192.0.42");
    expect(info?.parentCidr).toBeNull();
  });

  it("tolerates an up-link without a trailing CIDR", async () => {
    mockFetchOnce({
      name: "MALFORMED",
      cidr0_cidrs: [{ v4prefix: "192.0.2.0", length: 24 }],
      links: [
        { rel: "self", href: "https://rdap.arin.net/registry/ip/192.0.2.0" },
        { rel: "up", href: "https://rdap.arin.net/registry/" },
      ],
      entities: [],
    });
    const info = await rdapIpLookup("192.0.2.5");
    expect(info?.parentCidr).toBeNull();
  });
});
