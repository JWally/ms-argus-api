import { describe, it, expect } from "vitest";
import { categorize } from "./categorize";

describe("categorize — English carriers", () => {
  it("ATT-MOBILITY-LLC → mobile", () => {
    expect(categorize("ATT-MOBILITY-LLC")).toBe("mobile");
  });
  it("T-MOBILE USA → mobile", () => {
    expect(categorize("T-MOBILE USA")).toBe("mobile");
  });
  it("EE-MOBILE → mobile", () => {
    expect(categorize("EE-MOBILE")).toBe("mobile");
  });
  it("VERIZON-WIRELESS → mobile", () => {
    expect(categorize("VERIZON-WIRELESS")).toBe("mobile");
  });
  it("BT-CENTRAL-PLUS → residential", () => {
    expect(categorize("BT-CENTRAL-PLUS")).toBe("residential");
  });
  it("ARCOR-DSL-NET17 → residential", () => {
    expect(categorize("ARCOR-DSL-NET17")).toBe("residential");
  });
  it("SBCIS-SBIS → residential (AT&T U-Verse)", () => {
    expect(categorize("SBCIS-SBIS")).toBe("residential");
  });
  it("SIS-80-4-2012 → residential (AT&T sub-allocation series)", () => {
    expect(categorize("SIS-80-4-2012")).toBe("residential");
  });
});

describe("categorize — multilingual + brand names (POC discoveries)", () => {
  it("MOBILE-POOL-NET → mobile (Telefónica DE)", () => {
    expect(categorize("MOBILE-POOL-NET")).toBe("mobile");
  });
  it("DE-D2VODAFONE-20220628 → mobile (Vodafone DE legacy D2 brand)", () => {
    expect(categorize("DE-D2VODAFONE-20220628")).toBe("mobile");
  });
  it("VF_Strategic_Connectivity → mobile (Vodafone UK)", () => {
    expect(categorize("VF_Strategic_Connectivity")).toBe("mobile");
  });
  it("MSM-External → mobile (Vodafone-grouping)", () => {
    expect(categorize("MSM-External")).toBe("mobile");
  });
  it("Movistar Móvil ES → mobile", () => {
    expect(categorize("MOVISTAR MÓVIL ES")).toBe("mobile");
  });
  it("Vivo nameserver → mobile (BR Telefónica brand)", () => {
    expect(categorize(null, null, "orion.vivo.com.br")).toBe("mobile");
  });
  it("TELSTRAINTERNET49-AU → mobile", () => {
    expect(categorize("TELSTRAINTERNET49-AU")).toBe("mobile");
  });
});

describe("categorize — datacenter / proxy / cdn", () => {
  it.each<[string, string]>([
    ["AMAZON-AES", "datacenter"],
    ["GOOGLE-CLOUD-PLATFORM", "datacenter"],
    ["MICROSOFT-AZURE", "datacenter"],
    ["DIGITALOCEAN-AS", "datacenter"],
    ["LINODE-AP", "datacenter"],
    ["VULTR-AS", "datacenter"],
    ["OVH-CLOUD", "datacenter"],
    ["HETZNER-AS", "datacenter"],
    ["CLOUDFLARENET", "cdn"],
    ["AKAMAI-LINEAR", "cdn"],
    ["FASTLY", "cdn"],
    ["M247-EUROPE", "vpn_proxy"],
    ["LEASEWEB-USA-NYC", "vpn_proxy"],
    ["DATAPACKET-NET", "vpn_proxy"],
    ["HIVELOCITY-INC", "hosting_proxy"],
    ["AS-SPRIO", "hosting_proxy"],
    ["BLAZINGSEO-US-19", "hosting_proxy"],
    // Datacenter REITs / colocation operators
    ["QTS-SUW1-ATL1", "datacenter"],
    ["QTS-209-10-139-0-24", "datacenter"],
    ["EQUINIX-IX-LON5", "datacenter"],
    ["CORESITE-LA1", "datacenter"],
    ["CYXTERA-COMM", "datacenter"],
    ["COLOGIX-MTL3", "datacenter"],
    ["DIGITAL-REALTY-DAL", "datacenter"],
    ["TELEHOUSE-NORTH", "datacenter"],
    ["INTERXION-AMS9", "datacenter"],
    ["IRON-MOUNTAIN-DC", "datacenter"],
    // Cloud device farms
    ["BROWSERSTACK-SY4", "datacenter"],
    ["SAUCELABS-NET", "datacenter"],
    ["LAMBDATEST-CLOUD", "datacenter"],
  ])("%s → %s", (org, expected) => {
    expect(categorize(org)).toBe(expected);
  });
});

describe("categorize — provider-owned VPN networks", () => {
  it.each([
    "PROTONVPN",
    "PROTONVPN-2",
    "IVPN",
    "MULLVAD-AS",
    "WINDSCRIBE",
    "CASTLEVPN",
    "SKYVPN",
  ])("%s → vpn_proxy", (org) => {
    expect(categorize(org)).toBe("vpn_proxy");
  });

  it.each([
    "PROTON",
    "PROTON66",
    "NRI-IVPN Nomura Research Institute,Ltd.",
    "NORDUNET",
    "NORDICOM",
  ])("does not treat lookalike or mixed-use org %s as a VPN", (org) => {
    expect(categorize(org)).toBeNull();
  });
});

describe("categorize — multi-candidate fallback (LACNIC/non-English RIRs)", () => {
  it("falls through name → org → nameservers in order", () => {
    // BR LACNIC: name is just a numeric handle, but nameserver carries Vivo
    expect(
      categorize("130040", "TELEFÔNICA BRASIL S.A", "lynx.vivo.com.br"),
    ).toBe("mobile");
  });

  it("returns null when nothing matches across all candidates", () => {
    expect(
      categorize("UNKNOWN-HANDLE", "Some Generic ISP", "ns.example.com"),
    ).toBeNull();
  });

  it("handles null/undefined candidates without throwing", () => {
    expect(categorize(null, undefined, "lightspeed.dallas.sbcglobal.net")).toBe(
      "residential",
    );
  });

  it("first matching candidate wins (left-to-right)", () => {
    // The name field should win even if the org/nameserver would also match
    expect(
      categorize("ATT-MOBILITY-LLC", "AT&T Inc.", "lightspeed.example.com"),
    ).toBe("mobile");
  });
});

describe("categorize — order matters (regression guards)", () => {
  it("'MOBILE BROADBAND' classifies as mobile, not residential", () => {
    // The mobile pattern must precede the broadband pattern in the rule order
    expect(categorize("MOBILE BROADBAND ASIA")).toBe("mobile");
  });

  it("'COMCAST BUSINESS' classifies as business, not residential", () => {
    // The negative-lookahead in the COMCAST pattern excludes BUSINESS
    expect(categorize("COMCAST-BUSINESS-EAST")).toBe("business");
  });
});
