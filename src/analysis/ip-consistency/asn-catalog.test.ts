import { describe, it, expect } from "vitest";
import { lookupAsn } from "./asn-catalog";

describe("asn-catalog — lookupAsn()", () => {
  describe("null / undefined / missing", () => {
    it("returns null for undefined", () => {
      expect(lookupAsn(undefined)).toBeNull();
    });
    it("returns null for null", () => {
      expect(lookupAsn(null)).toBeNull();
    });
    it("returns null for an ASN not in the catalog (residential default)", () => {
      expect(lookupAsn("99999999")).toBeNull();
    });
    it("accepts numeric ASN", () => {
      expect(lookupAsn(16509)?.category).toBe("datacenter");
    });
    it("accepts string ASN", () => {
      expect(lookupAsn("16509")?.category).toBe("datacenter");
    });
  });

  describe("datacenter / hosting", () => {
    it("AWS AS16509 is datacenter", () => {
      const e = lookupAsn("16509");
      expect(e?.category).toBe("datacenter");
      expect(e?.org).toBe("Amazon.com");
    });
    it("AWS AS14618 is datacenter", () => {
      expect(lookupAsn("14618")?.category).toBe("datacenter");
    });
    it("Google AS15169 is datacenter", () => {
      expect(lookupAsn("15169")?.category).toBe("datacenter");
    });
    it("Microsoft Azure AS8075 is datacenter", () => {
      expect(lookupAsn("8075")?.category).toBe("datacenter");
    });
    it("DigitalOcean AS14061 is datacenter", () => {
      expect(lookupAsn("14061")?.category).toBe("datacenter");
    });
    it("OVH AS16276 is datacenter", () => {
      expect(lookupAsn("16276")?.category).toBe("datacenter");
    });
    it("Hetzner AS24940 is datacenter", () => {
      expect(lookupAsn("24940")?.category).toBe("datacenter");
    });
    it("Vultr AS20473 is datacenter", () => {
      expect(lookupAsn("20473")?.category).toBe("datacenter");
    });
    it("Linode AS63949 is datacenter", () => {
      expect(lookupAsn("63949")?.category).toBe("datacenter");
    });
    it("Oracle AS31898 is datacenter", () => {
      expect(lookupAsn("31898")?.category).toBe("datacenter");
    });
    it("Alibaba AS45102 is datacenter", () => {
      expect(lookupAsn("45102")?.category).toBe("datacenter");
    });
    it("Tencent AS132203 is datacenter", () => {
      expect(lookupAsn("132203")?.category).toBe("datacenter");
    });
    it("Scaleway AS12876 is datacenter", () => {
      expect(lookupAsn("12876")?.category).toBe("datacenter");
    });
    it("Contabo AS40021 is datacenter", () => {
      expect(lookupAsn("40021")?.category).toBe("datacenter");
    });
    it("Hostinger AS47583 is datacenter", () => {
      expect(lookupAsn("47583")?.category).toBe("datacenter");
    });
  });

  describe("vpn_proxy", () => {
    it.each([
      ["199218", "ProtonVPN"],
      ["203619", "IVPN"],
      ["209103", "ProtonVPN"],
      ["214879", "SkyVPN"],
      ["216025", "Mullvad"],
      ["57138", "Mullvad"],
      ["397282", "Castle VPN"],
      ["397540", "Windscribe"],
    ])("provider-owned AS%s (%s) is vpn_proxy", (asn, provider) => {
      const e = lookupAsn(asn);
      expect(e?.category).toBe("vpn_proxy");
      expect(e?.org).toContain(provider);
    });

    it("M247 AS9009 is vpn_proxy", () => {
      expect(lookupAsn("9009")?.category).toBe("vpn_proxy");
    });

    it.each(["212238", "57523", "394711", "198093", "212029", "33438"])(
      "does not hard-block stale provider assignment AS%s",
      (asn) => {
        expect(lookupAsn(asn)).toBeNull();
      },
    );
  });

  describe("corporate_proxy", () => {
    it("Zscaler AS22616 is corporate_proxy", () => {
      expect(lookupAsn("22616")?.category).toBe("corporate_proxy");
    });
    it("Zscaler AS62044 is corporate_proxy", () => {
      expect(lookupAsn("62044")?.category).toBe("corporate_proxy");
    });
    it("Zscaler AS398324 is corporate_proxy", () => {
      expect(lookupAsn("398324")?.category).toBe("corporate_proxy");
    });
    it("Cisco Umbrella AS36692 is corporate_proxy", () => {
      expect(lookupAsn("36692")?.category).toBe("corporate_proxy");
    });
    it("Palo Alto Prisma AS396507 is corporate_proxy", () => {
      expect(lookupAsn("396507")?.category).toBe("corporate_proxy");
    });
  });

  describe("privacy_relay (new category)", () => {
    it("Cloudflare AS13335 is privacy_relay (moved from datacenter)", () => {
      const e = lookupAsn("13335");
      expect(e?.category).toBe("privacy_relay");
      expect(e?.org).toBe("Cloudflare");
    });
    it("Cloudflare WARP AS209242 is privacy_relay (moved from corporate_proxy)", () => {
      const e = lookupAsn("209242");
      expect(e?.category).toBe("privacy_relay");
      expect(e?.org).toContain("WARP");
    });
    it("Apple AS714 is privacy_relay", () => {
      const e = lookupAsn("714");
      expect(e?.category).toBe("privacy_relay");
      expect(e?.org).toContain("Apple");
    });
    it("Apple AS6185 is privacy_relay", () => {
      expect(lookupAsn("6185")?.category).toBe("privacy_relay");
    });
    it("Akamai Apple PR egress AS16625 is privacy_relay", () => {
      expect(lookupAsn("16625")?.category).toBe("privacy_relay");
    });
    it("Akamai International AS20940 is privacy_relay", () => {
      expect(lookupAsn("20940")?.category).toBe("privacy_relay");
    });
  });

  describe("mobile", () => {
    it("Verizon Wireless AS6167 is mobile", () => {
      expect(lookupAsn("6167")?.category).toBe("mobile");
    });
    it("T-Mobile AS21928 is mobile", () => {
      expect(lookupAsn("21928")?.category).toBe("mobile");
    });
    it("AT&T Mobility AS20057 is mobile", () => {
      expect(lookupAsn("20057")?.category).toBe("mobile");
    });
    it("Sprint legacy AS10507 is mobile", () => {
      expect(lookupAsn("10507")?.category).toBe("mobile");
    });
    it("Cricket AS19108 is mobile", () => {
      expect(lookupAsn("19108")?.category).toBe("mobile");
    });
    it("US Cellular AS6315 is mobile", () => {
      expect(lookupAsn("6315")?.category).toBe("mobile");
    });
    it("Vodafone UK AS25135 is mobile", () => {
      expect(lookupAsn("25135")?.category).toBe("mobile");
    });
    it("Reliance Jio AS55836 is mobile", () => {
      expect(lookupAsn("55836")?.category).toBe("mobile");
    });
  });

  describe("no collisions across categories", () => {
    // Guard against accidentally duplicating an ASN key in two categories.
    it("Cloudflare 13335 is NOT datacenter anymore (safety against regression)", () => {
      expect(lookupAsn("13335")?.category).not.toBe("datacenter");
    });
    it("Cloudflare WARP 209242 is NOT corporate_proxy anymore", () => {
      expect(lookupAsn("209242")?.category).not.toBe("corporate_proxy");
    });
  });
});
