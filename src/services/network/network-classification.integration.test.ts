/**
 * Integration tests for the full network-classification evidence chain.
 *
 * Exercises analyzeIpConsistency end-to-end across all evidence sources:
 *   1. Dynamic ASN dataset (asn-classifier)            — fastest, broadest
 *   2. CIDR overlay (cidr-overlay)                     — mixed-use ASNs
 *   3. Legacy ASN catalog (asn-catalog)                — VPN/datacenter
 *   4. SAME_SUBNET_CGNAT signal (ip-consistency)       — cellular tell
 *
 * Fixtures are derived from real archive data validated on 2026-04-25
 * (17/18 agreement between the WebRTC-split signal and rDNS classification
 * across AT&T 7018 iPhone sessions). The cellular pattern is the canonical
 * "TCP IP and WebRTC IP differ within same /16" footprint.
 *
 * These tests are the regression guard for the policy: "an iPhone on AT&T
 * cellular and the same iPhone on AT&T home wifi must classify differently
 * even though they share ASN 7018." This is the headline correctness
 * requirement of the entire feature.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { analyzeIpConsistency } from "../../analysis/ip-consistency";
import {
  _resetCacheForTesting,
  _seedCacheForTesting,
  type NetworkCategory,
} from "./asn-classifier";

/** Realistic device shape that satisfies webrtcAvailable(). */
function device(): Record<string, unknown> {
  return { webrtc: { iceCandidates: {} } };
}

/** Build a sigint payload with the given IPs and CF ASN. */
function sigint(opts: {
  tlsIp?: string | null;
  tcpIp?: string | null;
  asn?: string | null;
}): Record<string, unknown> {
  return {
    aws_cf: { ip: opts.tlsIp ?? undefined, asn: opts.asn ?? undefined },
    tcp_probe: opts.tcpIp ? { client_ip: opts.tcpIp } : undefined,
  };
}

/** Helper: run the analyzer with the standard sigint shape + a webrtc IP. */
function analyze(opts: {
  cfIp: string | null;
  tcpIp: string | null;
  webrtcIp: string | null;
  asn: string | null;
}) {
  return analyzeIpConsistency(
    device(),
    sigint({ tlsIp: opts.cfIp, tcpIp: opts.tcpIp, asn: opts.asn }),
    opts.cfIp ?? "",
    opts.webrtcIp
      ? { ip: opts.webrtcIp, forgery: false }
      : { ip: null, forgery: false },
  );
}

beforeEach(() => _resetCacheForTesting());
afterEach(() => _resetCacheForTesting());

// ────────────────────────────────────────────────────────────────────────
//  Headline regression: AT&T 7018 mobile vs residential disambiguation
// ────────────────────────────────────────────────────────────────────────

describe("AT&T 7018 — same ASN, different physical networks", () => {
  it("home wifi (107.210.133.127): all IPs match → residential, no CGNAT signal", () => {
    const r = analyze({
      cfIp: "107.210.133.127",
      tcpIp: "107.210.133.127",
      webrtcIp: "107.210.133.127",
      asn: "7018",
    });
    expect(r.asn.network_class).toBe("residential");
    expect(r.signals.some((s) => s.code === "SAME_SUBNET_CGNAT")).toBe(false);
    expect(r.integrity).toBe(1.0);
    expect(r.ip).toBe("107.210.133.127");
  });

  it("cellular (107.116.185.73 vs 107.116.156.97): split /20 → mobile + SAME_SUBNET_CGNAT", () => {
    // Real archive fixture from the 2026-04-12 AT&T iPhone session
    const r = analyze({
      cfIp: "107.116.185.73",
      tcpIp: "107.116.185.73",
      webrtcIp: "107.116.156.97",
      asn: "7018",
    });
    expect(r.asn.network_class).toBe("mobile");
    expect(r.signals.some((s) => s.code === "SAME_SUBNET_CGNAT")).toBe(true);
    // Per the integrity-score table, 3+1 split where the solo IS webrtc and
    // it lies on the same /16 as the probes is the "classic mobile-CGNAT"
    // pattern — scored 1.0, not penalised.
    expect(r.integrity).toBe(1.0);
  });

  it("cellular (107.115.171.50 vs 107.115.176.65): another archive fixture → mobile", () => {
    const r = analyze({
      cfIp: "107.115.171.50",
      tcpIp: "107.115.171.50",
      webrtcIp: "107.115.176.65",
      asn: "7018",
    });
    expect(r.asn.network_class).toBe("mobile");
    expect(r.signals.some((s) => s.code === "SAME_SUBNET_CGNAT")).toBe(true);
  });

  it("U-Verse Houston (99.100.141.186) → residential via overlay", () => {
    const r = analyze({
      cfIp: "99.100.141.186",
      tcpIp: "99.100.141.186",
      webrtcIp: "99.100.141.186",
      asn: "7018",
    });
    expect(r.asn.network_class).toBe("residential");
  });

  it("U-Verse Fresno (108.243.197.41) → residential via overlay", () => {
    const r = analyze({
      cfIp: "108.243.197.41",
      tcpIp: "108.243.197.41",
      webrtcIp: "108.243.197.41",
      asn: "7018",
    });
    expect(r.asn.network_class).toBe("residential");
  });
});

// ────────────────────────────────────────────────────────────────────────
//  Other carriers — verify each ASN→category path
// ────────────────────────────────────────────────────────────────────────

describe("Other-carrier classification via dataset / overlay", () => {
  it("T-Mobile cellular (172.58.x) → mobile via overlay (no dataset needed)", () => {
    const r = analyze({
      cfIp: "172.58.11.182",
      tcpIp: "172.58.11.182",
      webrtcIp: "172.58.11.182",
      asn: "21928",
    });
    expect(r.asn.network_class).toBe("mobile");
  });

  it("Verizon Wireless (174.193.x) → mobile via overlay (signed-int32 trap area)", () => {
    const r = analyze({
      cfIp: "174.193.0.1",
      tcpIp: "174.193.0.1",
      webrtcIp: "174.193.0.1",
      asn: "6167",
    });
    expect(r.asn.network_class).toBe("mobile");
  });

  it("Comcast residential (73.43.1.77) → residential via dataset (with seed)", () => {
    _seedCacheForTesting({ "7922": "residential" });
    const r = analyze({
      cfIp: "73.43.1.77",
      tcpIp: "73.43.1.77",
      webrtcIp: "73.43.1.77",
      asn: "7922",
    });
    expect(r.asn.network_class).toBe("residential");
  });

  it("Starlink (143.105.85.139) → satellite via overlay", () => {
    const r = analyze({
      cfIp: "143.105.85.139",
      tcpIp: "143.105.85.139",
      webrtcIp: "143.105.85.139",
      asn: "14593",
    });
    expect(r.asn.network_class).toBe("satellite");
  });

  it("AWS EC2 (52.32.41.53) → datacenter via legacy AsnCategory fallback", () => {
    // Dataset is empty, overlay doesn't cover AWS, but ASN 16509 is in the
    // legacy static catalog as datacenter — that fallback should fire.
    const r = analyze({
      cfIp: "52.32.41.53",
      tcpIp: "52.32.41.53",
      webrtcIp: "52.32.41.53",
      asn: "16509",
    });
    expect(r.asn.network_class).toBe("datacenter");
  });

  it("NordVPN backbone (149.22.84.135 ASN 212238) → vpn_proxy via legacy catalog", () => {
    const r = analyze({
      cfIp: "149.22.84.135",
      tcpIp: "149.22.84.135",
      webrtcIp: "149.22.84.135",
      asn: "212238",
    });
    expect(r.asn.network_class).toBe("vpn_proxy");
  });
});

// ────────────────────────────────────────────────────────────────────────
//  Evidence-priority: dataset > overlay > legacy catalog
// ────────────────────────────────────────────────────────────────────────

describe("Evidence priority — dataset > CIDR overlay > legacy catalog", () => {
  it("dataset hit wins over CIDR overlay", () => {
    // 107.116.185.73 is in the AT&T cellular CIDR overlay (mobile). If
    // we seed the dataset with ASN 7018 → "residential", the dataset wins
    // (overlay never consulted) per deriveNetworkClass's resolution order.
    _seedCacheForTesting({ "7018": "residential" });
    const r = analyze({
      cfIp: "107.116.185.73",
      tcpIp: "107.116.185.73",
      webrtcIp: "107.116.185.73",
      asn: "7018",
    });
    expect(r.asn.network_class).toBe("residential");
  });

  it("dataset miss → CIDR overlay wins over legacy catalog", () => {
    // 107.116.185.73 → AT&T cellular per overlay. Legacy catalog has no
    // entry for ASN 7018 (it falls through to the default residential
    // fallback in checkAsnCategory). Overlay should win.
    const r = analyze({
      cfIp: "107.116.185.73",
      tcpIp: "107.116.185.73",
      webrtcIp: "107.116.185.73",
      asn: "7018",
    });
    expect(r.asn.network_class).toBe("mobile");
  });

  it("dataset and overlay both miss → legacy catalog (datacenter ASN) wins", () => {
    const r = analyze({
      cfIp: "1.2.3.4",
      tcpIp: "1.2.3.4",
      webrtcIp: "1.2.3.4",
      asn: "16509", // AWS in legacy catalog
    });
    expect(r.asn.network_class).toBe("datacenter");
  });

  it("everything misses → null network_class (no false confidence)", () => {
    // Some random unknown ASN with no overlay coverage and no legacy entry.
    const r = analyze({
      cfIp: "1.2.3.4",
      tcpIp: "1.2.3.4",
      webrtcIp: "1.2.3.4",
      asn: "99999999",
    });
    expect(r.asn.network_class).toBeNull();
  });

  it("no ASN at all → null network_class", () => {
    const r = analyze({
      cfIp: "1.2.3.4",
      tcpIp: "1.2.3.4",
      webrtcIp: null,
      asn: null,
    });
    expect(r.asn.network_class).toBeNull();
  });
});

// ────────────────────────────────────────────────────────────────────────
//  WebRTC-split signal × network_class — they should AGREE on cellular
// ────────────────────────────────────────────────────────────────────────

describe("WebRTC-split + network_class cross-validation", () => {
  it("agree → cellular: SAME_SUBNET_CGNAT fires AND network_class=mobile", () => {
    // The empirical 17/18 case: when these two independent signals agree,
    // confidence is very high.
    const r = analyze({
      cfIp: "107.116.185.73",
      tcpIp: "107.116.185.73",
      webrtcIp: "107.116.156.97",
      asn: "7018",
    });
    expect(r.signals.some((s) => s.code === "SAME_SUBNET_CGNAT")).toBe(true);
    expect(r.asn.network_class).toBe("mobile");
  });

  it("agree → wifi: no CGNAT signal AND network_class=residential", () => {
    const r = analyze({
      cfIp: "107.210.133.127",
      tcpIp: "107.210.133.127",
      webrtcIp: "107.210.133.127",
      asn: "7018",
    });
    expect(r.signals.some((s) => s.code === "SAME_SUBNET_CGNAT")).toBe(false);
    expect(r.asn.network_class).toBe("residential");
  });

  it("conflict → CGNAT signal fires on a residential AT&T IP (anomaly indicator)", () => {
    // Residential AT&T IP 107.210.133.127 with a fake split webrtc IP in
    // the same /16. The CGNAT signal will fire (because /16 matches), but
    // network_class will say "residential" (because the CIDR overlay puts
    // 107.210.x in U-Verse). Disagreement worth investigating.
    const r = analyze({
      cfIp: "107.210.133.127",
      tcpIp: "107.210.133.127",
      webrtcIp: "107.210.50.50",
      asn: "7018",
    });
    expect(r.signals.some((s) => s.code === "SAME_SUBNET_CGNAT")).toBe(true);
    // network_class is decided by CIDR overlay alone — overlay says
    // residential for this IP. The signal disagreement is what tells the
    // detector something's off; the merchant payload carries both pieces.
    expect(r.asn.network_class).toBe("residential");
  });

  it("WebRTC IP off /16 → WEBRTC_IP_MISMATCH (proxy), not CGNAT", () => {
    const r = analyze({
      cfIp: "107.116.185.73",
      tcpIp: "107.116.185.73",
      webrtcIp: "8.8.8.8", // way off /16 — proxy leak
      asn: "7018",
    });
    expect(r.signals.some((s) => s.code === "WEBRTC_IP_MISMATCH")).toBe(true);
    expect(r.signals.some((s) => s.code === "SAME_SUBNET_CGNAT")).toBe(false);
    // network_class still reflects the AT&T CIDR overlay (mobile), since
    // the cf_ip / tcp_ip is in the AT&T cellular pool — what the merchant
    // would care about is the WEBRTC_IP_MISMATCH anomaly and the /16
    // disagreement that drove integrity to 0.1 below.
    expect(r.asn.network_class).toBe("mobile");
    expect(r.integrity).toBeLessThanOrEqual(0.1);
  });
});

// ────────────────────────────────────────────────────────────────────────
//  Invariants — properties that must hold across all classifications
// ────────────────────────────────────────────────────────────────────────

describe("Invariants", () => {
  it("network_class is always one of the documented enum values or null", () => {
    const allowed: (NetworkCategory | null)[] = [
      "mobile",
      "residential",
      "datacenter",
      "vpn_proxy",
      "hosting_proxy",
      "cdn",
      "satellite",
      "privacy_relay",
      "security_filter",
      "business",
      "education",
      "government",
      "unknown",
      null,
    ];
    const cases = [
      { cfIp: "107.116.185.73", asn: "7018" },
      { cfIp: "107.210.133.127", asn: "7018" },
      { cfIp: "172.58.11.182", asn: "21928" },
      { cfIp: "52.32.41.53", asn: "16509" },
      { cfIp: "143.105.85.139", asn: "14593" },
      { cfIp: "1.2.3.4", asn: "99999999" },
      { cfIp: "100.64.5.5", asn: null },
    ];
    for (const c of cases) {
      const r = analyze({
        cfIp: c.cfIp,
        tcpIp: c.cfIp,
        webrtcIp: c.cfIp,
        asn: c.asn,
      });
      expect(allowed).toContain(r.asn.network_class);
    }
  });

  it("CGNAT signal NEVER fires when all IPs match (no /16 to compare)", () => {
    const r = analyze({
      cfIp: "107.116.185.73",
      tcpIp: "107.116.185.73",
      webrtcIp: "107.116.185.73",
      asn: "7018",
    });
    expect(r.signals.some((s) => s.code === "SAME_SUBNET_CGNAT")).toBe(false);
  });

  it("classification is deterministic across repeated calls", () => {
    const args = {
      cfIp: "107.116.185.73",
      tcpIp: "107.116.185.73",
      webrtcIp: "107.116.156.97",
      asn: "7018",
    };
    const a = analyze(args);
    const b = analyze(args);
    expect(a.asn.network_class).toBe(b.asn.network_class);
    expect(a.integrity).toBe(b.integrity);
    expect(a.signals.length).toBe(b.signals.length);
  });
});
