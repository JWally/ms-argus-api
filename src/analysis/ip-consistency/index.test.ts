import { describe, it, expect } from "vitest";
import { analyzeIpConsistency } from "./index";

/**
 * Helper: build a device shape that satisfies webrtcAvailable() unless
 * the test needs to exercise the blocked path explicitly.
 */
function deviceWithWebrtc(): Record<string, unknown> {
  return { webrtc: { iceCandidates: {} } };
}

/**
 * Helper: build a sigint shape with the given tls and tcp IPs.
 */
function sigint(opts: {
  tlsIp?: string;
  tcpIp?: string;
  asn?: string;
}): Record<string, unknown> {
  return {
    aws_cf: { ip: opts.tlsIp, asn: opts.asn },
    tcp_probe: opts.tcpIp ? { client_ip: opts.tcpIp } : undefined,
  };
}

describe("analyzeIpConsistency — integrity score", () => {
  const device = deviceWithWebrtc();

  it("1.0 — all 4 IPs identical", () => {
    const r = analyzeIpConsistency(
      device,
      sigint({ tlsIp: "1.2.3.4", tcpIp: "1.2.3.4" }),
      "1.2.3.4",
      { ip: "1.2.3.4", forgery: false },
    );
    expect(r.integrity).toBe(1.0);
    expect(r.ip).toBe("1.2.3.4");
  });

  it("1.0 — 3+1 split where the solo is webrtc (classic CGNAT)", () => {
    const r = analyzeIpConsistency(
      device,
      sigint({ tlsIp: "10.0.1.1", tcpIp: "10.0.1.1" }),
      "10.0.1.1",
      { ip: "10.0.2.2", forgery: false },
    );
    expect(r.integrity).toBe(1.0);
    expect(r.ip).toBe("10.0.2.2"); // prefers webrtc for surfacing
  });

  it("0.8 — 3+1 split where the solo is NOT webrtc", () => {
    // webrtc agrees with 2 probes, tcp is the odd one in the same /16
    const r = analyzeIpConsistency(
      device,
      sigint({ tlsIp: "10.0.1.1", tcpIp: "10.0.2.2" }),
      "10.0.1.1",
      { ip: "10.0.1.1", forgery: false },
    );
    expect(r.integrity).toBe(0.8);
    expect(r.ip).toBe("10.0.1.1");
  });

  it("0.7 — 2+2 split, all same /16", () => {
    const r = analyzeIpConsistency(
      device,
      sigint({ tlsIp: "10.0.1.1", tcpIp: "10.0.2.2" }),
      "10.0.1.1",
      { ip: "10.0.2.2", forgery: false },
    );
    expect(r.integrity).toBe(0.7);
  });

  it("0.6 — 3 distinct IPs (2+1+1) in one /16", () => {
    const r = analyzeIpConsistency(
      device,
      sigint({ tlsIp: "10.0.1.1", tcpIp: "10.0.2.2" }),
      "10.0.1.1",
      { ip: "10.0.3.3", forgery: false },
    );
    expect(r.integrity).toBe(0.6);
  });

  it("0.5 — 4 distinct IPs, all same /16 (heavy CGNAT)", () => {
    const r = analyzeIpConsistency(
      device,
      sigint({ tlsIp: "10.0.2.2", tcpIp: "10.0.3.3" }),
      "10.0.1.1",
      { ip: "10.0.4.4", forgery: false },
    );
    expect(r.integrity).toBe(0.5);
  });

  it("0.5 — no webrtc submitted", () => {
    const r = analyzeIpConsistency(
      { webrtc: null },
      sigint({ tlsIp: "1.2.3.4", tcpIp: "1.2.3.4" }),
      "1.2.3.4",
      { ip: null, forgery: false },
    );
    expect(r.integrity).toBe(0.5);
    expect(r.ip).toBe("1.2.3.4"); // falls back to tls/tcp consensus
  });

  it("0.1 — webrtc on a different /16 than probes (proxy-ish)", () => {
    const r = analyzeIpConsistency(
      device,
      sigint({ tlsIp: "1.2.3.4", tcpIp: "1.2.3.4" }),
      "1.2.3.4",
      { ip: "9.9.9.9", forgery: false },
    );
    expect(r.integrity).toBe(0.1);
    expect(r.ip).toBeNull();
  });

  it("0.1 — probes on different /16 from each other", () => {
    const r = analyzeIpConsistency(
      device,
      sigint({ tlsIp: "1.2.3.4", tcpIp: "9.9.9.9" }),
      "1.2.3.4",
      { ip: "1.2.3.4", forgery: false },
    );
    expect(r.integrity).toBe(0.1);
    expect(r.ip).toBeNull();
  });

  it("0.0 — webrtc forgery (MAC invalid)", () => {
    const r = analyzeIpConsistency(
      device,
      sigint({ tlsIp: "1.2.3.4", tcpIp: "1.2.3.4" }),
      "1.2.3.4",
      { ip: null, forgery: true },
    );
    expect(r.integrity).toBe(0.0);
    expect(r.ip).toBeNull();
    expect(r.signals.some((s) => s.code === "WEBRTC_SIGINT_FORGERY")).toBe(
      true,
    );
  });
});

describe("analyzeIpConsistency — signals", () => {
  it("emits SAME_SUBNET_CGNAT when webrtc differs but same /16", () => {
    const r = analyzeIpConsistency(
      deviceWithWebrtc(),
      sigint({ tlsIp: "10.0.1.1", tcpIp: "10.0.1.1" }),
      "10.0.1.1",
      { ip: "10.0.2.2", forgery: false },
    );
    expect(r.signals.some((s) => s.code === "SAME_SUBNET_CGNAT")).toBe(true);
  });

  it("emits WEBRTC_IP_MISMATCH when webrtc off /16", () => {
    const r = analyzeIpConsistency(
      deviceWithWebrtc(),
      sigint({ tlsIp: "1.2.3.4", tcpIp: "1.2.3.4" }),
      "1.2.3.4",
      { ip: "9.9.9.9", forgery: false },
    );
    expect(r.signals.some((s) => s.code === "WEBRTC_IP_MISMATCH")).toBe(true);
  });

  it("emits WEBRTC_BLOCKED when device.webrtc is absent", () => {
    const r = analyzeIpConsistency(
      {},
      sigint({ tlsIp: "1.2.3.4", tcpIp: "1.2.3.4" }),
      "1.2.3.4",
      { ip: null, forgery: false },
    );
    expect(r.signals.some((s) => s.code === "WEBRTC_BLOCKED")).toBe(true);
  });

  it("does NOT emit ASN anomaly for mobile carriers (mobile is context)", () => {
    const r = analyzeIpConsistency(
      deviceWithWebrtc(),
      sigint({ tlsIp: "1.2.3.4", tcpIp: "1.2.3.4", asn: "21928" }),
      "1.2.3.4",
      { ip: "1.2.3.4", forgery: false },
    );
    expect(r.asn.category).toBe("mobile");
    expect(r.signals.some((s) => s.code === "IP_PROBE_SCATTER")).toBe(false);
  });

  it("still emits ASN anomaly for datacenter ASNs", () => {
    const r = analyzeIpConsistency(
      deviceWithWebrtc(),
      sigint({ tlsIp: "1.2.3.4", tcpIp: "1.2.3.4", asn: "16509" }),
      "1.2.3.4",
      { ip: "1.2.3.4", forgery: false },
    );
    expect(r.asn.category).toBe("datacenter");
    expect(r.signals.some((s) => s.code === "IP_PROBE_SCATTER")).toBe(true);
  });
});

describe("analyzeIpConsistency — IP surfacing", () => {
  it("surfaces webrtc IP at score >= 0.5 when present", () => {
    const r = analyzeIpConsistency(
      deviceWithWebrtc(),
      sigint({ tlsIp: "1.2.3.4", tcpIp: "1.2.3.4" }),
      "1.2.3.4",
      { ip: "1.2.3.4", forgery: false },
    );
    expect(r.integrity).toBe(1.0);
    expect(r.ip).toBe("1.2.3.4");
  });

  it("surfaces tls IP fallback when no webrtc", () => {
    const r = analyzeIpConsistency(
      { webrtc: null },
      sigint({ tlsIp: "5.6.7.8", tcpIp: "5.6.7.8" }),
      "5.6.7.8",
      { ip: null, forgery: false },
    );
    expect(r.integrity).toBe(0.5);
    expect(r.ip).toBe("5.6.7.8");
  });

  it("never surfaces an IP at score < 0.5", () => {
    const r = analyzeIpConsistency(
      deviceWithWebrtc(),
      sigint({ tlsIp: "1.2.3.4", tcpIp: "1.2.3.4" }),
      "1.2.3.4",
      { ip: null, forgery: true },
    );
    expect(r.integrity).toBe(0.0);
    expect(r.ip).toBeNull();
  });
});

describe("analyzeIpConsistency — network_class CIDR-overlay ordering", () => {
  it("server-observed probe IP wins over a leaky webrtc IP for classification", () => {
    // TLS/TCP probes hit a mobile CIDR; webrtc leaks the user's AT&T
    // residential IP. The classifier must prefer the probe IPs — webrtc is
    // what's BEHIND the proxy, not what the upstream sees. Hand-curated
    // overlay only here so the test doesn't depend on S3-backed auto-overlay.
    const r = analyzeIpConsistency(
      deviceWithWebrtc(),
      sigint({ tlsIp: "172.56.0.1", tcpIp: "172.56.0.1" }),
      "172.56.0.1",
      { ip: "108.192.0.1", forgery: false }, // webrtc on AT&T residential
    );
    // 172.56.0.0/14 → mobile (T-Mobile). Old order [webrtc, tls, tcp, api]
    // would have matched 108.192.0.0/10 → residential first.
    expect(r.asn.network_class).toBe("mobile");
  });

  it("ASN dict beats lower-priority IP's CIDR hit when probe IPs miss CIDR", async () => {
    // Cisco Umbrella session through a PoP not yet in the auto-overlay
    // (e.g. 155.190.7.x — the Minneapolis PoP). Probe IPs miss CIDR
    // entirely; apiIp/webrtcIp leak the user's residential 107.210.133.x
    // (matched by the hand-curated AT&T 107.192.0.0/11 → residential).
    // The classifier must consult the ASN dict (which has 36692 →
    // security_filter) BEFORE falling through to the residential CIDR
    // hit on the leaked low-priority IP.
    const { _seedCacheForTesting, _resetCacheForTesting } =
      await import("../../services/network/asn-classifier");
    _seedCacheForTesting({ "36692": "security_filter" });
    try {
      const r = analyzeIpConsistency(
        deviceWithWebrtc(),
        sigint({
          tlsIp: "155.190.7.96",
          tcpIp: "155.190.7.96",
          asn: "36692",
        }),
        "107.210.133.127",
        { ip: "107.210.133.127", forgery: false },
      );
      expect(r.asn.network_class).toBe("security_filter");
    } finally {
      _resetCacheForTesting();
    }
  });

  it("higher-priority IP's auto-overlay hit beats lower-priority IP's hand-curated hit", async () => {
    // Cisco Umbrella regression: probes hit 155.190.18.x (security_filter,
    // auto-overlay only — no hand-curated rule), webrtc/api leak the user's
    // residential 107.210.133.x (matched by the hand-curated AT&T U-Verse
    // 107.192.0.0/11 → residential). Pre-fix, hand-curated was tried for
    // ALL IPs before auto-overlay, so residential won despite being on a
    // lower-priority IP. Post-fix, the per-IP-then-per-source walk picks
    // up the auto-overlay hit on the high-priority probe IP first.
    const { _seedAutoOverlayForTesting, _resetAutoOverlayForTesting } =
      await import("../../services/network/auto-overlay");
    _seedAutoOverlayForTesting([
      { cidr: "155.190.18.0/24", category: "security_filter", name: "CIE-US" },
    ]);
    try {
      const r = analyzeIpConsistency(
        deviceWithWebrtc(),
        sigint({ tlsIp: "155.190.18.45", tcpIp: "155.190.18.45" }),
        "107.210.133.127",
        { ip: "107.210.133.127", forgery: false },
      );
      expect(r.asn.network_class).toBe("security_filter");
    } finally {
      _resetAutoOverlayForTesting();
    }
  });
});

describe("analyzeIpConsistency — asn.org resolution", () => {
  it("falls back to the dynamic dict org when the static catalog has no entry", async () => {
    // ASN 7018 (AT&T) isn't in the static catalog (asn-catalog.ts), but
    // appears in the IPtoASN dataset that ip-class-builder writes to S3.
    // Pre-fix, asn.org was null. Post-fix, the dynamic dict provides the
    // long-tail name.
    const { _seedCacheForTesting, _resetCacheForTesting } =
      await import("../../services/network/asn-classifier");
    _seedCacheForTesting({}, { "7018": "AT&T Services, Inc." });
    try {
      const r = analyzeIpConsistency(
        deviceWithWebrtc(),
        sigint({
          tlsIp: "107.210.133.127",
          tcpIp: "107.210.133.127",
          asn: "7018",
        }),
        "107.210.133.127",
        { ip: "107.210.133.127", forgery: false },
      );
      expect(r.asn.org).toBe("AT&T Services, Inc.");
      expect(r.asn.number).toBe("7018");
    } finally {
      _resetCacheForTesting();
    }
  });

  it("static catalog wins over the dynamic dict (hand-curated names are cleaner)", async () => {
    // ASN 16509 (Amazon) is in the static catalog as "Amazon.com". Even if
    // the dict has a different value (raw IPtoASN strings can be ugly),
    // the static catalog should win.
    const { _seedCacheForTesting, _resetCacheForTesting } =
      await import("../../services/network/asn-classifier");
    _seedCacheForTesting({}, { "16509": "AMAZON-02-IPV4-ALLOC" });
    try {
      const r = analyzeIpConsistency(
        deviceWithWebrtc(),
        sigint({ tlsIp: "1.2.3.4", tcpIp: "1.2.3.4", asn: "16509" }),
        "1.2.3.4",
        { ip: "1.2.3.4", forgery: false },
      );
      expect(r.asn.org).toBe("Amazon.com");
    } finally {
      _resetCacheForTesting();
    }
  });

  it("returns null when both sources miss", () => {
    const r = analyzeIpConsistency(
      deviceWithWebrtc(),
      sigint({ tlsIp: "1.2.3.4", tcpIp: "1.2.3.4", asn: "999999" }),
      "1.2.3.4",
      { ip: "1.2.3.4", forgery: false },
    );
    expect(r.asn.org).toBeNull();
  });
});
