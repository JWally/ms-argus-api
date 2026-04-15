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
