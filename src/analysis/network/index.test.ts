import { describe, it, expect } from "vitest";
import { analyzeNetworkProbes } from "./index";

/** Helper — build a minimal sigint with snd_mss and optional rtt values. */
function sigint(opts: {
  sndMss?: number | null;
  rtt?: number | null;
  rcvRtt?: number | null;
}): unknown {
  const rtt_fingerprint: Record<string, number> = {};
  if (opts.sndMss != null) rtt_fingerprint.snd_mss = opts.sndMss;
  if (opts.rtt != null) rtt_fingerprint.rtt_refreshed = opts.rtt;
  if (opts.rcvRtt != null) rtt_fingerprint.rcv_rtt_refreshed = opts.rcvRtt;
  return { tcp_probe: { rtt_fingerprint } };
}

describe("analyzeNetworkProbes — MSS-only path (no ASN category)", () => {
  it("returns zero components when tcp_probe is missing", () => {
    const r = analyzeNetworkProbes(undefined);
    expect(r.vpn_component).toBe(0);
    expect(r.proxy_component).toBe(0);
    expect(r.proxy_score).toBe(0);
  });

  it("returns zero vpn_component when MSS >= 1440 (normal ethernet)", () => {
    const r = analyzeNetworkProbes(sigint({ sndMss: 1460 }));
    expect(r.vpn_component).toBe(0);
  });

  it("returns zero vpn_component when MSS == 1440 (boundary, PPPoE tolerant)", () => {
    const r = analyzeNetworkProbes(sigint({ sndMss: 1440 }));
    expect(r.vpn_component).toBe(0);
  });

  it("returns 0.43 for MSS 1380 (typical WireGuard default)", () => {
    const r = analyzeNetworkProbes(sigint({ sndMss: 1380 }));
    expect(r.vpn_component).toBeCloseTo((1440 - 1380) / 140, 2);
    expect(r.vpn_component).toBeCloseTo(0.43, 2);
  });

  it("saturates at 1.0 for MSS <= 1300 (heavy tunnel)", () => {
    expect(analyzeNetworkProbes(sigint({ sndMss: 1300 })).vpn_component).toBe(
      1,
    );
    expect(analyzeNetworkProbes(sigint({ sndMss: 1200 })).vpn_component).toBe(
      1,
    );
  });

  it("computes proxy_component from rcv_rtt / rtt ratio", () => {
    const r = analyzeNetworkProbes(
      sigint({ sndMss: 1460, rtt: 50000, rcvRtt: 150000 }),
    );
    expect(r.proxy_component).toBeCloseTo((3 - 1) / 2, 2); // saturates at 1 (ratio=3)
    expect(r.proxy_component).toBe(1);
  });

  it("proxy_component is 0 when ratio == 1", () => {
    const r = analyzeNetworkProbes(
      sigint({ sndMss: 1460, rtt: 50000, rcvRtt: 50000 }),
    );
    expect(r.proxy_component).toBe(0);
  });

  it("noisy-OR combines components", () => {
    const r = analyzeNetworkProbes(
      sigint({ sndMss: 1380, rtt: 50000, rcvRtt: 100000 }),
    );
    // vpn = 0.43, proxy ≈ 0.5
    // combined = 1 - (1 - 0.43) * (1 - 0.5) = 0.715
    expect(r.proxy_score).toBeCloseTo(0.715, 2);
  });

  it("handles null asnCategory identically to absent asnCategory", () => {
    const a = analyzeNetworkProbes(sigint({ sndMss: 1400 }));
    const b = analyzeNetworkProbes(sigint({ sndMss: 1400 }), null);
    const c = analyzeNetworkProbes(sigint({ sndMss: 1400 }), undefined);
    expect(a.vpn_component).toBe(b.vpn_component);
    expect(a.vpn_component).toBe(c.vpn_component);
  });
});

describe("analyzeNetworkProbes — ASN category override", () => {
  describe("datacenter → vpn_component 1.0", () => {
    it("datacenter overrides high MSS (clean-looking WG exit)", () => {
      // This is the WG-MTU-1440 case: MSS ~1400 → 0.29 on MSS alone
      const r = analyzeNetworkProbes(sigint({ sndMss: 1400 }), "datacenter");
      expect(r.vpn_component).toBe(1.0);
    });

    it("datacenter with null MSS still produces 1.0", () => {
      const r = analyzeNetworkProbes({ tcp_probe: {} }, "datacenter");
      expect(r.vpn_component).toBe(1.0);
    });

    it("datacenter with MSS 1460 (as if direct) still produces 1.0", () => {
      const r = analyzeNetworkProbes(sigint({ sndMss: 1460 }), "datacenter");
      expect(r.vpn_component).toBe(1.0);
    });

    it("datacenter with low MSS takes max (stays 1.0)", () => {
      const r = analyzeNetworkProbes(sigint({ sndMss: 1300 }), "datacenter");
      expect(r.vpn_component).toBe(1.0);
    });

    it("datacenter produces CATEGORY_VPN signal", () => {
      const r = analyzeNetworkProbes(sigint({ sndMss: 1400 }), "datacenter");
      expect(r.signals.some((s) => s.code === "CATEGORY_VPN")).toBe(true);
    });
  });

  describe("vpn_proxy → vpn_component 1.0", () => {
    it("vpn_proxy produces 1.0 regardless of MSS", () => {
      const r = analyzeNetworkProbes(sigint({ sndMss: 1460 }), "vpn_proxy");
      expect(r.vpn_component).toBe(1.0);
    });

    it("vpn_proxy produces CATEGORY_VPN signal", () => {
      const r = analyzeNetworkProbes(sigint({ sndMss: 1460 }), "vpn_proxy");
      expect(r.signals.some((s) => s.code === "CATEGORY_VPN")).toBe(true);
    });
  });

  describe("privacy_relay → vpn_component 0.5 (not auto-fail)", () => {
    it("privacy_relay with clean MSS produces 0.5", () => {
      const r = analyzeNetworkProbes(sigint({ sndMss: 1460 }), "privacy_relay");
      expect(r.vpn_component).toBe(0.5);
    });

    it("privacy_relay produces CATEGORY_PRIVACY_RELAY signal (not CATEGORY_VPN)", () => {
      const r = analyzeNetworkProbes(sigint({ sndMss: 1460 }), "privacy_relay");
      expect(r.signals.some((s) => s.code === "CATEGORY_PRIVACY_RELAY")).toBe(
        true,
      );
      expect(r.signals.some((s) => s.code === "CATEGORY_VPN")).toBe(false);
    });

    it("privacy_relay with low MSS takes max (MSS wins)", () => {
      // User on WireGuard tunneled over Apple Private Relay would show
      // low MSS AND privacy_relay ASN — take the stronger signal.
      const r = analyzeNetworkProbes(sigint({ sndMss: 1300 }), "privacy_relay");
      expect(r.vpn_component).toBe(1.0);
    });
  });

  describe("corporate_proxy → no override (real employees)", () => {
    it("corporate_proxy does not force vpn_component", () => {
      const r = analyzeNetworkProbes(
        sigint({ sndMss: 1460 }),
        "corporate_proxy",
      );
      expect(r.vpn_component).toBe(0);
    });
    it("corporate_proxy falls through to MSS math", () => {
      const r = analyzeNetworkProbes(
        sigint({ sndMss: 1380 }),
        "corporate_proxy",
      );
      expect(r.vpn_component).toBeCloseTo(0.43, 2);
    });
    it("corporate_proxy does not emit CATEGORY_VPN signal", () => {
      const r = analyzeNetworkProbes(
        sigint({ sndMss: 1460 }),
        "corporate_proxy",
      );
      expect(r.signals.some((s) => s.code === "CATEGORY_VPN")).toBe(false);
    });
  });

  describe("mobile → no override (cellular is context, not threat)", () => {
    it("mobile does not force vpn_component", () => {
      const r = analyzeNetworkProbes(sigint({ sndMss: 1376 }), "mobile");
      // Cellular MSS is low naturally; rely on MSS math as before.
      expect(r.vpn_component).toBeCloseTo(0.457, 2);
    });
    it("mobile does not emit CATEGORY_VPN signal", () => {
      const r = analyzeNetworkProbes(sigint({ sndMss: 1376 }), "mobile");
      expect(r.signals.some((s) => s.code === "CATEGORY_VPN")).toBe(false);
    });
  });
});

describe("analyzeNetworkProbes — signals", () => {
  it("includes categoryHit evidence string referencing the asn category", () => {
    const r = analyzeNetworkProbes(sigint({ sndMss: 1400 }), "datacenter");
    const sig = r.signals.find((s) => s.code === "CATEGORY_VPN");
    expect(sig?.evidence).toContain("datacenter");
  });

  it("does not emit category signal for unclassified (null) category", () => {
    const r = analyzeNetworkProbes(sigint({ sndMss: 1400 }), null);
    expect(r.signals.some((s) => s.code === "CATEGORY_VPN")).toBe(false);
    expect(r.signals.some((s) => s.code === "CATEGORY_PRIVACY_RELAY")).toBe(
      false,
    );
  });
});

describe("analyzeNetworkProbes — proxy_score combinations", () => {
  it("datacenter + clean ratio → proxy_score still 1.0 via vpn fusion", () => {
    // noisy-OR with vpn=1.0 forces combined=1.0
    const r = analyzeNetworkProbes(
      sigint({ sndMss: 1460, rtt: 50000, rcvRtt: 50000 }),
      "datacenter",
    );
    expect(r.proxy_score).toBe(1);
  });

  it("privacy_relay + clean everything → proxy_score 0.5", () => {
    const r = analyzeNetworkProbes(
      sigint({ sndMss: 1460, rtt: 50000, rcvRtt: 50000 }),
      "privacy_relay",
    );
    // vpn=0.5, proxy=0 → combined = 1 - (1-0.5)*(1-0) = 0.5
    expect(r.proxy_score).toBe(0.5);
  });

  it("privacy_relay + elevated ratio → proxy_score reflects both", () => {
    const r = analyzeNetworkProbes(
      sigint({ sndMss: 1460, rtt: 50000, rcvRtt: 100000 }),
      "privacy_relay",
    );
    // vpn=0.5, proxy≈0.5 → combined ≈ 0.75
    expect(r.proxy_score).toBeCloseTo(0.75, 1);
  });
});

describe("analyzeNetworkProbes — real-world session replays", () => {
  it("WG MTU=1440 through EC2 (the exact session we just tested)", () => {
    // Observed: snd_mss=1388, ratio=0.92, asn=datacenter
    const r = analyzeNetworkProbes(
      sigint({ sndMss: 1388, rtt: 36820, rcvRtt: 34000 }),
      "datacenter",
    );
    expect(r.vpn_component).toBe(1.0); // category override
    expect(r.proxy_component).toBe(0); // clean ratio
    expect(r.proxy_score).toBe(1.0); // driven by vpn category
  });

  it("SOAX cellular proxy session (pre-change: FN; post-change: still caught via waterfall path)", () => {
    // Observed: snd_mss=1376, ratio=2.97, asn=mobile (from 75.210.100.127)
    // ASN is "mobile" so NO category override — MSS math applies.
    const r = analyzeNetworkProbes(
      sigint({ sndMss: 1376, rtt: 48884, rcvRtt: 145000 }),
      "mobile",
    );
    expect(r.vpn_component).toBeCloseTo(0.457, 2);
    expect(r.proxy_component).toBeCloseTo(0.98, 1); // ratio 2.97 nearly saturates
  });

  it("Direct home fiber + PPPoE baseline (legit user)", () => {
    // Typical US cable MSS=1448, direct RTT, no VPN, ratio exactly 1.0
    const r = analyzeNetworkProbes(
      sigint({ sndMss: 1448, rtt: 30000, rcvRtt: 30000 }),
    );
    expect(r.vpn_component).toBe(0);
    expect(r.proxy_component).toBe(0);
    expect(r.proxy_score).toBe(0);
  });

  it("Mullvad-style aggressive VPN (MSS 1340, no catalog hit)", () => {
    // Someone on Mullvad through an ASN we don't catalog — MSS alone catches
    const r = analyzeNetworkProbes(sigint({ sndMss: 1340 }));
    expect(r.vpn_component).toBeCloseTo((1440 - 1340) / 140, 2); // ~0.71
  });

  it("Mullvad provider network (AS216025 is vpn_proxy) forces 1.0", () => {
    const r = analyzeNetworkProbes(sigint({ sndMss: 1340 }), "vpn_proxy");
    expect(r.vpn_component).toBe(1.0);
  });
});
