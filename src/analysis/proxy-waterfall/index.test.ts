import { describe, it, expect } from "vitest";
import { classifyProxy, sharedPrefixBits } from "./index";

describe("sharedPrefixBits", () => {
  it("identical IPs share /32", () => {
    expect(sharedPrefixBits("1.2.3.4", "1.2.3.4")).toBe(32);
  });
  it("AT&T iPhone case — 107.116.185 vs 107.116.156 share /18", () => {
    expect(sharedPrefixBits("107.116.185.73", "107.116.156.97")).toBe(18);
  });
  it("cross-ISP share /5", () => {
    expect(sharedPrefixBits("108.243.197.41", "107.210.133.127")).toBe(5);
  });
  it("malformed returns null", () => {
    expect(sharedPrefixBits("not-an-ip", "1.2.3.4")).toBeNull();
  });
});

describe("classifyProxy", () => {
  const base = {
    tcpIp: null as string | null,
    webrtcIp: null as string | null,
    webrtcStatus: "ok" as const,
    rttRatio: null as number | null,
  };

  it("rule 0 — forgery → KILL", () => {
    const r = classifyProxy({ ...base, webrtcStatus: "forgery" });
    expect(r.verdict).toBe("KILL");
    expect(r.rule).toBe(0);
  });

  it("rule 0 — parse_fail → KILL", () => {
    const r = classifyProxy({ ...base, webrtcStatus: "parse_fail" });
    expect(r.verdict).toBe("KILL");
    expect(r.rule).toBe(0);
  });

  it("rule 1 — UDP == TCP → SAFE", () => {
    const r = classifyProxy({
      ...base,
      tcpIp: "1.2.3.4",
      webrtcIp: "1.2.3.4",
      rttRatio: 5.0, // even with high ratio
    });
    expect(r.verdict).toBe("SAFE");
    expect(r.rule).toBe(1);
  });

  it("rule 2 — freak veto: low ratio, wildly different IPs → SAFE", () => {
    const r = classifyProxy({
      ...base,
      tcpIp: "108.243.197.41",
      webrtcIp: "107.210.133.127",
      rttRatio: 0.95,
    });
    expect(r.verdict).toBe("SAFE");
    expect(r.rule).toBe(2);
  });

  it("rule 3 — cellular CGNAT (/24 same, ratio < 3) → SAFE", () => {
    const r = classifyProxy({
      ...base,
      tcpIp: "107.116.185.73",
      webrtcIp: "107.116.185.97", // same /24
      rttRatio: 2.5,
    });
    expect(r.verdict).toBe("SAFE");
    expect(r.rule).toBe(3);
  });

  it("rule 3 — /24 same without ratio → SAFE", () => {
    const r = classifyProxy({
      ...base,
      tcpIp: "10.0.1.10",
      webrtcIp: "10.0.1.20",
      rttRatio: null,
    });
    expect(r.verdict).toBe("SAFE");
    expect(r.rule).toBe(3);
  });

  it("rule 4 — fiber CGNAT (/16 same, ratio < 2) → SAFE", () => {
    const r = classifyProxy({
      ...base,
      tcpIp: "68.10.5.5",
      webrtcIp: "68.10.200.200", // same /16, diff /24
      rttRatio: 1.8,
    });
    expect(r.verdict).toBe("SAFE");
    expect(r.rule).toBe(4);
  });

  it("rule 5 — SOAX Dallas AT&T (/5 split, ratio 5.6) → KILL", () => {
    const r = classifyProxy({
      ...base,
      tcpIp: "108.243.197.41",
      webrtcIp: "107.210.133.127",
      rttRatio: 5.59,
    });
    expect(r.verdict).toBe("KILL");
    expect(r.rule).toBe(5);
  });

  it("rule 5 — split + ratio=2.0 borderline → KILL", () => {
    const r = classifyProxy({
      ...base,
      tcpIp: "72.190.83.43",
      webrtcIp: "107.210.133.127",
      rttRatio: 2.0,
    });
    expect(r.verdict).toBe("KILL");
    expect(r.rule).toBe(5);
  });

  it("rule 5 — /16 diff but ratio < 2 → fall through to SAFE (ambiguous)", () => {
    const r = classifyProxy({
      ...base,
      tcpIp: "10.0.0.1",
      webrtcIp: "192.168.0.1",
      rttRatio: 1.3,
    });
    expect(r.verdict).toBe("SAFE");
    expect(r.rule).toBe(8);
  });

  it("rule 6 — webrtc silent, ratio > 2.5 → KILL", () => {
    const r = classifyProxy({
      ...base,
      webrtcStatus: "no_candidates",
      tcpIp: "1.2.3.4",
      rttRatio: 3.0,
    });
    expect(r.verdict).toBe("KILL");
    expect(r.rule).toBe(6);
  });

  it("rule 7 — webrtc silent, ratio in (1.5, 2.5] → HIGH", () => {
    const r = classifyProxy({
      ...base,
      webrtcStatus: "no_candidates",
      tcpIp: "1.2.3.4",
      rttRatio: 2.0,
    });
    expect(r.verdict).toBe("HIGH");
    expect(r.rule).toBe(7);
  });

  it("rule 7 — webrtc silent, ratio ≤ 1.5 → SAFE (rule 8)", () => {
    const r = classifyProxy({
      ...base,
      webrtcStatus: "no_candidates",
      tcpIp: "1.2.3.4",
      rttRatio: 1.2,
    });
    expect(r.verdict).toBe("SAFE");
    expect(r.rule).toBe(8);
  });

  it("rule 8 — no data at all → SAFE", () => {
    const r = classifyProxy(base);
    expect(r.verdict).toBe("SAFE");
    expect(r.rule).toBe(8);
  });

  it("populates diagnostics (shared_prefix + ratio)", () => {
    const r = classifyProxy({
      ...base,
      tcpIp: "108.243.197.41",
      webrtcIp: "107.210.133.127",
      rttRatio: 5.59,
    });
    expect(r.shared_prefix).toBe(5);
    expect(r.ratio).toBe(5.59);
  });
});

describe("threat_score mapping", () => {
  const base = {
    tcpIp: null as string | null,
    webrtcIp: null as string | null,
    webrtcStatus: "ok" as const,
    rttRatio: null as number | null,
  };

  it("rule 0 (forgery) → 100", () => {
    expect(
      classifyProxy({ ...base, webrtcStatus: "forgery" }).threat_score,
    ).toBe(100);
  });

  it("rule 5 (split + ratio) → 100", () => {
    expect(
      classifyProxy({
        ...base,
        tcpIp: "108.243.197.41",
        webrtcIp: "107.210.133.127",
        rttRatio: 5.59,
      }).threat_score,
    ).toBe(100);
  });

  it("rule 6 (silent + high ratio) → 100", () => {
    expect(
      classifyProxy({
        ...base,
        webrtcStatus: "no_candidates",
        tcpIp: "1.2.3.4",
        rttRatio: 3.0,
      }).threat_score,
    ).toBe(100);
  });

  it("rule 7 (silent + moderate ratio) → 50", () => {
    expect(
      classifyProxy({
        ...base,
        webrtcStatus: "no_candidates",
        tcpIp: "1.2.3.4",
        rttRatio: 2.0,
      }).threat_score,
    ).toBe(50);
  });

  it("rules 1–4, 8 (safe) → 0", () => {
    expect(
      classifyProxy({
        ...base,
        tcpIp: "1.2.3.4",
        webrtcIp: "1.2.3.4",
      }).threat_score,
    ).toBe(0);
    expect(classifyProxy(base).threat_score).toBe(0);
  });
});
