import { describe, expect, it } from "vitest";
import type { IntegrityResultsData } from "../helpers/payload-schema";
import {
  detectBraveIos,
  detectLanguageMismatch,
  detectLocationMismatch,
  deviceTamperingProbability,
} from "./device-tampering";

function integrity(): IntegrityResultsData {
  return {
    session_id: "tampering-test",
    device: {},
    meta: {},
    sigint: {},
    analysis: {
      network: {
        proxy_score: 0,
        proxy_component: 0,
        vpn_component: 0,
        signals: [],
      },
      worker: { lied: false, divergences: [], signals: [] },
      timezone: {
        lied: false,
        checks: {
          offsetMatchesComputed: true,
          locationMatchesCfTimezone: true,
          offsetMatchesWorker: true,
          clientReportedLie: false,
        },
        cfTimezone: null,
        clientTimezone: null,
        signals: [],
      },
      ip: {
        lied: false,
        ips: { api: null, tls: null, tcp: null, webrtc: null },
        asn: { number: null, category: null, org: null },
        checks: { probesConsistent: true, webrtcMatchesProbes: true },
        integrity: 1,
        ip: null,
        signals: [],
      },
    },
    client_ip: "203.0.113.9",
    user_agent: "Mozilla/5.0 Firefox/150",
    created_at: 0,
  };
}

function score(row: IntegrityResultsData): number {
  return deviceTamperingProbability({
    session_id: row.session_id,
    integrity: row,
  });
}

describe("deviceTamperingProbability", () => {
  it("returns zero without integrity evidence", () => {
    expect(deviceTamperingProbability({ session_id: "missing" })).toBe(0);
  });

  it.each([
    [20, 100],
    [5, 60],
    [1, 25],
  ])("maps %i structural lies to tier %i", (totalLies, expected) => {
    const row = integrity();
    row.device = { lies: { totalLies, data: {} } };
    expect(score(row)).toBe(expected);
  });

  it("scores iframe crypto liveness failure at tier 50", () => {
    const row = integrity();
    row.device = {
      status: { iframeCrypto: { iframe_created: true, responsive: false } },
    };
    expect(score(row)).toBe(50);
  });

  it("scores timezone-versus-IP mismatch at tier 35", () => {
    const row = integrity();
    row.analysis.timezone.signals = [
      {
        code: "TZ_GEOLOCATION_MISMATCH",
        severity: 0.5,
        evidence: "test",
      },
    ];
    expect(score(row)).toBe(35);
    expect(
      detectLocationMismatch({ session_id: row.session_id, integrity: row }),
    ).toBe(true);
  });

  it("attributes the Brave iOS privacy-wrap signature", () => {
    const row = integrity();
    Object.assign(row.analysis, {
      ja4_ua: { ua_browser_family: "safari", ua_os: "iOS" },
    });
    row.device = {
      lies: {
        totalLies: 5,
        data: {
          "AnalyserNode.getFloatFrequencyData": ["wrapped"],
          "AnalyserNode.getByteFrequencyData": ["wrapped"],
          "AnalyserNode.getFloatTimeDomainData": ["wrapped"],
          "AnalyserNode.getByteTimeDomainData": ["wrapped"],
          "Navigator.plugins": ["wrapped"],
        },
      },
    };
    expect(detectBraveIos(row)).toEqual({ matched: true, attributedLies: 5 });
    expect(score(row)).toBe(0);
  });

  it("surfaces language mismatch as a tag predicate without score", () => {
    const row = integrity();
    Object.assign(row.analysis, {
      locale_geo: {
        hasLocaleTamper: false,
        signals: [{ code: "ACCEPT_LANG_GEO_CROSS_COUNTRY" }],
      },
    });
    const input = { session_id: row.session_id, integrity: row };
    expect(detectLanguageMismatch(input)).toBe(true);
    expect(deviceTamperingProbability(input)).toBe(0);
  });
});
