import { describe, expect, it } from "vitest";
import type { IntegrityResultsData } from "../helpers/payload-schema";
import {
  detectUaFamilyHeaderMismatch,
  hasJa4UaMismatch,
  hasTlsUaMismatch,
  isCorporateShieldedAsn,
  isVerifiedAppleRelay,
  readBrowserEngineSignals,
  readKernelOsSignals,
  readLocaleGeoSignals,
} from "./identity";

function integrity(): IntegrityResultsData {
  return {
    session_id: "identity-test",
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
    client_ip: "203.0.113.8",
    user_agent: "Mozilla/5.0 Firefox/150",
    created_at: 0,
  };
}

describe("identity evidence readers", () => {
  it("defaults absent optional analysis blocks to clean evidence", () => {
    const row = integrity();
    expect(hasJa4UaMismatch(row)).toBe(false);
    expect(hasTlsUaMismatch(row)).toBe(false);
    expect(readBrowserEngineSignals(row)).toEqual({ hard: false, soft: false });
    expect(readKernelOsSignals(row)).toEqual({ hard: false, soft: false });
    expect(readLocaleGeoSignals(row)).toEqual({
      localeTamper: false,
      crossContinent: false,
      crossCountry: false,
    });
  });

  it("reads JA4, TLS, browser-engine, and locale signal blocks", () => {
    const row = integrity();
    Object.assign(row.analysis, {
      ja4_ua: {
        signals: [
          { code: "JA4_UA_BROWSER_MISMATCH", severity: 1 },
          { code: "TLS_UA_MISMATCH", severity: 0.9 },
        ],
      },
      browser_engine: {
        signals: [{ code: "BROWSER_ENGINE_INCONSISTENT_HARD" }],
      },
      locale_geo: {
        hasLocaleTamper: true,
        signals: [{ code: "ACCEPT_LANG_GEO_CROSS_CONTINENT" }],
      },
    });
    expect(hasJa4UaMismatch(row)).toBe(true);
    expect(hasTlsUaMismatch(row)).toBe(true);
    expect(readBrowserEngineSignals(row)).toEqual({ hard: true, soft: false });
    expect(readLocaleGeoSignals(row)).toEqual({
      localeTamper: true,
      crossContinent: true,
      crossCountry: false,
    });
  });

  it("recognizes corporate shields and authoritative Apple relay rows", () => {
    const shield = integrity();
    shield.analysis.ip.asn.category = "corporate_proxy";
    expect(isCorporateShieldedAsn(shield)).toBe(true);

    const relay = integrity() as IntegrityResultsData & {
      apple_relay_egress: boolean;
    };
    relay.apple_relay_egress = true;
    expect(isVerifiedAppleRelay(relay)).toBe(true);
  });

  it("demotes Darwin kernel mismatch when Safari wire evidence converges", () => {
    const row = integrity();
    Object.assign(row.analysis, {
      ja4_ua: {
        ja4_browser_family: "safari",
        h2_browser_family: "safari",
        ua_os: "iOS",
      },
      kernel_os: {
        signals: [{ code: "KERNEL_OS_MISMATCH_DARWIN" }],
      },
    });
    expect(readKernelOsSignals(row)).toEqual({ hard: false, soft: true });
  });

  it("requires body client hints when a Chrome UA lacks the header", () => {
    const row = integrity();
    row.user_agent = "Mozilla/5.0 Chrome/140.0.0.0 Safari/537.36";
    expect(detectUaFamilyHeaderMismatch(row)).toBe(true);
    row.device = {
      navigator: { userAgentData: { brands: [{ brand: "Chromium" }] } },
    };
    expect(detectUaFamilyHeaderMismatch(row)).toBe(false);
  });
});
