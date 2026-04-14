/**
 * Unit tests for the merchant-safe response projection.
 *
 * These tests assert both the positive cases (tags fire when evidence
 * warrants them) and the adversary-safety contract (no raw signal names,
 * no raw numeric scores, no Hamming distances leak through the
 * projection).
 */

import { describe, it, expect } from "vitest";
import {
  buildMerchantResponse,
  type MerchantProjectionInput,
} from "./merchant-projection";
import type { SessionCacheValue } from "../types/matching";
import type { IntegrityResultsData } from "../handlers/session-get/session-ops";

function baseSession(
  overrides: Partial<SessionCacheValue> = {},
): SessionCacheValue {
  return {
    status: "complete",
    device_id: "dev-abc",
    risk_score: 0.1,
    confidence: 0.9,
    match_tier: 1,
    match_version: 1,
    idempotency_key: "idem-1",
    flags: [],
    evidence_codes: [],
    updated_at: 0,
    ...overrides,
  };
}

function baseIntegrity(
  overrides: Partial<IntegrityResultsData> = {},
): IntegrityResultsData {
  return {
    session_id: "sess-1",
    tampered: false,
    vm_signals: [],
    vm_hash: "h",
    signal_count: 0,
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
        signals: [],
      },
    },
    client_ip: "1.2.3.4",
    user_agent: "ua",
    created_at: 0,
    ...overrides,
  };
}

describe("buildMerchantResponse", () => {
  describe("shape contract", () => {
    it("returns the documented shape with nulls where we don't have data yet", () => {
      const result = buildMerchantResponse({ session_id: "s-1" });
      expect(result).toEqual({
        session_id: "s-1",
        device_id: null,
        is_new_device: false,
        first_seen_at: null,
        confidence: 0,
        risk_score: 0,
        bot: "none",
        tags: [],
        network: { asn: null, asn_org: null, country: null },
        policy: null,
        velocity: null,
      });
    });

    it("never leaks internal score component names", () => {
      const input: MerchantProjectionInput = {
        session_id: "s-1",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            network: {
              proxy_score: 0.9,
              proxy_component: 0.8,
              vpn_component: 0.7,
              signals: [{ code: "MSS_TOO_LOW", severity: 1, evidence: "raw" }],
            },
          },
        }),
      };
      const result = buildMerchantResponse(input);
      const json = JSON.stringify(result);
      expect(json).not.toContain("proxy_score");
      expect(json).not.toContain("proxy_component");
      expect(json).not.toContain("vpn_component");
      expect(json).not.toContain("MSS_TOO_LOW");
      expect(json).not.toContain("hamming");
    });
  });

  describe("tag derivation", () => {
    it("emits vpn tag when vpn_component >= 0.5", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            network: {
              proxy_score: 0.5,
              proxy_component: 0,
              vpn_component: 0.7,
              signals: [],
            },
          },
        }),
      });
      expect(result.tags).toContain("vpn");
      expect(result.tags).not.toContain("proxy");
    });

    it("emits proxy tag when proxy_component >= 0.5", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            network: {
              proxy_score: 0.5,
              proxy_component: 0.6,
              vpn_component: 0,
              signals: [],
            },
          },
        }),
      });
      expect(result.tags).toContain("proxy");
      expect(result.tags).not.toContain("vpn");
    });

    it("emits both vpn and proxy when both components fire", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            network: {
              proxy_score: 0.9,
              proxy_component: 0.7,
              vpn_component: 0.7,
              signals: [],
            },
          },
        }),
      });
      expect(result.tags).toEqual(expect.arrayContaining(["vpn", "proxy"]));
    });

    it("emits hyperscaler when asn category is datacenter", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          analysis: {
            ...base.analysis,
            ip: {
              ...base.analysis.ip,
              asn: {
                number: "AS16509",
                category: "datacenter",
                org: "AMAZON-02",
              },
            },
          },
        },
      });
      expect(result.tags).toContain("hyperscaler");
    });

    it("emits corporate_shield when asn category is corporate_proxy", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          analysis: {
            ...base.analysis,
            ip: {
              ...base.analysis.ip,
              asn: {
                number: "AS22616",
                category: "corporate_proxy",
                org: "ZSCALER",
              },
            },
          },
        },
      });
      expect(result.tags).toContain("corporate_shield");
    });

    it("emits browser_tampering when lies.totalLies >= 5", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: { lies: { totalLies: 7 } },
        },
      });
      expect(result.tags).toContain("browser_tampering");
    });

    it("emits browser_tampering on relevant worker divergence", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          analysis: {
            ...base.analysis,
            worker: {
              lied: true,
              divergences: [
                {
                  field: "navigator.userAgent",
                  main: "a",
                  web: "b",
                  shared: "a",
                },
              ],
              signals: [],
            },
          },
        },
      });
      expect(result.tags).toContain("browser_tampering");
    });

    it("emits automation when webdriver is on", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: { headless: { webDriverIsOn: true } },
        },
      });
      expect(result.tags).toContain("automation");
      expect(result.bot).toBe("confirmed");
    });

    it("emits automation on likeHeadlessRating >= 20", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: { headless: { likeHeadlessRating: 40 } },
        },
      });
      expect(result.tags).toContain("automation");
      expect(result.bot).toBe("suspected");
    });

    it("falls back to session flags when integrity is absent", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        session: baseSession({ flags: ["likely_vpn", "bot_detected"] }),
      });
      expect(result.tags).toContain("vpn");
      expect(result.tags).toContain("automation");
      expect(result.bot).toBe("confirmed");
    });

    it("emits incognito tag from incognito_browser_mismatch flag", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        session: baseSession({ flags: ["incognito_browser_mismatch"] }),
      });
      expect(result.tags).toContain("incognito");
    });

    it("returns empty tags for clean traffic", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        session: baseSession(),
        integrity: baseIntegrity(),
      });
      expect(result.tags).toEqual([]);
      expect(result.bot).toBe("none");
    });
  });

  describe("network block", () => {
    it("parses AS-prefixed ASN to a number", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          analysis: {
            ...base.analysis,
            ip: {
              ...base.analysis.ip,
              asn: { number: "AS16509", category: null, org: "AMAZON" },
            },
          },
        },
      });
      expect(result.network.asn).toBe(16509);
      expect(result.network.asn_org).toBe("AMAZON");
    });

    it("falls back to sigint.aws_cf when integrity is absent", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        payload: {
          identifiers: { session_id: "s", device_id: "d" },
          analysis: {
            status: "complete",
            confidence: 0.5,
            match_tier: 1,
            is_new_device: false,
            risk_score: 0.1,
            flags: [],
            evidence_codes: [],
          },
          hashes: { stable: "x", fuzzy: "y" },
          device: {},
          sigint: {
            aws_cf: { asn: "13335", country: "US" },
          } as unknown as Record<string, Record<string, unknown>>,
        },
      });
      expect(result.network.asn).toBe(13335);
      expect(result.network.country).toBe("US");
    });
  });

  describe("passthroughs", () => {
    it("wires confidence and risk_score through from payload", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        payload: {
          identifiers: { session_id: "s", device_id: "d" },
          analysis: {
            status: "complete",
            confidence: 0.87,
            match_tier: 1,
            is_new_device: true,
            risk_score: 0.42,
            flags: [],
            evidence_codes: [],
          },
          hashes: { stable: "x", fuzzy: "y" },
          device: {},
        },
      });
      expect(result.confidence).toBe(0.87);
      expect(result.risk_score).toBe(0.42);
      expect(result.is_new_device).toBe(true);
      expect(result.device_id).toBe("d");
    });

    it("first_seen_at is null (placeholder until DeviceProfile wiring)", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        session: baseSession(),
      });
      expect(result.first_seen_at).toBeNull();
    });

    it("policy and velocity are null (forward-compat placeholders)", () => {
      const result = buildMerchantResponse({ session_id: "s" });
      expect(result.policy).toBeNull();
      expect(result.velocity).toBeNull();
    });
  });
});
