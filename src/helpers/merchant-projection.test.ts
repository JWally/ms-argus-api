/**
 * Unit tests for the merchant-safe response projection.
 *
 * Asserts the FPJS-shaped product-block surface and the adversary-safety
 * contract: no raw signal names, no raw numeric component scores, no
 * Hamming distances or internal analyzer evidence leaks through.
 */

import { describe, it, expect } from "vitest";
import {
  buildMerchantResponse,
  type MerchantProjectionInput,
} from "./merchant-projection";
import type { SessionCacheValue } from "../types/matching";
import type { IntegrityResultsData } from "./payload-schema";

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
        ips: {
          api: "1.2.3.4",
          tls: "1.2.3.4",
          tcp: "1.2.3.4",
          webrtc: "1.2.3.4",
        },
        asn: { number: null, category: null, org: null },
        checks: { probesConsistent: true, webrtcMatchesProbes: true },
        integrity: 1.0,
        ip: "1.2.3.4",
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
    it("returns the documented shape with nulls where we don't have data", () => {
      const result = buildMerchantResponse({ session_id: "s-1" });
      expect(result).toEqual({
        session_id: "s-1",
        created_at: null,
        ttl: null,
        identification: {
          device_id: null,
          is_new_device: false,
          first_seen_at: null,
          last_seen_at: null,
          confidence: { score: 0 },
          crypto_device_id: null,
          crypto_verified: null,
          tpc_id: null,
          tpc_created: null,
          tpc_verified: null,
          browserDetails: {
            browserName: null,
            browserVersion: null,
            os: null,
            osVersion: null,
            device: null,
            userAgent: null,
          },
        },
        ip: null,
        ipLocation: {
          city: null,
          country: null,
          latitude: null,
          longitude: null,
          timezone: null,
        },
        ipInfo: {
          asn: { number: null, organization: null, category: null },
          datacenter: { result: false },
        },
        bot: { probability: 0 },
        vpn: { probability: 0 },
        proxy: { probability: 0 },
        tampering: { probability: 0 },
        incognito: { result: false },
        networkIntegrity: { score: 0.5 },
        suspectScore: { result: null },
        tags: [],
        requestHeaders: null,
        policy: null,
        velocity: null,
      });
    });

    it("never leaks internal score component names or raw signal codes", () => {
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

    it("rounds probabilities to the nearest 5, never exposes raw component", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            network: {
              proxy_score: 0.73,
              proxy_component: 0,
              vpn_component: 0.73,
              signals: [],
            },
          },
        }),
      });
      // 0.73 → 73% → rounds to 75, not 73
      expect(result.vpn.probability).toBe(75);
      expect(result.vpn.probability % 5).toBe(0);
      const json = JSON.stringify(result);
      expect(json).not.toContain("0.73");
      expect(json).not.toContain("73,"); // raw 73% must not leak
    });
  });

  describe("product blocks", () => {
    it("vpn tag fires when probability >= 50, proxy stays 0", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            network: {
              proxy_score: 0.5,
              proxy_component: 0,
              vpn_component: 0.85,
              signals: [],
            },
          },
        }),
      });
      expect(result.vpn.probability).toBe(85);
      expect(result.proxy.probability).toBe(0);
      expect(result.tags).toContain("vpn");
      expect(result.tags).not.toContain("proxy");
    });

    it("proxy tag fires when probability >= 50", () => {
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
      expect(result.proxy.probability).toBe(60);
      expect(result.vpn.probability).toBe(0);
      expect(result.tags).toContain("proxy");
    });

    it("ipInfo.datacenter.result true when ASN category is datacenter", () => {
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
      expect(result.ipInfo.datacenter.result).toBe(true);
      expect(result.ipInfo.asn.number).toBe(16509);
      expect(result.ipInfo.asn.organization).toBe("AMAZON-02");
      expect(result.ipInfo.asn.category).toBe("datacenter");
      expect(result.tags).toContain("hyperscaler");
    });

    it("tampering probability fires on lies.totalLies >= 5", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: { lies: { totalLies: 7 } },
        },
      });
      expect(result.tampering.probability).toBe(60);
      expect(result.tags).toContain("browser_tampering");
    });

    it("tampering probability maxes at 100 on JA4-UA mismatch", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          analysis: {
            ...base.analysis,
            worker: {
              lied: true,
              divergences: [],
              signals: [
                {
                  code: "JA4_UA_BROWSER_MISMATCH",
                  severity: 1,
                  evidence: "mismatch",
                },
              ],
            },
          },
        },
      });
      expect(result.tampering.probability).toBe(100);
    });

    it("bot probability is 100 when webdriver is on", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: { headless: { webDriverIsOn: true } },
        },
      });
      expect(result.bot.probability).toBe(100);
      expect(result.tags).toContain("automation");
    });

    it("bot probability mirrors likeHeadlessRating (rounded to 5)", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: { headless: { likeHeadlessRating: 42 } },
        },
      });
      // 42 rounds to 40
      expect(result.bot.probability).toBe(40);
    });

    it("incognito.result is true when device.incognito.isPrivate is true", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: { incognito: { isPrivate: true } },
        },
      });
      expect(result.incognito.result).toBe(true);
      expect(result.tags).toContain("incognito");
    });

    it("incognito.result falls back to the session flag when integrity absent", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        session: baseSession({ flags: ["incognito_browser_mismatch"] }),
      });
      expect(result.incognito.result).toBe(true);
    });

    it("falls back to session flags when integrity is absent", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        session: baseSession({ flags: ["likely_vpn", "bot_detected"] }),
      });
      expect(result.vpn.probability).toBeGreaterThanOrEqual(50);
      expect(result.bot.probability).toBe(100);
      expect(result.tags).toContain("vpn");
      expect(result.tags).toContain("automation");
    });

    it("returns clean defaults for clean traffic", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        session: baseSession(),
        integrity: baseIntegrity(),
      });
      expect(result.tags).toEqual([]);
      expect(result.bot.probability).toBe(0);
      expect(result.vpn.probability).toBe(0);
      expect(result.proxy.probability).toBe(0);
      expect(result.tampering.probability).toBe(0);
      expect(result.incognito.result).toBe(false);
    });
  });

  describe("cellular + no_webrtc tags", () => {
    it("emits 'cellular' when ASN category is mobile", () => {
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
                number: "21928",
                category: "mobile",
                org: "T-Mobile USA",
              },
            },
          },
        },
      });
      expect(result.tags).toContain("cellular");
    });

    it("emits 'cellular' when SAME_SUBNET_CGNAT signal fired", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          analysis: {
            ...base.analysis,
            ip: {
              ...base.analysis.ip,
              signals: [
                {
                  code: "SAME_SUBNET_CGNAT",
                  severity: 0.1,
                  evidence: "webrtc same /16",
                },
              ],
            },
          },
        },
      });
      expect(result.tags).toContain("cellular");
      // But the raw signal name must NOT leak
      expect(JSON.stringify(result)).not.toContain("SAME_SUBNET_CGNAT");
    });

    it("emits 'no_webrtc' when webrtc IP absent and integrity > 0", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          analysis: {
            ...base.analysis,
            ip: {
              ...base.analysis.ip,
              ips: { ...base.analysis.ip.ips, webrtc: null },
              integrity: 0.5,
            },
          },
        },
      });
      expect(result.tags).toContain("no_webrtc");
    });

    it("suppresses 'no_webrtc' at integrity 0 (forgery — no hints)", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          analysis: {
            ...base.analysis,
            ip: {
              ...base.analysis.ip,
              ips: { ...base.analysis.ip.ips, webrtc: null },
              integrity: 0,
            },
          },
        },
      });
      expect(result.tags).not.toContain("no_webrtc");
    });
  });

  describe("ip + ipLocation + ipInfo", () => {
    it("parses AS-prefixed ASN to a number and surfaces org", () => {
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
      expect(result.ipInfo.asn.number).toBe(16509);
      expect(result.ipInfo.asn.organization).toBe("AMAZON");
    });

    it("surfaces ipLocation from sigint.aws_cf with coordinates parsed to floats", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          sigint: {
            aws_cf: {
              city: "Dallas",
              country: "US",
              lat: "32.972",
              lon: "-96.791",
              tz: "America/Chicago",
            },
          } as unknown as Record<string, string>,
        },
      });
      expect(result.ipLocation).toEqual({
        city: "Dallas",
        country: "US",
        latitude: 32.972,
        longitude: -96.791,
        timezone: "America/Chicago",
      });
    });

    it("defaults networkIntegrity to 0.5 when no integrity data", () => {
      const result = buildMerchantResponse({ session_id: "s" });
      expect(result.networkIntegrity.score).toBe(0.5);
      expect(result.ip).toBeNull();
    });

    it("falls back to payload.sigint.aws_cf when integrity is absent", () => {
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
            aws_cf: { asn: "13335", country: "US", city: "Houston" },
          } as unknown as Record<string, Record<string, unknown>>,
        },
      });
      expect(result.ipInfo.asn.number).toBe(13335);
      expect(result.ipLocation.country).toBe("US");
      expect(result.ipLocation.city).toBe("Houston");
    });
  });

  describe("identification", () => {
    it("wires confidence, risk_score, and device_id from payload", () => {
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
      expect(result.identification.confidence.score).toBe(0.87);
      expect(result.identification.is_new_device).toBe(true);
      expect(result.identification.device_id).toBe("d");
      expect(result.suspectScore.result).toBe(0.42);
    });

    it("first_seen_at and last_seen_at are null (DeviceProfile placeholders)", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        session: baseSession(),
      });
      expect(result.identification.first_seen_at).toBeNull();
      expect(result.identification.last_seen_at).toBeNull();
    });

    it("policy and velocity are null (forward-compat placeholders)", () => {
      const result = buildMerchantResponse({ session_id: "s" });
      expect(result.policy).toBeNull();
      expect(result.velocity).toBeNull();
    });

    it("crypto identity is null when no identification block arrived", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity(),
      });
      expect(result.identification.crypto_device_id).toBeNull();
      expect(result.identification.crypto_verified).toBeNull();
    });

    it("surfaces hashed crypto_device_id + verified when identification present", () => {
      const pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXXX";
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          identification: {
            pubkey,
            verified: true,
            reason: null,
            sig_present: true,
          },
        }),
      });
      expect(result.identification.crypto_device_id).toMatch(/^[0-9a-f]{10}$/);
      expect(result.identification.crypto_verified).toBe(true);
    });

    it("produces the same crypto hash for the same pubkey across calls", () => {
      const pubkey = "repeatable-pubkey-bytes";
      const a = buildMerchantResponse({
        session_id: "s1",
        integrity: baseIntegrity({
          identification: {
            pubkey,
            verified: true,
            reason: null,
            sig_present: true,
          },
        }),
      });
      const b = buildMerchantResponse({
        session_id: "s2",
        integrity: baseIntegrity({
          identification: {
            pubkey,
            verified: true,
            reason: null,
            sig_present: true,
          },
        }),
      });
      expect(a.identification.crypto_device_id).toBe(
        b.identification.crypto_device_id,
      );
    });

    it("produces different hashes for different pubkeys", () => {
      const a = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          identification: {
            pubkey: "key-A",
            verified: true,
            reason: null,
            sig_present: true,
          },
        }),
      });
      const b = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          identification: {
            pubkey: "key-B",
            verified: true,
            reason: null,
            sig_present: true,
          },
        }),
      });
      expect(a.identification.crypto_device_id).not.toBe(
        b.identification.crypto_device_id,
      );
    });

    it("never leaks the raw pubkey or verification reason to the merchant", () => {
      const pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE_RAW_KEY_BYTES_";
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          identification: {
            pubkey,
            verified: false,
            reason: "sig_invalid",
            sig_present: true,
          },
        }),
      });
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain(pubkey);
      expect(serialized).not.toContain("MFkwEwYHKoZIzj0");
      expect(serialized).not.toContain("sig_invalid");
      expect(serialized).not.toContain("sig_present");
    });
  });

  describe("browserDetails", () => {
    it("parses browser name and version from navigator.userAgentParsed", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            navigator: {
              userAgentParsed: "Firefox 148",
              system: "Linux",
              device: "Ubuntu Linux x86_64",
              userAgent: "Mozilla/5.0 Firefox/148",
            },
          },
        },
      });
      expect(result.identification.browserDetails).toEqual({
        browserName: "Firefox",
        browserVersion: "148",
        os: "Linux",
        osVersion: null,
        device: "Ubuntu Linux x86_64",
        userAgent: "Mozilla/5.0 Firefox/148",
      });
    });

    it("leaves browserDetails null when no navigator present", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity(),
      });
      expect(result.identification.browserDetails).toEqual({
        browserName: null,
        browserVersion: null,
        os: null,
        osVersion: null,
        device: null,
        userAgent: "ua",
      });
    });
  });

  describe("third-party cookie", () => {
    it("tpc_verified=pass + id + created when cookie matches token", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          sigint: {
            aws_cf: {
              id: "cf-cookie-id-1",
              issuedAt: 1700000000,
              cookieTampered: false,
              cookieMatchesToken: true,
            },
          } as unknown as Record<string, string>,
        }),
      });
      expect(result.identification.tpc_verified).toBe("pass");
      expect(result.identification.tpc_id).toBe("cf-cookie-id-1");
      expect(result.identification.tpc_created).toBe(1700000000);
    });

    it("tpc_verified=fail and id/created withheld when cookie was tampered", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          sigint: {
            aws_cf: {
              id: "cf-cookie-id-1",
              issuedAt: 1700000000,
              cookieTampered: true,
              cookieMatchesToken: null,
            },
          } as unknown as Record<string, string>,
        }),
      });
      expect(result.identification.tpc_verified).toBe("fail");
      expect(result.identification.tpc_id).toBeNull();
      expect(result.identification.tpc_created).toBeNull();
    });

    it("tpc_verified=null when no aws_cf sigint is available", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity(),
      });
      expect(result.identification.tpc_verified).toBeNull();
      expect(result.identification.tpc_id).toBeNull();
      expect(result.identification.tpc_created).toBeNull();
    });
  });

  describe("corporate shield suppresses VPN/proxy", () => {
    it("zeros vpn and proxy probabilities when ASN category is corporate_proxy", () => {
      const input: MerchantProjectionInput = {
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            network: {
              proxy_score: 1,
              proxy_component: 1,
              vpn_component: 1,
              signals: [],
            },
            ip: {
              ...baseIntegrity().analysis.ip,
              asn: {
                number: "36692",
                org: "Cisco Umbrella",
                category: "corporate_proxy",
              },
            },
          },
        }),
      };
      const result = buildMerchantResponse(input);
      expect(result.vpn.probability).toBe(0);
      expect(result.proxy.probability).toBe(0);
      expect(result.tags).toContain("corporate_shield");
      expect(result.tags).not.toContain("vpn");
      expect(result.tags).not.toContain("proxy");
    });

    it("clamps networkIntegrity.score to 1.0 on corporate_proxy (probe scatter is expected)", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            ip: {
              ...baseIntegrity().analysis.ip,
              integrity: 0.1,
              asn: {
                number: "36692",
                org: "Cisco Umbrella",
                category: "corporate_proxy",
              },
            },
          },
        }),
      });
      expect(result.networkIntegrity.score).toBe(1.0);
    });

    it("preserves networkIntegrity.score=0 (forgery) even on corporate_proxy", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            ip: {
              ...baseIntegrity().analysis.ip,
              integrity: 0,
              asn: {
                number: "36692",
                org: "Cisco Umbrella",
                category: "corporate_proxy",
              },
            },
          },
        }),
      });
      expect(result.networkIntegrity.score).toBe(0);
    });

    it("still surfaces vpn/proxy probabilities for non-corporate ASNs", () => {
      const input: MerchantProjectionInput = {
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            network: {
              proxy_score: 1,
              proxy_component: 1,
              vpn_component: 1,
              signals: [],
            },
            ip: {
              ...baseIntegrity().analysis.ip,
              asn: { number: "7018", org: "AT&T", category: "residential" },
            },
          },
        }),
      };
      const result = buildMerchantResponse(input);
      expect(result.vpn.probability).toBe(100);
      expect(result.proxy.probability).toBe(100);
    });
  });

  describe("requestHeaders", () => {
    it("surfaces captured headers and cookie names", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          request_headers: {
            headers: {
              "user-agent": "Mozilla/5.0",
              "accept-language": "en-US,en;q=0.9",
              "cloudfront-viewer-country": "US",
            },
            cookie_names: ["sessionid", "_ga"],
          },
        }),
      });
      expect(result.requestHeaders).toEqual({
        headers: {
          "user-agent": "Mozilla/5.0",
          "accept-language": "en-US,en;q=0.9",
          "cloudfront-viewer-country": "US",
        },
        cookie_names: ["sessionid", "_ga"],
      });
    });

    it("is null when no headers were captured", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity(),
      });
      expect(result.requestHeaders).toBeNull();
    });
  });

  describe("scoring rules A-F", () => {
    it("(A) WebRTC API tampering forces tampering.probability to 100", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          device: {
            lies: {
              totalLies: 2,
              data: {
                "undefined.createDataChannel": ["failed toString"],
                "undefined.iceConnectionState": [
                  "failed descriptor.value undefined",
                ],
              },
            },
          },
        }),
      });
      expect(result.tampering.probability).toBe(100);
    });

    it("(B) compound proxy+vpn downgrades networkIntegrity multiplicatively", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            network: {
              proxy_score: 0.85,
              proxy_component: 0.85,
              vpn_component: 0.1,
              signals: [],
            },
            ip: {
              ...baseIntegrity().analysis.ip,
              integrity: 0.5,
              ips: {
                api: "1.2.3.4",
                tls: "1.2.3.4",
                tcp: "1.2.3.4",
                webrtc: null,
              },
            },
          },
        }),
      });
      // 0.5 * (1-0.85) * (1-0.1) = 0.5 * 0.15 * 0.9 = 0.0675
      expect(result.networkIntegrity.score).toBeCloseTo(0.0675, 4);
    });

    it("(C) JA4 browser mismatch @ sev>=0.9 clamps networkIntegrity to <=0.2", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            ip: {
              ...baseIntegrity().analysis.ip,
              integrity: 1.0,
            },
            ja4_ua: {
              signals: [
                {
                  code: "JA4_UA_BROWSER_MISMATCH",
                  severity: 0.95,
                  evidence: "",
                },
              ],
              ja4_browser_family: "chromium",
              ua_browser_family: "safari",
              h2_browser_family: "chromium",
            },
          } as unknown as IntegrityResultsData["analysis"],
        }),
      });
      expect(result.networkIntegrity.score).toBeLessThanOrEqual(0.2);
    });

    it("(D) lies>=5 AND worker UA divergence → tampering.probability=100", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          device: { lies: { totalLies: 5, data: {} } },
          analysis: {
            ...baseIntegrity().analysis,
            worker: {
              lied: true,
              divergences: [
                { field: "userAgent", main: "A", web: "A", shared: "B" },
              ],
              signals: [],
            },
          },
        }),
      });
      expect(result.tampering.probability).toBe(100);
    });

    it("(E) UA claims Chrome but Sec-CH-UA missing → tampering.probability>=60", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          user_agent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
          request_headers: { headers: {}, cookie_names: [] },
        }),
      });
      expect(result.tampering.probability).toBeGreaterThanOrEqual(60);
    });

    it("(F) WEBRTC_BLOCKED on datacenter ASN applies extra 0.5× downgrade", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            ip: {
              ...baseIntegrity().analysis.ip,
              integrity: 0.5,
              signals: [
                { code: "WEBRTC_BLOCKED", severity: 0.2, evidence: "" },
              ],
              asn: { number: "16509", org: "AWS", category: "datacenter" },
            },
          },
        }),
      });
      // 0.5 * 0.5 (webrtc-blocked on non-residential penalty) = 0.25
      expect(result.networkIntegrity.score).toBeCloseTo(0.25, 4);
    });

    it("(F-neg) WEBRTC_BLOCKED on residential ASN does NOT apply the extra downgrade", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            ip: {
              ...baseIntegrity().analysis.ip,
              integrity: 0.5,
              signals: [
                { code: "WEBRTC_BLOCKED", severity: 0.2, evidence: "" },
              ],
              asn: { number: "7922", org: "Comcast", category: "residential" },
            },
          },
        }),
      });
      expect(result.networkIntegrity.score).toBe(0.5);
    });
  });
});
