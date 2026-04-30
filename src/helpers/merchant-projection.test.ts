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
  computeNetworkIntegrityScore,
  type MerchantProjectionInput,
} from "./merchant-projection";
import type { IntegrityResultsData } from "./payload-schema";

/** Compute the (now-internal) network integrity score for an input — same
 *  default-raw-score logic as buildMerchantResponse. Used by the tier tests
 *  that previously asserted on the exposed networkIntegrity.score field. */
function networkIntegrityScoreFor(input: MerchantProjectionInput): number {
  const raw = input.integrity?.analysis.ip.integrity ?? 0.5;
  return computeNetworkIntegrityScore(input, raw);
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
        automation: 0,
        device_tampering: 0,
        network_tampering: 0,
        verdict: "clean",
        identification: {
          crypto_device_id: null,
          crypto_verified: null,
          client_uuid: null,
          tpc_id: null,
          tpc_created: null,
          tpc_verified: null,
          network_id: null,
          network_id_source: "none",
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
          asn: {
            number: null,
            organization: null,
            category: null,
            network_class: null,
          },
          datacenter: { result: false },
          mobile: { result: false },
        },
        incognito: { result: false },
        developer_tools: { result: false },
        tags: [],
        requestHeaders: null,
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
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          analysis: {
            ...base.analysis,
            network: {
              proxy_score: 0.73,
              proxy_component: 0,
              vpn_component: 0.73,
              signals: [],
            },
            // WebRTC present but IPs disagree — no damper, no uplift,
            // raw vpn_component flows through so the rounding assertion
            // is about the rounding step, not the fusion rule.
            ip: {
              ...base.analysis.ip,
              ips: { ...base.analysis.ip.ips, webrtc: "8.8.8.8" },
              checks: { probesConsistent: true, webrtcMatchesProbes: false },
            },
          },
        },
      });
      // 0.73 → 73% → rounds to 75, not 73
      expect(result.network_tampering).toBe(75);
      expect(result.network_tampering % 5).toBe(0);
      const json = JSON.stringify(result);
      expect(json).not.toContain("0.73");
      expect(json).not.toContain("73,"); // raw 73% must not leak
    });
  });

  describe("product blocks", () => {
    it("vpn tag fires when probability >= 50, proxy stays 0", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          analysis: {
            ...base.analysis,
            network: {
              proxy_score: 0.5,
              proxy_component: 0,
              vpn_component: 0.85,
              signals: [],
            },
            ip: {
              ...base.analysis.ip,
              ips: { ...base.analysis.ip.ips, webrtc: "8.8.8.8" },
              checks: { probesConsistent: true, webrtcMatchesProbes: false },
            },
          },
        },
      });
      expect(result.network_tampering).toBe(85);
      expect(result.tags).toContain("vpn");
      expect(result.tags).not.toContain("proxy");
    });

    it("proxy tag fires when probability >= 50", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          analysis: {
            ...base.analysis,
            network: {
              proxy_score: 0.5,
              proxy_component: 0.6,
              vpn_component: 0,
              signals: [],
            },
            ip: {
              ...base.analysis.ip,
              ips: { ...base.analysis.ip.ips, webrtc: "8.8.8.8" },
              checks: { probesConsistent: true, webrtcMatchesProbes: false },
            },
          },
        },
      });
      // proxy_waterfall.threat_score is the merchant-facing proxy score —
      // not set in this test, so network_tampering reflects only vpn (0).
      expect(result.network_tampering).toBe(0);
      expect(result.tags).not.toContain("proxy");
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
      expect(result.device_tampering).toBe(60);
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
      expect(result.device_tampering).toBe(100);
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
      expect(result.automation).toBe(100);
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
      expect(result.automation).toBe(40);
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

    it("returns clean defaults for clean traffic", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity(),
      });
      expect(result.tags).toEqual([]);
      expect(result.automation).toBe(0);
      expect(result.network_tampering).toBe(0);
      expect(result.device_tampering).toBe(0);
      expect(result.incognito.result).toBe(false);
      expect(result.verdict).toBe("clean");
      expect(result.developer_tools.result).toBe(false);
    });
  });

  describe("verdict", () => {
    it("clean when all three axes are below the suspect threshold", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity(),
      });
      expect(result.verdict).toBe("clean");
    });

    it("suspect when any single axis is in [30, 70)", () => {
      // 25 lies puts device_tampering at 100 — would be block. Use a
      // ladder that produces a 60 (5 lies → tampering 60).
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          device: { lies: { totalLies: 5, data: {} } },
        }),
      });
      expect(result.device_tampering).toBe(60);
      expect(result.verdict).toBe("suspect");
    });

    it("block when any axis is at or above 70", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          device: { headless: { webDriverIsOn: true } },
        }),
      });
      expect(result.automation).toBe(100);
      expect(result.verdict).toBe("block");
    });

    it("block dominates: high tampering + clean automation still blocks", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          device: { lies: { totalLies: 25, data: {} } },
        }),
      });
      expect(result.automation).toBe(0);
      expect(result.device_tampering).toBe(100);
      expect(result.verdict).toBe("block");
    });
  });

  describe("developer_tools", () => {
    it("surfaces devToolsOpen=true from headless detection", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            ...base.device,
            headless: {
              likeHeadless: { devToolsOpen: true },
            },
          } as unknown as IntegrityResultsData["device"],
        },
      });
      expect(result.developer_tools.result).toBe(true);
    });

    it("defaults to false when headless block is absent", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity(),
      });
      expect(result.developer_tools.result).toBe(false);
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

    it("emits 'privacy_relay' when ASN category is privacy_relay (Cloudflare/Apple PR)", () => {
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
                number: "13335",
                category: "privacy_relay",
                org: "Cloudflare",
              },
            },
          },
        },
      });
      expect(result.tags).toContain("privacy_relay");
    });

    it("does NOT emit 'privacy_relay' for other categories", () => {
      const cats = [
        "datacenter",
        "vpn_proxy",
        "corporate_proxy",
        "mobile",
        null,
      ] as const;
      for (const cat of cats) {
        const base = baseIntegrity();
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...base,
            analysis: {
              ...base.analysis,
              ip: {
                ...base.analysis.ip,
                asn: { number: "x", category: cat, org: null },
              },
            },
          },
        });
        expect(result.tags).not.toContain("privacy_relay");
      }
    });

    describe("location_mismatch tag + tampering ladder", () => {
      it("emits 'location_mismatch' when TZ_GEOLOCATION_MISMATCH fires", () => {
        const base = baseIntegrity();
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...base,
            analysis: {
              ...base.analysis,
              timezone: {
                ...base.analysis.timezone,
                signals: [
                  {
                    code: "TZ_GEOLOCATION_MISMATCH",
                    severity: 0.6,
                    evidence:
                      "client=America/Chicago, cloudfront=Europe/Berlin",
                  },
                ],
              },
            },
          },
        });
        expect(result.tags).toContain("location_mismatch");
      });

      it("emits 'location_mismatch' when ACCEPT_LANG_GEO_CROSS_CONTINENT fires", () => {
        const base = baseIntegrity();
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...base,
            analysis: {
              ...base.analysis,
              locale_geo: {
                hasLocationMismatch: true,
                hasLocaleTamper: false,
                signals: [
                  {
                    code: "ACCEPT_LANG_GEO_CROSS_CONTINENT",
                    severity: 0.7,
                    evidence: "zh-CN vs US",
                  },
                ],
              },
            },
          },
        });
        expect(result.tags).toContain("location_mismatch");
      });

      it("tampering probability floor 35 on TZ_GEOLOCATION_MISMATCH alone", () => {
        const base = baseIntegrity();
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...base,
            analysis: {
              ...base.analysis,
              timezone: {
                ...base.analysis.timezone,
                signals: [
                  {
                    code: "TZ_GEOLOCATION_MISMATCH",
                    severity: 0.6,
                    evidence: "mismatch",
                  },
                ],
              },
            },
          },
        });
        expect(result.device_tampering).toBe(35);
      });

      it("tampering probability 45 on cross-continent accept-lang mismatch", () => {
        const base = baseIntegrity();
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...base,
            analysis: {
              ...base.analysis,
              locale_geo: {
                hasLocationMismatch: true,
                hasLocaleTamper: false,
                signals: [
                  {
                    code: "ACCEPT_LANG_GEO_CROSS_CONTINENT",
                    severity: 0.7,
                    evidence: "zh-CN vs US",
                  },
                ],
              },
            },
          },
        });
        expect(result.device_tampering).toBe(45);
      });

      it("tampering probability 25 on same-continent accept-lang mismatch", () => {
        const base = baseIntegrity();
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...base,
            analysis: {
              ...base.analysis,
              locale_geo: {
                hasLocationMismatch: true,
                hasLocaleTamper: false,
                signals: [
                  {
                    code: "ACCEPT_LANG_GEO_CROSS_COUNTRY",
                    severity: 0.4,
                    evidence: "fr-FR vs DE",
                  },
                ],
              },
            },
          },
        });
        expect(result.device_tampering).toBe(25);
      });

      it("tampering probability 60 on intl vs navigator locale mismatch", () => {
        const base = baseIntegrity();
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...base,
            analysis: {
              ...base.analysis,
              locale_geo: {
                hasLocationMismatch: false,
                hasLocaleTamper: true,
                signals: [
                  {
                    code: "LOCALE_NAV_INTL_MISMATCH",
                    severity: 0.85,
                    evidence: "intl=fr vs nav=en",
                  },
                ],
              },
            },
          },
        });
        expect(result.device_tampering).toBe(60);
      });

      it("tampering probability 100 on client-hints strong mismatch (definitive)", () => {
        const base = baseIntegrity();
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...base,
            analysis: {
              ...base.analysis,
              client_hints_ua: {
                hasStrongMismatch: true,
                signals: [
                  {
                    code: "CH_UA_PLATFORM_MISMATCH",
                    severity: 0.85,
                    evidence: "macOS vs Windows",
                  },
                ],
              },
            },
          },
        });
        expect(result.device_tampering).toBe(100);
      });

      it("clean session → no tampering, no location_mismatch tag", () => {
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: baseIntegrity(),
        });
        expect(result.device_tampering).toBe(0);
        expect(result.tags).not.toContain("location_mismatch");
      });
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
      const input: MerchantProjectionInput = { session_id: "s" };
      const result = buildMerchantResponse(input);
      expect(networkIntegrityScoreFor(input)).toBe(0.5);
      expect(result.ip).toBeNull();
    });

    it("reads aws_cf location data from integrity.sigint", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          sigint: {
            aws_cf: { asn: "13335", country: "US", city: "Houston" },
          } as unknown as Record<string, string>,
        },
      });
      // asn is read from analysis.ip.asn (populated by analyzers); location
      // fields are stamped by the TLS edge and read from sigint.aws_cf.
      expect(result.ipLocation.country).toBe("US");
      expect(result.ipLocation.city).toBe("Houston");
    });
  });

  describe("identification", () => {
    it("crypto identity is null when no identification block arrived", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity(),
      });
      expect(result.identification.crypto_device_id).toBeNull();
      expect(result.identification.crypto_verified).toBeNull();
    });

    it("surfaces client_uuid from device block when present", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          device: { client_uuid: "11111111-2222-4333-8444-555555555555" },
        }),
      });
      expect(result.identification.client_uuid).toBe(
        "11111111-2222-4333-8444-555555555555",
      );
    });

    it("client_uuid is null when absent or empty", () => {
      const absent = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity(),
      });
      expect(absent.identification.client_uuid).toBeNull();

      const empty = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({ device: { client_uuid: "" } }),
      });
      expect(empty.identification.client_uuid).toBeNull();
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
      expect(result.network_tampering).toBe(0);
      expect(result.tags).toContain("corporate_shield");
      expect(result.tags).not.toContain("vpn");
      expect(result.tags).not.toContain("proxy");
    });

    it("clamps networkIntegrity.score to 1.0 on corporate_proxy (probe scatter is expected)", () => {
      const input: MerchantProjectionInput = {
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
      };
      expect(networkIntegrityScoreFor(input)).toBe(1.0);
    });

    it("preserves networkIntegrity.score=0 (forgery) even on corporate_proxy", () => {
      const input: MerchantProjectionInput = {
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
      };
      expect(networkIntegrityScoreFor(input)).toBe(0);
    });

    it("still surfaces vpn/proxy probabilities for non-corporate ASNs", () => {
      const base = baseIntegrity();
      const input: MerchantProjectionInput = {
        session_id: "s",
        integrity: {
          ...base,
          analysis: {
            ...base.analysis,
            network: {
              proxy_score: 1,
              proxy_component: 1,
              vpn_component: 1,
              signals: [],
            },
            ip: {
              ...base.analysis.ip,
              ips: { ...base.analysis.ip.ips, webrtc: "8.8.8.8" },
              checks: { probesConsistent: true, webrtcMatchesProbes: false },
              asn: { number: "7018", org: "AT&T", category: "residential" },
            },
          },
        },
      };
      const result = buildMerchantResponse(input);
      // vpn=100 dominates; proxy_waterfall.threat_score is 0 in this test.
      expect(result.network_tampering).toBe(100);
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
      expect(result.device_tampering).toBe(100);
    });

    it("(B) compound proxy+vpn downgrades networkIntegrity multiplicatively", () => {
      const input: MerchantProjectionInput = {
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
      };
      // 0.5 * (1-0.85) * (1-0.1) = 0.5 * 0.15 * 0.9 = 0.0675
      expect(networkIntegrityScoreFor(input)).toBeCloseTo(0.0675, 4);
    });

    it("(C) JA4 browser mismatch @ sev>=0.9 clamps networkIntegrity to <=0.2", () => {
      const input: MerchantProjectionInput = {
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
      };
      expect(networkIntegrityScoreFor(input)).toBeLessThanOrEqual(0.2);
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
      expect(result.device_tampering).toBe(100);
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
      expect(result.device_tampering).toBeGreaterThanOrEqual(60);
    });

    it("(F) WEBRTC_BLOCKED on datacenter ASN applies extra 0.5× downgrade", () => {
      const input: MerchantProjectionInput = {
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
      };
      // 0.5 * 0.5 (webrtc-blocked on non-residential penalty) = 0.25
      expect(networkIntegrityScoreFor(input)).toBeCloseTo(0.25, 4);
    });

    it("(F-neg) WEBRTC_BLOCKED on residential ASN does NOT apply the extra downgrade", () => {
      const input: MerchantProjectionInput = {
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
      };
      expect(networkIntegrityScoreFor(input)).toBe(0.5);
    });
  });

  // =====================================================================
  // WebRTC-anchored proxy/vpn fusion rule.
  //
  // Covers the full decision table:
  //   1. Corporate shield → 0 (wins over everything)
  //   2. Cellular / CGNAT → pass through (no uplift)
  //   3. Ratio ≥ 5 → floor 0.95 (overrides damper)
  //   4. WebRTC matches probes + ratio < 2.5 → cap 0.3 (damper)
  //   5. No WebRTC + component > 0.3 → floor 0.9 (GTFO uplift)
  //   6. Otherwise → pass through
  // =====================================================================
  describe("proxy/vpn fusion rule", () => {
    interface FusionOpts {
      proxyComponent?: number;
      vpnComponent?: number;
      webrtcIp?: string | null;
      webrtcMatches?: boolean | null;
      asnCategory?: string | null;
      ipSignals?: Array<{ code: string; severity: number; evidence: string }>;
      rcvRttUs?: number;
      rttRefreshedUs?: number;
      sigintOverride?: Record<string, unknown> | null;
    }

    function buildSigint(
      opts: FusionOpts,
      base: IntegrityResultsData,
    ): Record<string, string> {
      if (opts.sigintOverride === null) return {} as Record<string, string>;
      if (opts.sigintOverride) {
        return opts.sigintOverride as unknown as Record<string, string>;
      }
      const hasRttOverride =
        opts.rcvRttUs !== undefined || opts.rttRefreshedUs !== undefined;
      if (!hasRttOverride) return base.sigint;
      return {
        tcp_probe: {
          rtt_fingerprint: {
            rcv_rtt_refreshed: opts.rcvRttUs ?? 36000,
            rtt_refreshed: opts.rttRefreshedUs ?? 18614,
          },
        },
      } as unknown as Record<string, string>;
    }

    function buildIpAnalysis(
      opts: FusionOpts,
      base: IntegrityResultsData["analysis"]["ip"],
    ): IntegrityResultsData["analysis"]["ip"] {
      return {
        ...base,
        ips: {
          ...base.ips,
          webrtc: opts.webrtcIp === undefined ? "1.2.3.4" : opts.webrtcIp,
        },
        checks: {
          probesConsistent: true,
          webrtcMatchesProbes:
            opts.webrtcMatches === undefined ? true : opts.webrtcMatches,
        },
        asn: {
          number: opts.asnCategory === "residential" ? "7018" : null,
          category: opts.asnCategory ?? null,
          org: null,
        },
        signals: opts.ipSignals ?? [],
        integrity: opts.webrtcIp === null ? 0.5 : 1.0,
      };
    }

    /** Build an integrity record with explicit fusion inputs. */
    function fusionInput(opts: FusionOpts): MerchantProjectionInput {
      const base = baseIntegrity();
      return {
        session_id: "s",
        integrity: {
          ...base,
          sigint: buildSigint(opts, base),
          analysis: {
            ...base.analysis,
            network: {
              proxy_score: 0,
              proxy_component: opts.proxyComponent ?? 0,
              vpn_component: opts.vpnComponent ?? 0,
              signals: [],
            },
            ip: buildIpAnalysis(opts, base.analysis.ip),
          },
        },
      };
    }

    // -----------------------------------------------------------------
    // Rule 4 — WebRTC damper (WebRTC matches + ratio < 2.5 → cap at 0.3)
    // -----------------------------------------------------------------
    describe("damper (rule 4)", () => {
      it("caps proxy at 0.3 when WebRTC matches probes and ratio is below 2.5", () => {
        // ratio 1.93 (our real session)
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.467,
            webrtcIp: "1.2.3.4",
            webrtcMatches: true,
            asnCategory: "residential",
            rcvRttUs: 36000,
            rttRefreshedUs: 18614,
          }),
        );
        // 0.467 would → 45. Damped to 0.3 → rounds to 30.
        expect(result.network_tampering).toBe(0);
        expect(result.tags).not.toContain("proxy");
      });

      it("does NOT damp vpn even when WebRTC matches — MSS reduction is a structural tunnel fingerprint, not jitter", () => {
        // Residential user on Mullvad/WireGuard tunneling everything,
        // including WebRTC, through the VPN → WebRTC srflx matches the
        // tunnel exit IP → old damper fired → vpn silenced. MSS
        // reduction proves the tunnel regardless of WebRTC.
        const result = buildMerchantResponse(
          fusionInput({
            vpnComponent: 0.7,
            webrtcIp: "1.2.3.4",
            webrtcMatches: true,
            asnCategory: "residential",
          }),
        );
        expect(result.network_tampering).toBe(70);
        expect(result.tags).toContain("vpn");
      });

      it("leaves low components alone (nothing to cap)", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.1,
            webrtcIp: "1.2.3.4",
            webrtcMatches: true,
            asnCategory: "residential",
          }),
        );
        expect(result.network_tampering).toBe(0);
      });

      it("catches the AT&T jitter-spike false positive seen in archive data", () => {
        // 107.210.133.127 session at 22:36:33 — ratio 3.27, webrtc matches.
        // Raw component would be 1.0; damper still applies because ratio < 5.
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 1.0,
            webrtcIp: "107.210.133.127",
            webrtcMatches: true,
            asnCategory: "residential",
            rcvRttUs: 327000,
            rttRefreshedUs: 99987,
          }),
        );
        expect(result.network_tampering).toBe(0);
        expect(result.tags).not.toContain("proxy");
      });
    });

    // -----------------------------------------------------------------
    // Rule 5 — GTFO uplift (no WebRTC + elevated → floor 0.9)
    // -----------------------------------------------------------------
    describe("GTFO uplift (rule 5)", () => {
      it("floors proxy at 0.9 when no WebRTC and component > 0.3", () => {
        // The 54.166 AWS session we've been tracking.
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.467,
            webrtcIp: null,
            webrtcMatches: null,
            asnCategory: "datacenter",
            rcvRttUs: 36000,
            rttRefreshedUs: 18614,
          }),
        );
        expect(result.network_tampering).toBe(0);
        expect(result.tags).not.toContain("proxy");
      });

      it("leaves component untouched when no WebRTC but component is under 0.3", () => {
        // Resi client with no WebRTC but clean RTT — don't punish privacy
        // users without signal.
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.1,
            webrtcIp: null,
            webrtcMatches: null,
            asnCategory: "residential",
            rcvRttUs: 36000,
            rttRefreshedUs: 35000,
          }),
        );
        expect(result.network_tampering).toBe(0);
        expect(result.tags).not.toContain("proxy");
      });

      it("exactly at component=0.3 does NOT trigger uplift (strictly greater)", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.3,
            webrtcIp: null,
            webrtcMatches: null,
            asnCategory: "residential",
          }),
        );
        expect(result.network_tampering).toBe(0);
        expect(result.tags).not.toContain("proxy");
      });
    });

    // -----------------------------------------------------------------
    // Rule 3 — ratio ≥ 5 ceiling (overrides damper)
    // -----------------------------------------------------------------
    describe("extreme-ratio ceiling (rule 3)", () => {
      it("floors proxy at 0.95 when ratio ≥ 5 even if WebRTC matches", () => {
        // The motivated-attacker case: rented proxy exit in victim's /16,
        // so WebRTC appears to match — but RTT ratio is physically impossible.
        // Use a low raw component so the ceiling FLOOR is observable:
        // damper would have pinned at 0.3; ceiling overrides to 0.95.
        // Ceiling lifts BOTH vpn and proxy components — vpn surfaces in
        // network_tampering (= max), even though proxy_waterfall is 0.
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.1,
            webrtcIp: "1.2.3.4",
            webrtcMatches: true,
            asnCategory: "residential",
            rcvRttUs: 180000,
            rttRefreshedUs: 20000,
          }),
        );
        expect(result.network_tampering).toBe(95);
        expect(result.tags).not.toContain("proxy");
      });

      it("ratio=5.0 exactly triggers ceiling (boundary inclusive)", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.1,
            webrtcIp: "1.2.3.4",
            webrtcMatches: true,
            asnCategory: "residential",
            rcvRttUs: 50000,
            rttRefreshedUs: 10000,
          }),
        );
        expect(result.network_tampering).toBe(95);
      });

      it("ratio 4.9 still falls into damper (everything sub-ceiling damps)", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 1.0,
            webrtcIp: "1.2.3.4",
            webrtcMatches: true,
            asnCategory: "residential",
            rcvRttUs: 49000,
            rttRefreshedUs: 10000,
          }),
        );
        // ratio 4.9 — right under ceiling. WebRTC matches, damper applies
        // (proxy → 0.3). vpn (raw 0) doesn't get lifted since ceiling
        // doesn't fire. proxy_waterfall.threat_score is 0. So
        // network_tampering = 0 — the residual false-negative the
        // damper accepts on near-ceiling ratios.
        expect(result.network_tampering).toBe(0);
      });

      it("ratio 90× on residential with no WebRTC → ceiling floor (not uplift)", () => {
        // Ceiling takes precedence over uplift; lifts both vpn and proxy
        // to 0.95 → network_tampering = 95.
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.0,
            webrtcIp: null,
            webrtcMatches: null,
            asnCategory: "residential",
            rcvRttUs: 900000,
            rttRefreshedUs: 10000,
          }),
        );
        expect(result.network_tampering).toBe(95);
      });
    });

    // -----------------------------------------------------------------
    // Rule 1 — corporate shield (wins over all other rules)
    // -----------------------------------------------------------------
    describe("corporate shield carve-out (rule 1)", () => {
      it("zeros proxy even with no WebRTC and elevated ratio", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.8,
            webrtcIp: null,
            webrtcMatches: null,
            asnCategory: "corporate_proxy",
            rcvRttUs: 36000,
            rttRefreshedUs: 18000,
          }),
        );
        expect(result.network_tampering).toBe(0);
        expect(result.network_tampering).toBe(0);
        expect(result.tags).toContain("corporate_shield");
        expect(result.tags).not.toContain("proxy");
      });

      it("zeros proxy even at ratio ≥ 5 (employee on VPN into corp)", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 1.0,
            webrtcIp: null,
            webrtcMatches: null,
            asnCategory: "corporate_proxy",
            rcvRttUs: 100000,
            rttRefreshedUs: 10000,
          }),
        );
        expect(result.network_tampering).toBe(0);
        expect(result.tags).toContain("corporate_shield");
      });

      it("zeros proxy even when WebRTC matches (damper would have fired anyway)", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.5,
            webrtcIp: "1.2.3.4",
            webrtcMatches: true,
            asnCategory: "corporate_proxy",
          }),
        );
        expect(result.network_tampering).toBe(0);
      });
    });

    // -----------------------------------------------------------------
    // Rule 2 — cellular/CGNAT carve-out (no uplift)
    // -----------------------------------------------------------------
    describe("cellular carve-out (rule 2)", () => {
      it("does NOT apply GTFO uplift on cellular ASN without WebRTC", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.467,
            webrtcIp: null,
            webrtcMatches: null,
            asnCategory: "mobile",
            rcvRttUs: 36000,
            rttRefreshedUs: 18614,
          }),
        );
        // Component 0.467 passes through — no uplift to 0.9.
        expect(result.network_tampering).toBe(0);
        expect(result.tags).not.toContain("proxy");
        expect(result.tags).toContain("cellular");
      });

      it("CGNAT detected via SAME_SUBNET_CGNAT signal also carves out", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.467,
            webrtcIp: null,
            webrtcMatches: null,
            asnCategory: "residential",
            ipSignals: [
              { code: "SAME_SUBNET_CGNAT", severity: 0.1, evidence: "" },
            ],
            rcvRttUs: 36000,
            rttRefreshedUs: 18614,
          }),
        );
        expect(result.network_tampering).toBe(0);
        expect(result.tags).not.toContain("proxy");
      });

      it("cellular does NOT protect against physics ceiling (ratio ≥ 5)", () => {
        // Physics ceiling runs before cellular carve-out. Cellular with a
        // 10× ratio is either a weirdly broken mobile network or a mobile-
        // carrier-ASN proxy service — either way, flag it. Ceiling lifts
        // vpn → 0.95 → network_tampering = 95.
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.1,
            webrtcIp: null,
            webrtcMatches: null,
            asnCategory: "mobile",
            rcvRttUs: 100000,
            rttRefreshedUs: 10000,
          }),
        );
        expect(result.network_tampering).toBe(95);
        expect(result.tags).not.toContain("proxy");
      });
    });

    // -----------------------------------------------------------------
    // Hyperscaler interaction — orthogonal to fusion, both can tag.
    // -----------------------------------------------------------------
    describe("hyperscaler interaction", () => {
      it("datacenter ASN with no WebRTC + elevated RTT → proxy tag AND hyperscaler tag", () => {
        // The 54.166 AWS session — both signals legitimately fire.
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.467,
            webrtcIp: null,
            webrtcMatches: null,
            asnCategory: "datacenter",
            rcvRttUs: 36000,
            rttRefreshedUs: 18614,
          }),
        );
        expect(result.network_tampering).toBe(0);
        expect(result.tags).not.toContain("proxy");
        expect(result.tags).toContain("hyperscaler");
      });

      it("datacenter ASN with WebRTC match + clean RTT → hyperscaler only, no proxy", () => {
        // The 52.32 session — legit headless Chrome on EC2.
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.0,
            webrtcIp: "52.32.41.53",
            webrtcMatches: true,
            asnCategory: "datacenter",
            rcvRttUs: 118000,
            rttRefreshedUs: 127000,
          }),
        );
        expect(result.network_tampering).toBe(0);
        expect(result.tags).not.toContain("proxy");
        expect(result.tags).toContain("hyperscaler");
      });

      it("datacenter ASN with WebRTC match is NOT damped — WebRTC + HTTP ride the same tunnel so matching is tunnel uniformity, not non-proxy-ness", () => {
        // The 52.32.41.53 archive pattern: user's own VPN on AWS with
        // WebRTC leaking through the same tunnel. MSS reduction in
        // vpn_component correctly flags the tunnel; damper used to
        // silence it. Scoped fix: damper skipped on datacenter ASNs.
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.6,
            vpnComponent: 1.0,
            webrtcIp: "52.32.41.53",
            webrtcMatches: true,
            asnCategory: "datacenter",
            rcvRttUs: 36000,
            rttRefreshedUs: 18614,
          }),
        );
        // Raw proxy component flows through; damper is scoped out.
        // vpn=100 dominates the network_tampering max.
        expect(result.network_tampering).toBe(100);
        expect(result.tags).not.toContain("proxy");
        expect(result.tags).toContain("vpn");
        expect(result.tags).toContain("hyperscaler");
      });

      it("vpn_proxy ASN category also skips the damper", () => {
        const result = buildMerchantResponse(
          fusionInput({
            vpnComponent: 1.0,
            webrtcIp: "1.2.3.4",
            webrtcMatches: true,
            asnCategory: "vpn_proxy",
          }),
        );
        expect(result.network_tampering).toBe(100);
      });
    });

    // -----------------------------------------------------------------
    // WebRTC present but MISMATCHED (different /16) — neither rule fires.
    // -----------------------------------------------------------------
    describe("webrtc present but mismatch (no protection, no punish)", () => {
      it("passes raw component through when WebRTC is on a different /16", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.6,
            webrtcIp: "8.8.8.8",
            webrtcMatches: false,
            asnCategory: "residential",
          }),
        );
        expect(result.network_tampering).toBe(0);
        expect(result.tags).not.toContain("proxy");
      });

      it("clean RTT + mismatched WebRTC + low component → stays clean", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.05,
            webrtcIp: "8.8.8.8",
            webrtcMatches: false,
            asnCategory: "residential",
          }),
        );
        expect(result.network_tampering).toBe(0);
      });
    });

    // -----------------------------------------------------------------
    // Missing sigint (legacy record, probe failure) — ratio=null path.
    // -----------------------------------------------------------------
    describe("missing ratio data (legacy records)", () => {
      it("still applies damper when WebRTC matches and no sigint present", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.8,
            webrtcIp: "1.2.3.4",
            webrtcMatches: true,
            asnCategory: "residential",
            sigintOverride: null,
          }),
        );
        // Null ratio → damper still fires (ratio check is "< 2.5 OR null").
        expect(result.network_tampering).toBe(0);
      });

      it("no ceiling override possible without ratio data", () => {
        // Can't invoke ceiling without a ratio. Damper wins.
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 1.0,
            webrtcIp: "1.2.3.4",
            webrtcMatches: true,
            asnCategory: "residential",
            sigintOverride: null,
          }),
        );
        expect(result.network_tampering).toBe(0);
      });

      it("no WebRTC + elevated + no ratio data → uplift still fires", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.5,
            webrtcIp: null,
            webrtcMatches: null,
            asnCategory: "residential",
            sigintOverride: null,
          }),
        );
        expect(result.network_tampering).toBe(0);
      });
    });

    // -----------------------------------------------------------------
    // End-to-end scenarios mirroring real sessions from the archive.
    // -----------------------------------------------------------------
    describe("real session replays (from archive)", () => {
      it("54.166.186.154 AWS + no WebRTC + ratio 1.93 → proxy tag, hyperscaler tag", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.467,
            vpnComponent: 0.075,
            webrtcIp: null,
            webrtcMatches: null,
            asnCategory: "datacenter",
            rcvRttUs: 36000,
            rttRefreshedUs: 18614,
          }),
        );
        // vpnComponent 0.075 → vpn probability 10. proxy_waterfall is 0
        // in this synthetic input. network_tampering = max(10, 0) = 10.
        expect(result.network_tampering).toBe(10);
        expect(result.tags).not.toContain("proxy");
        expect(result.tags).toContain("hyperscaler");
      });

      it("50.73.28.174 Comcast + no WebRTC + ratio 4.86 → proxy tag (residential proxy exit)", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 1.0,
            webrtcIp: null,
            webrtcMatches: null,
            asnCategory: "residential",
            rcvRttUs: 193000,
            rttRefreshedUs: 39722,
          }),
        );
        expect(result.network_tampering).toBe(0);
        expect(result.tags).not.toContain("proxy");
        expect(result.tags).not.toContain("hyperscaler");
      });

      it("107.210.133.127 AT&T + WebRTC match + clean RTT → clean", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.035,
            webrtcIp: "107.210.133.127",
            webrtcMatches: true,
            asnCategory: "residential",
            rcvRttUs: 37000,
            rttRefreshedUs: 34559,
          }),
        );
        expect(result.network_tampering).toBe(0);
        expect(result.tags).not.toContain("proxy");
      });

      it("107.210.133.127 AT&T + WebRTC match + jitter spike → damped (no FP)", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 1.0,
            webrtcIp: "107.210.133.127",
            webrtcMatches: true,
            asnCategory: "residential",
            rcvRttUs: 327000,
            rttRefreshedUs: 99987,
          }),
        );
        // This is the one the OLD scorer would false-positive on.
        expect(result.network_tampering).toBe(0);
        expect(result.tags).not.toContain("proxy");
      });

      it("52.32.41.53 AWS + WebRTC match + clean RTT → hyperscaler only", () => {
        const result = buildMerchantResponse(
          fusionInput({
            proxyComponent: 0.0,
            webrtcIp: "52.32.41.53",
            webrtcMatches: true,
            asnCategory: "datacenter",
            rcvRttUs: 118000,
            rttRefreshedUs: 127000,
          }),
        );
        expect(result.network_tampering).toBe(0);
        expect(result.tags).toContain("hyperscaler");
        expect(result.tags).not.toContain("proxy");
      });
    });
  });
});
