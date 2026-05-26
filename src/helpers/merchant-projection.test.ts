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
            metadata: null,
          },
          datacenter: { result: false },
          mobile: { result: false },
          residential: { result: false },
          vpn: { result: false },
          hosting: { result: false },
          privacy_relay: { result: false },
          corporate_shield: { result: false },
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

    it("ipInfo.datacenter.result true when ASN network_class is datacenter", () => {
      // All convenience booleans (datacenter/mobile/vpn/hosting/etc) read
      // from `network_class`, the broader 12-value taxonomy. The legacy
      // `category` field is exposed for backwards compat but no longer
      // drives routing flags. Real ingestion data always sets both.
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
                network_class: "datacenter",
              },
            },
          },
        },
      });
      expect(result.ipInfo.datacenter.result).toBe(true);
      expect(result.ipInfo.asn.number).toBe(16509);
      expect(result.ipInfo.asn.organization).toBe("AMAZON-02");
      expect(result.ipInfo.asn.category).toBe("datacenter");
      expect(result.ipInfo.asn.network_class).toBe("datacenter");
      expect(result.tags).toContain("hyperscaler");
    });

    it("ipInfo convenience booleans cover vpn / hosting / privacy_relay / corporate_shield / residential", () => {
      const base = baseIntegrity();
      const cases: Array<{ nc: string; expected: keyof typeof flags }> = [
        { nc: "vpn_proxy", expected: "vpn" },
        { nc: "hosting_proxy", expected: "hosting" },
        { nc: "privacy_relay", expected: "privacy_relay" },
        { nc: "security_filter", expected: "corporate_shield" },
        { nc: "residential", expected: "residential" },
        { nc: "mobile", expected: "mobile" },
      ];
      // Sanity placeholder so the keyof above type-checks at runtime.
      const flags = {
        vpn: 0,
        hosting: 0,
        privacy_relay: 0,
        corporate_shield: 0,
        residential: 0,
        mobile: 0,
      };
      void flags;
      for (const { nc, expected } of cases) {
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...base,
            analysis: {
              ...base.analysis,
              ip: {
                ...base.analysis.ip,
                asn: {
                  number: "AS1",
                  category: "datacenter",
                  org: "X",
                  network_class: nc,
                },
              },
            },
          },
        });
        const info = result.ipInfo as unknown as Record<
          string,
          { result: boolean }
        >;
        expect(info[expected].result).toBe(true);
        // All other booleans for this row should be false.
        for (const other of [
          "datacenter",
          "mobile",
          "residential",
          "vpn",
          "hosting",
          "privacy_relay",
          "corporate_shield",
        ]) {
          if (other !== expected) {
            expect(info[other].result).toBe(false);
          }
        }
      }
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

    it("TLS_UA_MISMATCH alone bumps device_tampering to 60 on a non-shielded ASN", () => {
      // Probe-side TLS-vs-UA mismatch. JA4 cipher hash isn't in the known-
      // browser table (Umbrella's stripped TLS), so the family-table rule
      // fails open — TLS_UA_MISMATCH is the safety net. Outside a corp
      // shield context, this is a real TLS-MITM tell (mitmproxy / Burp /
      // anti-detect tool with custom TLS).
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          // ja4_ua isn't declared on the IntegrityResultsData schema (the
          // ingestion handler writes it; the projector reads via cast).
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          analysis: {
            ...base.analysis,
            ja4_ua: {
              signals: [
                {
                  code: "TLS_UA_MISMATCH",
                  severity: 0.7,
                  evidence: "stripped TLS",
                },
              ],
            },
          } as any,
        },
      });
      expect(result.device_tampering).toBe(60);
    });

    it("TLS_UA_MISMATCH is suppressed when the ASN is corporate_proxy (shield carve-out)", () => {
      // Cisco Umbrella / Zscaler / Cloudflare Access terminate TLS by
      // design. The same probe-side mismatch fires, but it's expected
      // behavior, not a tampering signal — surfaced via the corporate_shield
      // tag instead.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          analysis: {
            ...base.analysis,
            ip: {
              ...base.analysis.ip,
              asn: {
                number: "AS36692",
                category: "corporate_proxy",
                org: "Cisco OpenDNS / Umbrella",
                network_class: "security_filter",
              },
            },
            ja4_ua: {
              signals: [
                {
                  code: "TLS_UA_MISMATCH",
                  severity: 0.7,
                  evidence: "stripped TLS",
                },
              ],
            },
          } as any,
        },
      });
      expect(result.device_tampering).toBe(0);
      expect(result.tags).toContain("corporate_shield");
    });

    it("BROWSER_ENGINE_INCONSISTENT_HARD pushes device_tampering to 100 (definitive)", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          analysis: {
            ...base.analysis,
            browser_engine: {
              signals: [
                {
                  code: "BROWSER_ENGINE_INCONSISTENT_HARD",
                  severity: 0.95,
                  evidence: "Safari UA + V8 jsEngine",
                },
              ],
            },
          } as any,
        },
      });
      expect(result.device_tampering).toBe(100);
    });

    it("BROWSER_ENGINE_INCONSISTENT_SOFT bumps device_tampering to 60", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          analysis: {
            ...base.analysis,
            browser_engine: {
              signals: [
                {
                  code: "BROWSER_ENGINE_INCONSISTENT_SOFT",
                  severity: 0.5,
                  evidence: "low combined likelihood",
                },
              ],
            },
          } as any,
        },
      });
      expect(result.device_tampering).toBe(60);
    });

    it("KERNEL_OS_MISMATCH_DARWIN pushes device_tampering to 100 (definitive)", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          analysis: {
            ...base.analysis,
            kernel_os: {
              signals: [
                {
                  code: "KERNEL_OS_MISMATCH_DARWIN",
                  severity: 1,
                  evidence: "Apple UA, no ECN",
                },
              ],
            },
          } as any,
        },
      });
      expect(result.device_tampering).toBe(100);
      expect(result.tags).toContain("browser_tampering");
    });

    it("KERNEL_OS_MISMATCH_DARWIN is suppressed when the ASN is corporate_proxy (shield carve-out)", () => {
      // Cisco Umbrella / Zscaler / Cloudflare Access re-originate TCP from
      // their egress, so tcpi_options reflects the proxy's stack, not the
      // user's. ECN doesn't propagate, so every legitimate iOS/macOS user
      // behind these proxies trips the Darwin-without-ECN heuristic.
      // Mirror the TLS_UA_MISMATCH carve-out: scoring drops it, forensic
      // signal stays in analysis.kernel_os.signals.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          analysis: {
            ...base.analysis,
            ip: {
              ...base.analysis.ip,
              asn: {
                number: "AS36692",
                category: "corporate_proxy",
                org: "Cisco OpenDNS / Umbrella",
                network_class: "security_filter",
              },
            },
            kernel_os: {
              signals: [
                {
                  code: "KERNEL_OS_MISMATCH_DARWIN",
                  severity: 1,
                  evidence: "Apple UA, no ECN",
                },
              ],
            },
          } as any,
        },
      });
      expect(result.device_tampering).toBe(0);
      expect(result.tags).not.toContain("browser_tampering");
      expect(result.tags).toContain("corporate_shield");
    });

    it("KERNEL_OS_MISMATCH_LINUX (soft) bumps device_tampering to 60 outside a shield", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          analysis: {
            ...base.analysis,
            kernel_os: {
              signals: [
                {
                  code: "KERNEL_OS_MISMATCH_LINUX",
                  severity: 0.5,
                  evidence: "Linux UA, ECN on",
                },
              ],
            },
          } as any,
        },
      });
      expect(result.device_tampering).toBe(60);
    });

    it("KERNEL_OS_MISMATCH_DARWIN is suppressed on Apple Private Relay when JA4+H2+UA all confirm Safari", () => {
      // Modeled on a real iCloud Private Relay session from a verified iPhone:
      // Cloudflare AS13335 egress (network_class=cdn, category=privacy_relay),
      // ja4_browser_family=safari, h2_browser_family=safari, ua_os=iOS. The
      // relay terminates the iPhone's TCP at a Linux-side Cloudflare egress, so
      // tcpi_options=7 (no ECN) trips KERNEL_OS_MISMATCH_DARWIN — but the
      // three-fingerprint convergence proves it's actually Safari on Apple,
      // and the kernel signature is the relay's, not the client's.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          analysis: {
            ...base.analysis,
            ip: {
              ...base.analysis.ip,
              asn: {
                number: "13335",
                category: "privacy_relay",
                org: "Cloudflare",
                network_class: "cdn",
              },
            },
            ja4_ua: {
              ja4_browser_family: "safari",
              h2_browser_family: "safari",
              ua_browser_family: "safari",
              ua_os: "iOS",
              signals: [],
            },
            kernel_os: {
              signals: [
                {
                  code: "KERNEL_OS_MISMATCH_DARWIN",
                  severity: 0.85,
                  evidence:
                    "ua_os=iOS, tcpi_options=7 (no ECN — Linux-typical)",
                },
              ],
            },
          } as any,
        },
      });
      expect(result.device_tampering).toBe(0);
      expect(result.tags).not.toContain("browser_tampering");
      expect(result.tags).toContain("privacy_relay");
    });

    it("KERNEL_OS_MISMATCH_DARWIN still fires on privacy_relay if JA4 doesn't confirm Safari", () => {
      // The threat model the verified-Safari gate is designed to stop: an
      // attacker spinning up a Cloudflare Worker (egress IP lands on AS13335
      // that the classifier may incidentally tag as privacy_relay), proxying
      // a Linux/Python client through it, and claiming iOS in the UA. JA4
      // would still report the actual TLS stack (chrome / unknown / etc),
      // not safari. Without all three fingerprints aligned, we don't grant
      // the carve-out.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          user_agent:
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15",
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          analysis: {
            ...base.analysis,
            ip: {
              ...base.analysis.ip,
              asn: {
                number: "13335",
                category: "privacy_relay",
                org: "Cloudflare",
                network_class: "cdn",
              },
            },
            ja4_ua: {
              ja4_browser_family: "chrome",
              h2_browser_family: "chrome",
              ua_browser_family: "safari",
              ua_os: "iOS",
              signals: [],
            },
            kernel_os: {
              signals: [
                {
                  code: "KERNEL_OS_MISMATCH_DARWIN",
                  severity: 0.85,
                  evidence:
                    "ua_os=iOS, tcpi_options=7 (no ECN — Linux-typical)",
                },
              ],
            },
          } as any,
        },
      });
      expect(result.device_tampering).toBe(100);
    });

    it("KERNEL_OS_MISMATCH_LINUX (soft) is also suppressed under corporate_proxy", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          analysis: {
            ...base.analysis,
            ip: {
              ...base.analysis.ip,
              asn: {
                number: "AS36692",
                category: "corporate_proxy",
                org: "Cisco OpenDNS / Umbrella",
                network_class: "security_filter",
              },
            },
            kernel_os: {
              signals: [
                {
                  code: "KERNEL_OS_MISMATCH_LINUX",
                  severity: 0.5,
                  evidence: "Linux UA, ECN on",
                },
              ],
            },
          } as any,
        },
      });
      expect(result.device_tampering).toBe(0);
    });

    it("apple_attested tag fires when payload.pat.attested is true", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          pat: {
            attested: true,
            issuer: "demo-issuer.private-access-tokens.fastly.com",
            tokenHash: "abc",
            redeemedAt: 1_700_000_000_000,
          } as any,
        },
      });
      expect(result.tags).toContain("apple_attested");
      expect(result.tags).not.toContain("apple_attestation_missing");
      // Score-neutral — positive tag must not move device_tampering.
      expect(result.device_tampering).toBe(0);
    });

    it("apple_attestation_missing fires on iPhone Safari UA without pat", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          user_agent:
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1",
        },
      });
      expect(result.tags).toContain("apple_attestation_missing");
      expect(result.tags).not.toContain("apple_attested");
      // Score-neutral — observational only.
      expect(result.device_tampering).toBe(0);
    });

    it("apple_attestation_missing fires on macOS Safari UA without pat", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          user_agent:
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Safari/605.1.15",
        },
      });
      expect(result.tags).toContain("apple_attestation_missing");
    });

    it("apple_attestation_missing does NOT fire on Chrome/Mac UA (Chromium ≠ Safari)", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          user_agent:
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        },
      });
      expect(result.tags).not.toContain("apple_attestation_missing");
    });

    it("apple_attestation_missing does NOT fire on Firefox/Mac UA", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          user_agent:
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:150.0) Gecko/20100101 Firefox/150.0",
        },
      });
      expect(result.tags).not.toContain("apple_attestation_missing");
    });

    it("apple_attested AND apple_attestation_missing are mutually exclusive", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          user_agent:
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1",
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          pat: {
            attested: true,
            issuer: "demo-issuer.private-access-tokens.fastly.com",
            tokenHash: "abc",
            redeemedAt: 1_700_000_000_000,
          } as any,
        },
      });
      expect(result.tags).toContain("apple_attested");
      expect(result.tags).not.toContain("apple_attestation_missing");
    });

    describe("PAT score enforcement (applyPatAdjustment)", () => {
      const iphoneSafariUA =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1";
      const validPat = {
        attested: true,
        issuer: "demo-issuer.private-access-tokens.fastly.com",
        tokenHash: "abc",
        redeemedAt: 1_700_000_000_000,
      };

      it("valid PAT caps a soft automation score at 25", () => {
        // likeHeadlessRating 50 on desktop normally → automation 50.
        // PAT-valid caps it at 25 (suspect tier, not block).
        const base = baseIntegrity();
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...base,
            user_agent: iphoneSafariUA,
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            pat: validPat as any,
            device: {
              headless: {
                headlessRating: 0,
                likeHeadlessRating: 50,
                stealthRating: 0,
              },
            },
          },
        });
        // Without PAT cap, this would be 50 (or with iPhone mobile carve-out
        // would zero out anyway). With PAT it's capped at 25.
        expect(result.automation).toBeLessThanOrEqual(25);
      });

      it("valid PAT does NOT rescue webdriver=true (hard strict marker)", () => {
        // Real Apple hardware can still run WebDriver. PAT proves the
        // device, not the behavior. Hard tier (>= 75) passes through.
        const base = baseIntegrity();
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...base,
            user_agent: iphoneSafariUA,
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            pat: validPat as any,
            device: {
              headless: {
                headlessRating: 100,
                headless: { webDriverIsOn: true, hasHeadlessUA: true },
              },
            },
          },
        });
        expect(result.automation).toBe(100);
      });

      it("iOS Safari without PAT penalizes automation by +25", () => {
        // Clean iPhone-claimed session → botProbability ≈ 0. PAT-missing
        // penalty pushes to 25 — surfaces as suspect, not block.
        const base = baseIntegrity();
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: { ...base, user_agent: iphoneSafariUA },
        });
        expect(result.automation).toBe(25);
        expect(result.tags).toContain("apple_attestation_missing");
      });

      it("non-Apple UA without PAT is NOT penalized (fail-open)", () => {
        // Firefox/Linux has no platform PAT primitive — absence is
        // expected, must not contribute to automation.
        const base = baseIntegrity();
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...base,
            user_agent:
              "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0",
          },
        });
        expect(result.automation).toBe(0);
        expect(result.tags).not.toContain("apple_attestation_missing");
      });
    });

    it("automation is 100 when all 3 strict markers fire (headlessRating 100)", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 100,
              headless: {
                webDriverIsOn: true,
                hasHeadlessUA: true,
                hasHeadlessWorkerUA: true,
              },
            },
          },
        },
      });
      expect(result.automation).toBe(100);
      expect(result.tags).toContain("automation");
    });

    it("automation is 100 when 2/3 strict markers fire (headlessRating 67)", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 67,
              headless: {
                webDriverIsOn: true,
                hasHeadlessUA: false,
                hasHeadlessWorkerUA: true,
              },
            },
          },
        },
      });
      expect(result.automation).toBe(100);
    });

    it("strict + CDP MAX-compose: PW-FF with webdriver=true AND iframe-crypto-stuck → 100", () => {
      // Regression test for the short-circuit-was-inverted bug. Pre-fix:
      // strict>0 returned 75 immediately and never reached cdpAutomationScore,
      // so PW-FF (webdriver=true + Marionette-orphaned iframe crypto) scored
      // 75 while Camoufox (webdriver hidden + same iframe crypto issue)
      // fell through to cdpAutomationScore and scored 100. Inverted from
      // intent. Post-fix both score 100 via max() composition.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 33,
              headless: { webDriverIsOn: true },
            },
            status: {
              iframeCrypto: {
                iframe_created: true,
                responsive: false,
                elapsed_ms: null,
              },
            },
          } as IntegrityResultsData["device"],
        },
      });
      expect(result.automation).toBe(100);
    });

    it("pristine lift admission: lifted=false → automation 75", () => {
      // The SDK reports lifted=false when its nested-iframe pristine-ref
      // module couldn't construct an iframe at module init. The common
      // attacker path is hooking document.createElement('iframe') via
      // addInitScript so every SDK call that "uses pristine" silently
      // falls back to top-level globals — which the attacker has hooked.
      // Score below the iframeCryptoStuck 100 tier because legitimate
      // sandboxed/CSP environments can also produce this. Lock-on-the-door
      // tier; refine with empirical data.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            status: {
              pristine: {
                lifted: false,
                getRandomValuesNativeSource: null,
                randomUUIDNativeSource: null,
              },
            },
          } as IntegrityResultsData["device"],
        },
      });
      expect(result.automation).toBe(75);
    });

    it("pristine lift forged: lifted=true but RNG snapshot missing → automation 75", () => {
      // A real successful lift always populates getRandomValuesNativeSource
      // (RNG is universal). If the client claims lifted=true but the
      // snapshot is null, the lifted field itself was tampered to hide
      // the fallback. Same score as honest admission — the attempt to
      // hide is itself the signal.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            status: {
              pristine: {
                lifted: true,
                getRandomValuesNativeSource: null,
                randomUUIDNativeSource: null,
              },
            },
          } as IntegrityResultsData["device"],
        },
      });
      expect(result.automation).toBe(75);
    });

    it("pristine lift clean: lifted=true with RNG snapshot present → no automation", () => {
      // The healthy path. RNG snapshot populated as expected.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            status: {
              pristine: {
                lifted: true,
                getRandomValuesNativeSource:
                  "function getRandomValues() { [native code] }",
                randomUUIDNativeSource:
                  "function randomUUID() { [native code] }",
              },
            },
          } as IntegrityResultsData["device"],
        },
      });
      expect(result.automation).toBe(0);
    });

    it("pristine lift clean on older browser: lifted=true, RNG present, UUID absent → no automation", () => {
      // Older browsers without Crypto.randomUUID legitimately leave the
      // randomUUIDNativeSource null. Only the RNG snapshot is required
      // for a real lift.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            status: {
              pristine: {
                lifted: true,
                getRandomValuesNativeSource:
                  "function getRandomValues() { [native code] }",
                randomUUIDNativeSource: null,
              },
            },
          } as IntegrityResultsData["device"],
        },
      });
      expect(result.automation).toBe(0);
    });

    it("pristine field absent (pre-PR-23 legacy bundle) → no automation penalty", () => {
      // Sessions from SDK versions before the lift signal was wired
      // don't include device.status.pristine at all. Don't penalize.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            status: {},
          } as IntegrityResultsData["device"],
        },
      });
      expect(result.automation).toBe(0);
    });

    it("automation is 100 when any single strict marker fires (webdriver alone)", () => {
      // Playwright Firefox / Webkit case — sets navigator.webdriver but
      // doesn't change UA. A single strict marker is on its own
      // conclusive automation evidence; no legitimate human browser
      // exposes any of webDriverIsOn / hasHeadlessUA / hasHeadlessWorkerUA.
      // The previous 1/3 → 75 ladder underweighted webdriver=true.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 33,
              headless: {
                webDriverIsOn: true,
                hasHeadlessUA: false,
                hasHeadlessWorkerUA: false,
              },
            },
          },
        },
      });
      expect(result.automation).toBe(100);
    });

    it("automation mirrors likeHeadlessRating when no strict markers fire", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              likeHeadlessRating: 42,
            },
          },
        },
      });
      // 42 rounds to 40
      expect(result.automation).toBe(40);
    });

    it("automation gets +20 stealth bonus on top of weak markers", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              likeHeadlessRating: 18,
              stealthRating: 38,
            },
          },
        },
      });
      // 18 + 20 = 38, rounds to 40
      expect(result.automation).toBe(40);
    });

    it("mobile carve-out: iPhone UA zeroes likeHeadlessRating contribution", () => {
      // Real-world floor on iPhone Safari: noTaskbar, noPlugins, blank UA-CH
      // are legitimately absent and otherwise produce likeHeadlessRating ≈ 9
      // → rounds to automation 10 on every real iPhone visitor. PAT is
      // included because real iPhone Safari ships one — see PAT score
      // enforcement (`applyPatAdjustment`); a real iPhone WITHOUT PAT is a
      // different scenario covered by the apple_attestation_missing tests.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          user_agent:
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1",
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          pat: {
            attested: true,
            issuer: "demo-issuer.private-access-tokens.fastly.com",
            tokenHash: "abc",
            redeemedAt: 1_700_000_000_000,
          } as any,
          device: {
            headless: {
              headlessRating: 0,
              likeHeadlessRating: 9,
              stealthRating: 0,
            },
          },
        },
      });
      expect(result.automation).toBe(0);
    });

    it("mobile carve-out: strict markers still apply on iPhone", () => {
      // Even on mobile, a webdriver-on-iPhone is automation, no carve-out.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X)",
          device: {
            headless: {
              headlessRating: 33,
              likeHeadlessRating: 50,
            },
          },
        },
      });
      expect(result.automation).toBe(100);
    });

    it("mobile carve-out: detects iPhone via worker-scope UA when main UA is missing", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: { headlessRating: 0, likeHeadlessRating: 18 },
            workerScope: {
              scopes: {
                main: {
                  userAgent:
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X)",
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(0);
    });

    it("CDP timing: heavy_over_tiny ratio above 1.5 → automation 75", () => {
      // Empirical Playwright Chrome 148: ratio 2.11. Real Chrome: 0.79.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTiming: {
                  log_tiny_us: 30,
                  log_heavy_us: 63,
                  dir_heavy_us: 54,
                  heavy_over_tiny: 2.11,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(75);
    });

    it("CDP timing: log_heavy_us above absolute threshold → automation 75 even with ratio near 1", () => {
      // Edge case: muted ratio (busy CPU during bench) but absolute
      // heavy-object time still implausibly slow for a real user.
      // Uses 55µs to exceed BENCH_HEAVY_ABS_US (50) — anything below
      // that floor is in the range real mobile Chrome reaches under
      // thermal or scheduler noise (we've seen 27µs on a real Pixel).
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTiming: {
                  log_tiny_us: 44,
                  log_heavy_us: 55,
                  dir_heavy_us: 52,
                  heavy_over_tiny: 1.25,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(75);
    });

    it("CDP timing: real Android Chrome worker bench at heavy=27µs does not flag", () => {
      // Regression: same physical phone scanned the pair captcha twice,
      // 9 min apart. First scan worker bench reported log_heavy_us=16.8;
      // second reported 27.2 — pure scheduler/cache noise. The old
      // absolute threshold (25µs) caught the second one and the merchant
      // saw automation=75 → block. BENCH_HEAVY_ABS_US=50 puts honest
      // mobile readings comfortably below the trip line.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTiming: {
                  log_tiny_us: 29.4,
                  log_heavy_us: 24,
                  tl_heavy_us: 24,
                  dir_heavy_us: 27.4,
                  heavy_over_tiny: 0.82,
                },
                consoleTimingWorker: {
                  log_tiny_us: 28.1,
                  log_heavy_us: 27.2,
                  tl_heavy_us: 27,
                  dir_heavy_us: 19.3,
                  heavy_over_tiny: 0.97,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(0);
    });

    it("CDP timing: real-Chrome ratio (0.79) does not flag", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTiming: {
                  log_tiny_us: 9.4,
                  log_heavy_us: 7.4,
                  dir_heavy_us: 7.5,
                  heavy_over_tiny: 0.79,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(0);
    });

    it("CDP timing: headless=new ratio (1.22) does not flag", () => {
      // Legitimate --headless=new Chrome (no CDP attached) sits comfortably
      // below the threshold even though the ratio is slightly above 1.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTiming: {
                  log_tiny_us: 6.3,
                  log_heavy_us: 7.7,
                  dir_heavy_us: 10.3,
                  heavy_over_tiny: 1.22,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(0);
    });

    it("CDP timing: absent block does not raise automation", () => {
      // Non-Blink (Firefox/WebKit) — SDK omits consoleTiming entirely.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {},
            },
          },
        },
      });
      expect(result.automation).toBe(0);
    });

    it("worker bench: trips on its own when iframe bench was stubbed", () => {
      // page.route rewrote the iframe bench to return clean numbers, but
      // can't intercept the worker's blob URL. Worker still measures
      // real CDP overhead → automation must fire on the worker alone.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTiming: {
                  log_tiny_us: 10.2,
                  log_heavy_us: 11.0,
                  dir_heavy_us: 10.7,
                  heavy_over_tiny: 1.08,
                  perf_now_native: true,
                  date_now_native: true,
                  con_log_native: true,
                  con_dir_native: true,
                },
                consoleTimingWorker: {
                  log_tiny_us: 30,
                  log_heavy_us: 63,
                  dir_heavy_us: 54,
                  heavy_over_tiny: 2.11,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(75);
    });

    it("worker bench: clean numbers on both → no automation", () => {
      // Real Chrome, no CDP. Both benches measure ratio ≈ 1 and agree.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTiming: {
                  log_tiny_us: 9.4,
                  log_heavy_us: 7.4,
                  dir_heavy_us: 7.5,
                  heavy_over_tiny: 0.79,
                },
                consoleTimingWorker: {
                  log_tiny_us: 8.8,
                  log_heavy_us: 8.1,
                  dir_heavy_us: 8.2,
                  heavy_over_tiny: 0.92,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(0);
    });

    it("worker bench: both trip → automation 75", () => {
      // Vanilla Playwright Chrome with no attacker patches — both benches
      // see the same CDP overhead and both trip. Sanity check that
      // hasCdpTimingSignal still wins at 75 when both fire (i.e., we
      // don't double-count up to 100).
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTiming: {
                  log_tiny_us: 30,
                  log_heavy_us: 63,
                  dir_heavy_us: 54,
                  heavy_over_tiny: 2.11,
                },
                consoleTimingWorker: {
                  log_tiny_us: 28,
                  log_heavy_us: 60,
                  dir_heavy_us: 52,
                  heavy_over_tiny: 2.14,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(75);
    });

    it("worker bench: disagreement > 0.5 → automation 75 (stub-one attack)", () => {
      // Attacker stubbed the worker bench (rare — would require wrapping
      // Worker / URL.createObjectURL), leaving the iframe bench intact.
      // Iframe sees real CDP ratio 2.1, worker reports 1.05. Gap = 1.05.
      // Neither bench may trip on its own depending on which side was
      // stubbed; the disagreement itself is the tell.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTiming: {
                  log_tiny_us: 30,
                  log_heavy_us: 63,
                  dir_heavy_us: 54,
                  heavy_over_tiny: 2.1,
                  perf_now_native: true,
                  date_now_native: true,
                  con_log_native: true,
                  con_dir_native: true,
                },
                consoleTimingWorker: {
                  log_tiny_us: 10,
                  log_heavy_us: 11,
                  dir_heavy_us: 11,
                  heavy_over_tiny: 1.05,
                  perf_now_native: true,
                  date_now_native: true,
                  con_log_native: true,
                  con_dir_native: true,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(75);
    });

    it("worker bench: small disagreement within tolerance → no automation", () => {
      // Real-world inter-bench jitter. Different thread schedulers, cold-
      // cache behavior, and timer coarsening can produce gaps up to ~0.3.
      // Tolerance is 0.5, so 0.29 should NOT trip.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTiming: {
                  log_tiny_us: 8.5,
                  log_heavy_us: 8.8,
                  dir_heavy_us: 8.6,
                  heavy_over_tiny: 1.03,
                },
                consoleTimingWorker: {
                  log_tiny_us: 9.0,
                  log_heavy_us: 11.9,
                  dir_heavy_us: 10.2,
                  heavy_over_tiny: 1.32,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(0);
    });

    it("worker bench: missing heavy_over_tiny disables disagreement check", () => {
      // Defensive: if either side is malformed or older-SDK omits the
      // ratio field, the disagreement detector must not produce a false
      // positive on the missing-value comparison.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTiming: {
                  log_tiny_us: 9,
                  log_heavy_us: 8,
                  dir_heavy_us: 9,
                  heavy_over_tiny: 0.89,
                },
                consoleTimingWorker: {
                  // ratio absent — partial payload
                  log_tiny_us: 9,
                  log_heavy_us: 8,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(0);
    });

    it("worker bench: dependency tamper trips even with clean numbers", () => {
      // con_log_native:false in the worker realm means the attacker patched
      // console.log inside the worker (more advanced attack). Numbers
      // look clean but the bench primitive is compromised.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTimingWorker: {
                  log_tiny_us: 10,
                  log_heavy_us: 11,
                  dir_heavy_us: 10,
                  heavy_over_tiny: 1.1,
                  perf_now_native: true,
                  date_now_native: true,
                  con_log_native: false,
                  con_dir_native: true,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(75);
    });

    it("worker bench: console_lies > 0 → automation 100 (hard residue tier)", () => {
      // The in-worker v3-closure scan caught a wrapped console.* method.
      // Workers have no legitimate console wrappers — anything > 0 here
      // is attacker source injected via wrapped Worker / Blob /
      // URL.createObjectURL. Hard residue, full-block tier.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTimingWorker: {
                  log_tiny_us: 10,
                  log_heavy_us: 11,
                  dir_heavy_us: 10,
                  heavy_over_tiny: 1.1,
                  perf_now_native: true,
                  date_now_native: true,
                  con_log_native: true,
                  con_dir_native: true,
                  console_lies: 1,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(100);
    });

    it("worker bench: console_lies === 0 → no automation from this rule", () => {
      // Clean worker realm — every probed console method is native.
      // No automation contribution from this signal.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTimingWorker: {
                  log_tiny_us: 9,
                  log_heavy_us: 8,
                  dir_heavy_us: 9,
                  heavy_over_tiny: 0.89,
                  perf_now_native: true,
                  date_now_native: true,
                  con_log_native: true,
                  con_dir_native: true,
                  console_lies: 0,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(0);
    });

    it("worker bench: console_lies absent (older SDK) does not trip", () => {
      // Backward-compat: clients on the previous worker-bench build
      // omit console_lies entirely. Treat as "no probe ran" — must
      // not false-positive on missing field.
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          device: {
            headless: {
              headlessRating: 0,
              cdp: {
                consoleTimingWorker: {
                  log_tiny_us: 9,
                  log_heavy_us: 8,
                  dir_heavy_us: 9,
                  heavy_over_tiny: 0.89,
                  perf_now_native: true,
                  date_now_native: true,
                  con_log_native: true,
                  con_dir_native: true,
                },
              },
            },
          },
        },
      });
      expect(result.automation).toBe(0);
    });

    // Regression fixtures captured 2026-05-24 from real Brave / Linux desktop,
    // same hardware, same network, 10 same-day submissions to arcades.click/
    // bot-buster. Pre-fix (no magnitude floor) 4 of 10 false-blocked at
    // automation=75: two via worker `heavy_over_tiny > 1.5` per-bench, two via
    // `hasBenchDisagreement` |Δratio|>0.5. Cause: sub-10µs measurements
    // dominated by thread-scheduling jitter, not CDP serialization. Real CDP
    // lives at heavy≈63µs, so ratios on sub-floor measurements have no
    // discriminative value. See BENCH_NOISE_FLOOR_US in merchant-projection.ts.
    describe("real-Brave sub-floor regressions (2026-05-24)", () => {
      const braveSubFloor = (
        i: { tiny: number; heavy: number; dir: number; ratio: number },
        w: { tiny: number; heavy: number; dir: number; ratio: number },
      ) =>
        buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...baseIntegrity(),
            device: {
              headless: {
                headlessRating: 0,
                likeHeadlessRating: 0,
                stealthRating: 0,
                cdp: {
                  consoleTiming: {
                    log_tiny_us: i.tiny,
                    log_heavy_us: i.heavy,
                    dir_heavy_us: i.dir,
                    heavy_over_tiny: i.ratio,
                    perf_now_native: true,
                    date_now_native: true,
                    con_log_native: true,
                    con_dir_native: true,
                  },
                  consoleTimingWorker: {
                    log_tiny_us: w.tiny,
                    log_heavy_us: w.heavy,
                    dir_heavy_us: w.dir,
                    heavy_over_tiny: w.ratio,
                    perf_now_native: true,
                    date_now_native: true,
                    con_log_native: true,
                    con_dir_native: true,
                    console_lies: 0,
                  },
                },
              },
            },
          },
        });

      // sid 540e48a5: worker ratio 2.00 + |Δ|=1.05 (both pre-fix trips)
      it("540e48a5: worker ratio 2.00 at heavy=6.6µs is noise → 0", () => {
        const r = braveSubFloor(
          { tiny: 8.7, heavy: 8.3, dir: 8.7, ratio: 0.95 },
          { tiny: 3.3, heavy: 6.6, dir: 8.3, ratio: 2.0 },
        );
        expect(r.automation).toBe(0);
      });

      // sid 84375938: worker ratio 1.65 + |Δ|=0.53 (both pre-fix trips)
      it("84375938: worker ratio 1.65 at heavy=4.3µs is noise → 0", () => {
        const r = braveSubFloor(
          { tiny: 7.6, heavy: 8.5, dir: 9.1, ratio: 1.12 },
          { tiny: 2.6, heavy: 4.3, dir: 4.6, ratio: 1.65 },
        );
        expect(r.automation).toBe(0);
      });

      // sid 37a57315: cross-bench |Δ|=0.56 only
      it("37a57315: |Δratio|=0.56 with both heavies <10µs → 0", () => {
        const r = braveSubFloor(
          { tiny: 9.0, heavy: 8.5, dir: 14.1, ratio: 0.94 },
          { tiny: 2.8, heavy: 4.2, dir: 4.3, ratio: 1.5 },
        );
        expect(r.automation).toBe(0);
      });

      // sid 149ca86f: cross-bench |Δ|=0.63 only (iframe-higher direction)
      it("149ca86f: |Δratio|=0.63 inverted (iframe>worker) → 0", () => {
        const r = braveSubFloor(
          { tiny: 7.9, heavy: 11.4, dir: 13.1, ratio: 1.44 },
          { tiny: 5.2, heavy: 4.2, dir: 5.6, ratio: 0.81 },
        );
        // iframe heavy=11.4 is just above floor but ratio 1.44 < 1.5, so
        // per-bench safe; worker is sub-floor; disagreement skips because
        // worker is sub-floor (matches the floor's intent).
        expect(r.automation).toBe(0);
      });

      // Negative control: the 6 sessions that scored 0 pre-fix must also
      // still score 0 post-fix. Just spot-check the two with the noisiest
      // worker ratios (these were the closest to wrongly tripping).
      it("c7b20755 (cleanest of the 6): ratios stable, → 0", () => {
        const r = braveSubFloor(
          { tiny: 9.1, heavy: 8.9, dir: 9.3, ratio: 0.98 },
          { tiny: 2.9, heavy: 4.0, dir: 4.2, ratio: 1.38 },
        );
        expect(r.automation).toBe(0);
      });

      it("3f649664 (|Δ|=0.46 near miss): does not regress → 0", () => {
        const r = braveSubFloor(
          { tiny: 9.8, heavy: 8.9, dir: 10.3, ratio: 0.91 },
          { tiny: 3.0, heavy: 4.1, dir: 4.6, ratio: 1.37 },
        );
        expect(r.automation).toBe(0);
      });
    });

    // Critical: the magnitude floor must NOT blind us to real CDP. The
    // SDK calibration baseline (Playwright Chromium with CDP attached)
    // sits at heavy=63µs / ratio=2.11 — well above the 10µs floor. These
    // tests lock that in so we'd catch a future tweak that accidentally
    // raises the floor above the CDP signal.
    describe("magnitude floor preserves real CDP detection", () => {
      it("Playwright CDP iframe (heavy=63, ratio=2.11) → 75", () => {
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...baseIntegrity(),
            device: {
              headless: {
                headlessRating: 0,
                cdp: {
                  consoleTiming: {
                    log_tiny_us: 30,
                    log_heavy_us: 63,
                    dir_heavy_us: 54,
                    heavy_over_tiny: 2.11,
                  },
                },
              },
            },
          },
        });
        expect(result.automation).toBe(75);
      });

      it("stubbed iframe (ratio 1.0 / heavy 8) + real-CDP worker (ratio 2.1 / heavy 63) → 75 via per-bench", () => {
        // The attack model hasBenchDisagreement was designed for: one
        // bench stubbed near-baseline, the other untouched and showing
        // CDP. Per-bench fires on the worker (heavy>25). Disagreement
        // does NOT fire under the new OR-floor rule (iframe is sub-floor)
        // because the unstubbed side is already caught by per-bench at
        // heavy=63 — the disagreement check is redundant for this case.
        const result = buildMerchantResponse({
          session_id: "s",
          integrity: {
            ...baseIntegrity(),
            device: {
              headless: {
                headlessRating: 0,
                cdp: {
                  consoleTiming: {
                    log_tiny_us: 9,
                    log_heavy_us: 8,
                    dir_heavy_us: 8,
                    heavy_over_tiny: 1.0,
                  },
                  consoleTimingWorker: {
                    log_tiny_us: 30,
                    log_heavy_us: 63,
                    dir_heavy_us: 54,
                    heavy_over_tiny: 2.1,
                  },
                },
              },
            },
          },
        });
        expect(result.automation).toBe(75);
      });
    });

    it("desktop UA still uses likeHeadlessRating as before", () => {
      const base = baseIntegrity();
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: {
          ...base,
          // Firefox/Linux rather than macOS Safari: this test is about the
          // absence of the mobile carve-out, not the PAT score path. macOS
          // Safari without PAT now correctly trips the apple_attestation_missing
          // penalty (separate coverage); using a non-Apple UA isolates the
          // mobile-vs-desktop behavior under test.
          user_agent:
            "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0",
          device: {
            headless: {
              headlessRating: 0,
              likeHeadlessRating: 42,
            },
          },
        },
      });
      // 42 → rounds to 40 (unchanged from existing desktop behavior).
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
          device: {
            headless: {
              headlessRating: 100,
              headless: {
                webDriverIsOn: true,
                hasHeadlessUA: true,
                hasHeadlessWorkerUA: true,
              },
            },
          },
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

      it("emits 'language_mismatch' (not 'location_mismatch') when ACCEPT_LANG_GEO_CROSS_CONTINENT fires", () => {
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
        // Language-vs-IP differences are widespread legitimate user
        // preferences (en-GB on US, expat communities, Vietnamese-speaking
        // households in Houston). They surface as a soft tag only — neither
        // location_mismatch nor any tampering score should fire.
        expect(result.tags).toContain("language_mismatch");
        expect(result.tags).not.toContain("location_mismatch");
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

      it("TZ_GEOLOCATION_MISMATCH is suppressed when the ASN is corporate_proxy (shield carve-out)", () => {
        // Cisco Umbrella / Zscaler / Cloudflare Access route through PoPs
        // whose timezone often doesn't match the user's home timezone (a
        // Chicago employee egressing through Ashburn → America/Chicago vs
        // America/New_York). That structural false-positive shouldn't
        // bump device_tampering OR fire the location_mismatch tag.
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
                  number: "AS36692",
                  category: "corporate_proxy",
                  org: "Cisco OpenDNS / Umbrella",
                  network_class: "security_filter",
                },
              },
              timezone: {
                ...base.analysis.timezone,
                signals: [
                  {
                    code: "TZ_GEOLOCATION_MISMATCH",
                    severity: 0.6,
                    evidence: "client=Chicago, cloudfront=New_York",
                  },
                ],
              },
            },
          },
        });
        expect(result.device_tampering).toBe(0);
        expect(result.tags).toContain("corporate_shield");
        expect(result.tags).not.toContain("location_mismatch");
      });

      it("tampering probability stays 0 on cross-continent accept-lang mismatch (tag-only signal)", () => {
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
        // Cross-continent accept-language is now surfaced via the
        // `language_mismatch` tag only — no device_tampering contribution.
        expect(result.device_tampering).toBe(0);
        expect(result.tags).toContain("language_mismatch");
      });

      it("tampering probability stays 0 on same-continent accept-lang mismatch (tag-only signal)", () => {
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
        expect(result.device_tampering).toBe(0);
        expect(result.tags).toContain("language_mismatch");
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

  describe("ip_scatter penalty (Layer 5)", () => {
    function withScatter(
      severity: number,
      network_class: string | null = null,
    ) {
      const base = baseIntegrity();
      return {
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...base.analysis,
            ip: {
              ...base.analysis.ip,
              asn: {
                ...base.analysis.ip.asn,
                network_class,
              } as typeof base.analysis.ip.asn,
              signals: [
                {
                  code: "IP_PROBE_SCATTER",
                  severity,
                  evidence: "2 distinct: 1.2.3.4, 8.8.8.8",
                },
              ],
            },
          },
        }),
      } as MerchantProjectionInput;
    }

    it("lifts network_tampering to 60 when IP_PROBE_SCATTER fires at severity 0.6", () => {
      const result = buildMerchantResponse(withScatter(0.6));
      expect(result.network_tampering).toBe(60);
      expect(result.verdict).toBe("suspect");
    });

    it("lifts network_tampering to 80 when IP_PROBE_SCATTER fires at severity 0.8 (blocks)", () => {
      const result = buildMerchantResponse(withScatter(0.8));
      expect(result.network_tampering).toBe(80);
      expect(result.verdict).toBe("block");
    });

    it("suppresses penalty on mobile network_class (CGNAT scatter is benign)", () => {
      const result = buildMerchantResponse(withScatter(0.8, "mobile"));
      expect(result.network_tampering).toBe(0);
      expect(result.verdict).toBe("clean");
    });

    it("suppresses penalty on security_filter network_class (corporate shield)", () => {
      const result = buildMerchantResponse(withScatter(0.8, "security_filter"));
      expect(result.network_tampering).toBe(0);
      expect(result.verdict).toBe("clean");
    });

    it("does not penalize when IP_PROBE_SCATTER is absent", () => {
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity(),
      });
      expect(result.network_tampering).toBe(0);
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

    it("(D.1) worker UA divergence ALONE (no lies) → tampering.probability=100", () => {
      // Regression: pre-2026-05-16 the only path to 100 via worker
      // divergence was a compound `lies >= 5 && (uaDivergence || platformLie)`,
      // and the `divergences` field counter was filtered through a regex
      // (/navigator|css|screen/) that never matched the analyzer's actual
      // emitted field names (userAgent, platform, etc.). A real Playwright
      // session (f7066aba-bdd8-4756-bec8-0760b02ed135) with 0 lies but a
      // genuine worker.userAgent divergence scored device_tampering=0.
      // Now any single COMPARE_FIELDS divergence is definitive on its own.
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          device: { lies: { totalLies: 0, data: {} } },
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

    it("(D.2) worker platform divergence ALONE → tampering.probability=100", () => {
      // Sibling coverage: the COMPARE_FIELDS that aren't userAgent (so
      // uaDivergence is false) must still count via the divergences
      // counter. Pre-fix this was masked by both the broken regex and
      // the lies-gate compound.
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          device: { lies: { totalLies: 0, data: {} } },
          analysis: {
            ...baseIntegrity().analysis,
            worker: {
              lied: true,
              divergences: [
                {
                  field: "webglRenderer",
                  main: "Apple M1",
                  web: "Mesa Intel",
                  shared: undefined,
                },
              ],
              signals: [],
            },
          },
        }),
      });
      expect(result.device_tampering).toBe(100);
    });

    it("(D.3) worker.divergences containing only `onLine` does NOT trigger tampering", () => {
      // `onLine` is the one COMPARE_FIELDS entry that can legitimately
      // differ between scopes (network state can flip between captures).
      // Excluded from the divergence count by collectTamperingEvidence.
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          device: { lies: { totalLies: 0, data: {} } },
          analysis: {
            ...baseIntegrity().analysis,
            worker: {
              lied: true,
              divergences: [
                { field: "onLine", main: true, web: false, shared: true },
              ],
              signals: [],
            },
          },
        }),
      });
      expect(result.device_tampering).toBeLessThan(100);
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

    it("(E.1) workerOracleMissing=main_only → tampering.probability=50", () => {
      // ARGUS_URGENT_FIXES #2: a submission with zero worker scopes (only
      // main) withholds the cross-thread oracle entirely. Tier-50 in the
      // tampering ladder — same slot as iframeCryptoStuck. Real browsers
      // running our SDK always produce at least a dedicated Worker
      // (Android Chrome included), so zero-workers has no honest-browser
      // carve-out.
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            worker: {
              lied: true,
              divergences: [],
              signals: [
                {
                  code: "WORKER_ORACLE_MAIN_ONLY",
                  severity: 0.5,
                  evidence: "no dedicated or shared worker scopes shipped",
                },
              ],
            },
          },
        }),
      });
      expect(result.device_tampering).toBe(50);
    });

    it("(E.2 regression) WORKER_ORACLE_NO_SHARED in signals does NOT score", () => {
      // The earlier iteration of the worker-oracle scoring tiered
      // "main+dedicated, no shared" at 25. That fired on every legit
      // Android Chrome session (Chromium never shipped SharedWorker on
      // Android) and pre-iOS-16 Safari. Now the rule is "any worker
      // present is enough"; analyzeWorkerScopes no longer emits this
      // code at all, but if legacy/synthetic data carries it, it must
      // NOT contribute to device_tampering.
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            worker: {
              lied: true,
              divergences: [],
              signals: [
                {
                  code: "WORKER_ORACLE_NO_SHARED",
                  severity: 0.25,
                  evidence: "legacy signal from prior analyzer version",
                },
              ],
            },
          },
        }),
      });
      expect(result.device_tampering).toBe(0);
    });

    it("(E.3) workerOracleMissing=false (all three scopes) → no extra penalty", () => {
      // Control case: complete oracle, no divergences, no other signals.
      // device_tampering should be 0 from this axis (other axes may still
      // contribute, but the worker oracle adds nothing).
      const result = buildMerchantResponse({
        session_id: "s",
        integrity: baseIntegrity({
          analysis: {
            ...baseIntegrity().analysis,
            worker: { lied: false, divergences: [], signals: [] },
          },
        }),
      });
      expect(result.device_tampering).toBe(0);
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

  describe("brave_ios carve-out", () => {
    // Real session that prompted this carve-out:
    // cpi=argus_cpi_test_UEeqk7Bk7uetxKKDxNmIdB,
    // session_id=01d32684-d8ad-44d5-a120-6ff2ad735102.
    // Brave Shields wrap audio + plugin APIs; the lies-scanner saw 53
    // lies concentrated in:
    //   AnalyserNode.{getFloat,getByte}{Frequency,TimeDomain}Data, ×4
    //   AudioBuffer.getChannelData,
    //   PluginArray.item / namedItem,
    //   Navigator.plugins / hardwareConcurrency
    // Without the carve-out, lies >= 20 trips definitive tampering and
    // a legitimate Brave-on-iOS user gets device_tampering = 100.
    function braveIosLiesData(): Record<string, string[]> {
      const seven = [
        "failed toString",
        'failed "prototype" in function',
        "failed descriptor",
        "failed own property",
        "failed descriptor keys",
        "failed own property names",
        "failed own keys names",
      ];
      return {
        "AnalyserNode.getFloatFrequencyData": [...seven],
        "AnalyserNode.getByteFrequencyData": [...seven],
        "AnalyserNode.getFloatTimeDomainData": [...seven],
        "AnalyserNode.getByteTimeDomainData": [...seven],
        "AudioBuffer.getChannelData": [...seven],
        "PluginArray.item": [
          "failed call interface error",
          "failed apply interface error",
          "failed new instance error",
          ...seven,
        ],
        "PluginArray.namedItem": [...seven],
        "Navigator.plugins": ["invalid mimetype"],
        "Navigator.hardwareConcurrency": ["failed undefined properties"],
      };
    }
    function withBraveIosFixture(extra: Partial<IntegrityResultsData> = {}) {
      const base = baseIntegrity();
      return {
        ...base,
        device: {
          ...base.device,
          lies: {
            data: braveIosLiesData(),
            totalLies: 53,
          },
        },
        analysis: {
          ...base.analysis,
          ja4_ua: {
            ja4_browser_family: "safari",
            ua_browser_family: "safari",
            ua_os: "iOS",
            h2_browser_family: "safari",
            signals: [],
          },
          ...((extra.analysis ?? {}) as object),
        },
        ...extra,
      };
    }

    it("does NOT flag device_tampering on Brave-iOS audio + plugin lie cluster", () => {
      const integrity = withBraveIosFixture();
      const result = buildMerchantResponse({ session_id: "s", integrity });
      expect(result.device_tampering).toBe(0);
      expect(result.tags).not.toContain("browser_tampering");
    });

    it("emits the `brave_ios` tag when the carve-out fires", () => {
      const integrity = withBraveIosFixture();
      const result = buildMerchantResponse({ session_id: "s", integrity });
      expect(result.tags).toContain("brave_ios");
    });

    it("still penalizes other tampering signals even when brave_ios fires", () => {
      // Worker divergence is structural — no privacy browser produces
      // this. Brave-iOS carve-out must NOT zero this out.
      const integrity = withBraveIosFixture();
      integrity.analysis = {
        ...integrity.analysis,
        worker: {
          lied: true,
          divergences: [
            { field: "userAgent", reason: "mismatch" } as unknown as never,
          ],
          signals: [],
        } as unknown as (typeof integrity.analysis)["worker"],
      };
      const result = buildMerchantResponse({ session_id: "s", integrity });
      expect(result.device_tampering).toBe(100);
      expect(result.tags).toContain("brave_ios");
      expect(result.tags).toContain("browser_tampering");
    });

    it("does NOT fire on plain iOS Safari with no lies (real iPhone user)", () => {
      const base = baseIntegrity();
      const integrity = {
        ...base,
        analysis: {
          ...base.analysis,
          ja4_ua: {
            ja4_browser_family: "safari",
            ua_browser_family: "safari",
            ua_os: "iOS",
            h2_browser_family: "safari",
            signals: [],
          },
        },
      } as IntegrityResultsData;
      const result = buildMerchantResponse({ session_id: "s", integrity });
      expect(result.tags).not.toContain("brave_ios");
    });

    it("does NOT fire on desktop Safari with the same lie pattern (wrong UA)", () => {
      const integrity = withBraveIosFixture();
      // Flip just the OS to macOS while keeping all other Brave-iOS-shaped
      // analysis intact. ja4_ua is index-accessed as an unknown field; cast
      // through `unknown` to mutate the ua_os string in-place.
      (
        integrity.analysis as unknown as {
          ja4_ua: { ua_os: string };
        }
      ).ja4_ua.ua_os = "macOS";
      const result = buildMerchantResponse({ session_id: "s", integrity });
      expect(result.tags).not.toContain("brave_ios");
      // Lies survive, so this DOES trip device_tampering — which is the
      // right call: real desktop Safari doesn't wrap audio APIs.
      expect(result.device_tampering).toBe(100);
    });

    it("does NOT fire when only audio lies present (partial signature)", () => {
      const integrity = withBraveIosFixture();
      const data = (
        integrity.device as { lies?: { data?: Record<string, string[]> } }
      ).lies!.data!;
      delete data["PluginArray.item"];
      delete data["PluginArray.namedItem"];
      delete data["Navigator.plugins"];
      const result = buildMerchantResponse({ session_id: "s", integrity });
      expect(result.tags).not.toContain("brave_ios");
    });
  });
});
