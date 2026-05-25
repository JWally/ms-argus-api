/**
 * ═══════════════════════════════════════════════════════════════════════
 * MERCHANT PROJECTION — END-TO-END DOCUMENTATION
 * ═══════════════════════════════════════════════════════════════════════
 *
 * This file is **runnable documentation**. Every claim it makes about how
 * the verdict pipeline behaves is asserted as a passing test. If anything
 * here drifts from reality, the test breaks; if you change the behavior,
 * update this file and you've simultaneously updated the docs.
 *
 * **Read this top-to-bottom** to understand:
 *
 *   1. The verdict shape — what `clean`, `suspect`, `block` mean
 *   2. The three threat axes — what each represents and how they're
 *      independent
 *   3. The `automation` axis — bot / headless / driver detection
 *   4. The `device_tampering` axis — the ladder of evidence and the
 *      definitive-tampering set
 *   5. The `network_tampering` axis — what counts and the corp-shield
 *      carve-out
 *   6. Network classification — datacenter / mobile / residential /
 *      vpn / hosting / privacy_relay / corporate_shield, what they mean,
 *      and which ones hurt your verdict
 *   7. Mobile classification specifically (ASN-only? CIDR? both?)
 *   8. Browser-engine baselines — the "anomaly counter" — how it
 *      tolerates bimodal legit distributions and when it fires hard
 *
 * The function under test throughout is `buildMerchantResponse`. It
 * takes a stored integrity record (the raw analyzer + sigint output)
 * and projects it down to the merchant-safe response — three threat
 * axes, a verdict, plus tags and identification fields.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  buildMerchantResponse,
  type MerchantProjectionInput,
} from "./merchant-projection";
import type { IntegrityResultsData } from "./payload-schema";
import { _resetBrowserBaselinesForTesting } from "../services/network/browser-baselines";

// ─────────────────────────────────────────────────────────────────────────
// Fixture helpers
// ─────────────────────────────────────────────────────────────────────────

/**
 * The baseline a "clean" session would produce. Every field is at its
 * benign default. Tests below modify just the fields relevant to the
 * scenario being demonstrated.
 */
function cleanSession(
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
    // Firefox UA by default — Firefox doesn't ship sec-ch-ua, so the
    // `uaHeaderMismatch` check (Chromium UA + no sec-ch-ua = spoof) doesn't
    // fire. Tests that need to demonstrate Chrome-specific behavior should
    // override `user_agent` AND populate `request_headers.headers["sec-ch-ua"]`
    // so the check stays satisfied.
    user_agent:
      "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0",
    created_at: 0,
    ...overrides,
  };
}

function project(
  integrity: IntegrityResultsData,
): ReturnType<typeof buildMerchantResponse> {
  const input: MerchantProjectionInput = {
    session_id: integrity.session_id,
    integrity,
  };
  return buildMerchantResponse(input);
}

beforeEach(() => {
  _resetBrowserBaselinesForTesting();
});

// ═════════════════════════════════════════════════════════════════════════
// 1. THE VERDICT
// ═════════════════════════════════════════════════════════════════════════
//
// Every session produces ONE verdict from a fixed three-value enum:
//
//   "clean"   — peak axis < 30
//   "suspect" — peak axis ∈ [30, 70)
//   "block"   — peak axis ≥ 70
//
// The peak is `max(automation, device_tampering, network_tampering)`.
// One axis is enough — the verdict is decided by the worst of the three.
//
// Thresholds: SUSPECT_THRESHOLD = 30, BLOCK_THRESHOLD = 70 (constants
// in `merchant-projection.ts`).

describe("§1 — verdict derivation", () => {
  it("clean: peak axis < 30 → 'clean'", () => {
    // No signals firing. All three axes 0. Verdict clean.
    expect(project(cleanSession()).verdict).toBe("clean");
  });

  it("suspect: peak axis in [30, 70) → 'suspect'", () => {
    // One TZ mismatch only — feeds device_tampering = 35.
    const r = project(
      cleanSession({
        analysis: {
          ...cleanSession().analysis,
          timezone: {
            ...cleanSession().analysis.timezone,
            signals: [
              { code: "TZ_GEOLOCATION_MISMATCH", severity: 0.6, evidence: "" },
            ],
          },
        },
      }),
    );
    expect(r.verdict).toBe("suspect");
    expect(r.device_tampering).toBe(35);
  });

  it("block: peak axis ≥ 70 → 'block'", () => {
    // 6 totalLies → device_tampering = 60. Wait, that's still suspect.
    // For block, we need ≥70. Use 5+ lies + uaDivergence → 100 (definitive).
    const base = cleanSession();
    const r = project({
      ...base,
      device: { lies: { totalLies: 7 } },
      analysis: {
        ...base.analysis,
        worker: {
          ...base.analysis.worker,
          divergences: [
            { field: "userAgent", main: "x", web: "y", shared: "" },
          ],
        },
      },
    });
    expect(r.verdict).toBe("block");
    expect(r.device_tampering).toBe(100);
  });

  it("the worst axis decides — even if the other two are 0", () => {
    // Pure network signal: datacenter ASN with the network analyzer's
    // VPN component set (real ingestion sets this when ASN category is
    // datacenter or vpn_proxy). network_tampering = 100 → BLOCK.
    const base = cleanSession();
    const r = project({
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
        network: {
          ...base.analysis.network,
          vpn_component: 1.0,
          signals: [
            {
              code: "CATEGORY_VPN",
              severity: 1,
              evidence: "asn.category=datacenter",
            },
          ],
        },
      },
    });
    expect(r.verdict).toBe("block");
    expect(r.automation).toBe(0);
    expect(r.device_tampering).toBe(0);
    expect(r.network_tampering).toBe(100);
  });
});

// ═════════════════════════════════════════════════════════════════════════
// 2. THE THREE AXES
// ═════════════════════════════════════════════════════════════════════════
//
// Each axis answers a distinct question. They are computed independently
// — there is no shared cap or normalization. The verdict only ever picks
// the max.
//
//   automation        — Is an automation framework driving this browser?
//                       (WebDriver, headless markers, Puppeteer/Playwright
//                        bindings, anti-detect tool fingerprints)
//
//   device_tampering  — Is the device lying about itself?
//                       (Function.toString proxies, navigator lies, JA4
//                        vs UA mismatch, client-hints vs UA disagreement,
//                        worker-scope divergence, locale tampering,
//                        baseline-derived engine inconsistencies)
//
//   network_tampering — Is the network path being masked?
//                       (VPN, proxy waterfall, datacenter ASN, WebRTC vs
//                        probe-IP disagreement)
//
// Notice what's NOT here: Geo mismatch is a *device_tampering* signal
// (TZ_GEOLOCATION_MISMATCH), not network. Locale mismatch (en-GB on a
// US IP) is intentionally *no signal at all* (carved out — see §4).

// ═════════════════════════════════════════════════════════════════════════
// 3. AUTOMATION
// ═════════════════════════════════════════════════════════════════════════
//
// Three tiers of evidence. Source: `botProbability` in projector.
//
//   Tier 1 STRICT markers — `headless.headlessRating`. Three checks,
//                           each 0/33/67/100% as a boolean group:
//                             - navigator.webdriver === true
//                             - hasHeadlessUA (UA contains "HeadlessChrome"
//                               or similar)
//                             - hasHeadlessWorkerUA (worker scope's UA
//                               also says headless)
//                           Score:
//                             rating ≥ 67 → automation = 100  (block)
//                             rating  > 0 → automation =  75  (block)
//                             rating == 0 → fall through to weak markers
//
//   Tier 2 WEAK markers   — `headless.likeHeadlessRating`. 11 environment
//                           signals (no Chrome object, no plugins, blank
//                           UA-CH, dev tools open, no taskbar, ...). The
//                           % of weak markers maps directly into the score.
//                           ⚠ MOBILE CARVE-OUT: zeroed for mobile UAs.
//                           Real iPhones legitimately lack plugins, taskbar,
//                           UA-CH; without the carve-out every iPhone
//                           floors at automation ≈ 10.
//
//   Tier 3 STEALTH bonus  — `headless.stealthRating`. Anti-detect markers
//                           (Function.toString proxy, missing chrome.runtime,
//                           bad WebGL). +20 added to the weak score when
//                           any fire.

describe("§3 — automation axis", () => {
  it("real human browser → automation 0", () => {
    expect(project(cleanSession()).automation).toBe(0);
  });

  it("STRICT 1/3: webDriverIsOn=true → automation 100 (BLOCK)", () => {
    // Any single strict marker is conclusive — no legitimate browser exposes
    // navigator.webdriver=true / HeadlessChrome UA / headless worker UA.
    // Previously this was 75 under a 1/3-of-3 ladder; the ladder is wrong
    // for `headless` markers (each is individually definitive) and was
    // letting webdriver-on-display PW-FF score lower than webdriver-hidden
    // Camoufox via short-circuit ordering. Bumped to 100.
    const base = cleanSession();
    const r = project({
      ...base,
      device: {
        headless: {
          headlessRating: 33, // 1/3 strict markers
          headless: { webDriverIsOn: true },
        },
      },
    });
    expect(r.automation).toBe(100);
    expect(r.verdict).toBe("block");
  });

  it("STRICT 2/3+: → automation 100 (BLOCK)", () => {
    const base = cleanSession();
    const r = project({
      ...base,
      device: {
        headless: {
          headlessRating: 67,
          headless: { webDriverIsOn: true, hasHeadlessUA: true },
        },
      },
    });
    expect(r.automation).toBe(100);
  });

  it("WEAK markers on a desktop UA contribute proportionally", () => {
    // 50% of 11 weak markers → ~50 raw → rounded to 50.
    const base = cleanSession();
    const r = project({
      ...base,
      device: {
        headless: {
          headlessRating: 0, // no strict markers
          likeHeadlessRating: 50, // 50% of weak markers
          stealthRating: 0,
        },
      },
    });
    expect(r.automation).toBe(50); // suspect, not block
    expect(r.verdict).toBe("suspect");
  });

  it("MOBILE CARVE-OUT: weak markers zeroed for iPhone UA", () => {
    // Same likeHeadlessRating=50 as above, but with iPhone UA → automation 0.
    // Real iPhones look "headless-y" by desktop standards (no plugins, no
    // chrome runtime, no taskbar). Penalizing them for that would block
    // every legit iPhone visitor. PAT included because real iPhone Safari
    // ships one (see PAT score enforcement in §3); without PAT the
    // apple_attestation_missing penalty would add +25 here.
    const base = cleanSession();
    const r = project({
      ...base,
      user_agent:
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1",
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
          likeHeadlessRating: 50,
          stealthRating: 0,
        },
      },
    });
    expect(r.automation).toBe(0);
  });

  it("STEALTH bonus: +20 added to weak score when any stealth marker fires", () => {
    const base = cleanSession();
    const r = project({
      ...base,
      device: {
        headless: {
          headlessRating: 0,
          likeHeadlessRating: 30,
          stealthRating: 1, // any nonzero
        },
      },
    });
    expect(r.automation).toBe(50); // 30 + 20
  });
});

// ═════════════════════════════════════════════════════════════════════════
// 4. DEVICE TAMPERING
// ═════════════════════════════════════════════════════════════════════════
//
// Source: `tamperingProbabilityFromEvidence` in projector. Two-stage:
//
// Stage 1 — DEFINITIVE TAMPERING → 100. Any of these alone:
//   - lies.totalLies ≥ 20            (massive API patching)
//   - JA4_UA_BROWSER_MISMATCH        (TLS family ≠ UA-claimed family)
//   - worker.divergences ≥ 1         (ANY split on the worker analyzer's
//                                     COMPARE_FIELDS — userAgent, platform,
//                                     hardwareConcurrency, deviceMemory,
//                                     languages, webglRenderer/Vendor,
//                                     webgl2Renderer/Vendor, appVersion,
//                                     product — except `onLine` which can
//                                     flip naturally with network state.
//                                     Real browsers propagate navigator
//                                     state identically; the only mechanism
//                                     producing a split is automation
//                                     overriding the main realm without
//                                     touching worker contexts.)
//   - uaDivergence                   (worker userAgent ≠ main; subset of
//                                     divergences but checked explicitly)
//   - platformLie                    (Navigator.platform getter patched)
//   - WebRTC API tampered            (RTCPeerConnection patched)
//   - chUaMismatch                   (sec-ch-ua platform/mobile ≠ UA)
//   - browserEngineHardBreak         (claimed browser_version's baseline
//                                     has count=0 for an observed value)
//
// Stage 2 — GRADED LADDER (first matching tier wins):
//   60: lies ≥ 5
//   60: uaHeaderMismatch          (Chromium UA + no sec-ch-ua header)
//   60: localeTamper              (intl ≠ navigator OR worker ≠ main locale)
//   60: tlsUaMismatch             (probe sees stripped TLS — corp-shield
//                                  carve-out applies, see below)
//   60: browserEngineSoft         (combined NB likelihood under the
//                                  baseline is below threshold; baseline
//                                  must be n≥1000 + version-specific)
//   35: tzGeoMismatch             (client TZ ≠ CF edge TZ — corp-shield
//                                  carve-out applies)
//   25: lies ≥ 1                  (any single lie)
//
// Carve-outs (suppressed at evidence-collection time when ASN is
// `corporate_proxy`, i.e. Cisco Umbrella / Zscaler / Cloudflare Access):
//   - tlsUaMismatch  (shields legitimately strip TLS)
//   - tzGeoMismatch  (shield egress PoP TZ ≠ user's home TZ)
//
// Things that DON'T contribute to device_tampering by design:
//   - langGeoCrossContinent / langGeoCrossCountry  (Accept-Language vs
//     IP country mismatch — surfaces as the soft `language_mismatch`
//     tag instead. en-GB on a US iPhone is widespread legit behavior.)

describe("§4 — device_tampering axis", () => {
  it("clean → 0", () => {
    expect(project(cleanSession()).device_tampering).toBe(0);
  });

  it("DEFINITIVE: ja4Mismatch alone → 100", () => {
    const base = cleanSession();
    const r = project({
      ...base,
      analysis: {
        ...base.analysis,
        worker: {
          ...base.analysis.worker,
          signals: [
            {
              code: "JA4_UA_BROWSER_MISMATCH",
              severity: 0.95,
              evidence: "JA4 family chromium vs UA Safari",
            },
          ],
        },
      },
    });
    expect(r.device_tampering).toBe(100);
  });

  it("DEFINITIVE: 20+ lies alone → 100", () => {
    const base = cleanSession();
    const r = project({ ...base, device: { lies: { totalLies: 20 } } });
    expect(r.device_tampering).toBe(100);
  });

  it("DEFINITIVE: compound — 5 lies + UA divergence in worker → 100", () => {
    const base = cleanSession();
    const r = project({
      ...base,
      device: { lies: { totalLies: 5 } },
      analysis: {
        ...base.analysis,
        worker: {
          ...base.analysis.worker,
          divergences: [
            { field: "userAgent", main: "x", web: "y", shared: "" },
          ],
        },
      },
    });
    expect(r.device_tampering).toBe(100);
  });

  it("LADDER 60: 5+ lies, no other triggers → 60", () => {
    const r = project(cleanSession({ device: { lies: { totalLies: 7 } } }));
    expect(r.device_tampering).toBe(60);
  });

  it("LADDER 35: lone TZ mismatch → 35 (suspect)", () => {
    const base = cleanSession();
    const r = project({
      ...base,
      analysis: {
        ...base.analysis,
        timezone: {
          ...base.analysis.timezone,
          signals: [
            { code: "TZ_GEOLOCATION_MISMATCH", severity: 0.6, evidence: "" },
          ],
        },
      },
    });
    expect(r.device_tampering).toBe(35);
  });

  it("CARVE-OUT: TZ mismatch on a corp-shield ASN → 0 (no penalty)", () => {
    // Cisco Umbrella employees get egressed through PoPs in different
    // timezones than their home. Without the carve-out, every shielded
    // user would suspect on TZ mismatch.
    const base = cleanSession();
    const r = project({
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
            { code: "TZ_GEOLOCATION_MISMATCH", severity: 0.6, evidence: "" },
          ],
        },
      },
    });
    expect(r.device_tampering).toBe(0);
    expect(r.tags).toContain("corporate_shield");
    expect(r.tags).not.toContain("location_mismatch");
  });

  it("language_mismatch is intentionally TAG-ONLY (never bumps device_tampering)", () => {
    // en-GB visitor on a US IP → tag yes, score no. Common legit pattern
    // (British-spelling preference users in the US, expat communities).
    const base = cleanSession();
    const r = project({
      ...base,
      analysis: {
        ...base.analysis,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        locale_geo: {
          hasLocationMismatch: true,
          hasLocaleTamper: false,
          signals: [
            {
              code: "ACCEPT_LANG_GEO_CROSS_CONTINENT",
              severity: 0.7,
              evidence: "en-GB vs US",
            },
          ],
        } as any,
      },
    });
    expect(r.device_tampering).toBe(0);
    expect(r.tags).toContain("language_mismatch");
  });
});

// ═════════════════════════════════════════════════════════════════════════
// 5. NETWORK TAMPERING
// ═════════════════════════════════════════════════════════════════════════
//
// Source: `networkTamperingScore`. Computed as:
//
//   max(vpnScore, proxy_waterfall.threat_score)
//
// Where:
//   - vpnScore considers ASN category (datacenter / vpn_proxy → up to
//     100), MSS-based VPN detection (network.vpn_component, derived from
//     stripped MSS values that indicate tunnel encapsulation), and
//     WebRTC vs probe-IP consensus (mismatch → suspect).
//   - proxy_waterfall.threat_score is computed in a separate analyzer
//     (proxy waterfall rules) and ranges 0/50/100.
//
// Carve-outs:
//   - corporate_proxy ASN → vpnScore zeroed (the shield's MSS reduction
//     is benign tunnel encapsulation, not a VPN). proxy_waterfall has
//     its own carve-out logic.
//   - WebRTC-matches-probes damper: when WebRTC IP matches probe IPs at
//     /16, the proxy_component gets capped (not zeroed) — see
//     applyWebrtcFusion comment in projector.

describe("§5 — network_tampering axis", () => {
  it("clean residential session → 0", () => {
    expect(project(cleanSession()).network_tampering).toBe(0);
  });

  it("datacenter ASN + vpn_component=1.0 → network_tampering 100", () => {
    // The network analyzer at ingestion time sets vpn_component=1.0 when
    // ASN category is datacenter or vpn_proxy (CATEGORY_VPN signal).
    // The projector reads vpn_component into vpnScore — that's what
    // produces network_tampering for datacenter sessions.
    const base = cleanSession();
    const r = project({
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
        network: {
          ...base.analysis.network,
          vpn_component: 1.0,
          signals: [
            {
              code: "CATEGORY_VPN",
              severity: 1,
              evidence: "asn.category=datacenter",
            },
          ],
        },
      },
    });
    expect(r.network_tampering).toBe(100);
    expect(r.verdict).toBe("block");
  });

  it("CARVE-OUT: corporate_proxy ASN → 0 (Umbrella/Zscaler look like VPNs but aren't)", () => {
    // The shield's MSS reduction (snd_mss=1298 typical) trips LIKELY_VPN
    // and would normally set vpn_component=1.0. Carve-out zeros it.
    const base = cleanSession();
    const r = project({
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
        network: {
          ...base.analysis.network,
          vpn_component: 1.0, // LIKELY_VPN fired
          signals: [
            { code: "LIKELY_VPN", severity: 0.7, evidence: "snd_mss=1298" },
          ],
        },
      },
    });
    expect(r.network_tampering).toBe(0);
  });

  it("proxy waterfall threat_score is the OTHER input — max of (vpn, proxy)", () => {
    const base = cleanSession();
    const r = project({
      ...base,
      analysis: {
        ...base.analysis,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        proxy_waterfall: { threat_score: 100 } as any,
      },
    });
    expect(r.network_tampering).toBe(100);
  });
});

// ═════════════════════════════════════════════════════════════════════════
// 6. NETWORK CLASSIFICATION — what hurts your verdict
// ═════════════════════════════════════════════════════════════════════════
//
// `ipInfo.asn.network_class` is the broad 12-value taxonomy returned to
// merchants. Convenience booleans (`ipInfo.datacenter.result`, .mobile,
// .vpn, .hosting, .privacy_relay, .corporate_shield, .residential) are
// derived from `network_class` alone — single source of truth.
//
//   network_class      | network_tampering impact
//   ───────────────────┼──────────────────────────────
//   residential        | 0  (clean default)
//   mobile             | 0  (clean — also tagged 'cellular')
//   business           | 0
//   education          | 0
//   government         | 0
//   satellite          | 0
//   cdn                | 0  (rare in merchant traffic)
//   datacenter         | 100 (BLOCK — real iPhones don't originate here)
//   vpn_proxy          | up to 100 via vpnScore
//   hosting_proxy      | up to 100 via vpnScore (residential proxy networks
//                      |     resold by Bright Data, SOAX, etc.)
//   privacy_relay      | tag-only, no score (Apple iCloud Private Relay —
//                      |     legitimate consumer privacy product)
//   corporate_proxy    | tag-only, no score (Cisco Umbrella / Zscaler /
//   (network_class:    |     Cloudflare Access — corp-shield carve-out
//   security_filter)   |     suppresses TLS/TZ/network signals)

describe("§6 — network classification → verdict impact", () => {
  function withNetworkClass(
    category: string,
    networkClass: string,
    extraNetwork: Partial<{ vpn_component: number }> = {},
  ) {
    const base = cleanSession();
    return project({
      ...base,
      analysis: {
        ...base.analysis,
        ip: {
          ...base.analysis.ip,
          asn: {
            number: "AS1",
            category,
            org: "test",
            network_class: networkClass,
          },
        },
        network: {
          ...base.analysis.network,
          ...extraNetwork,
        },
      },
    });
  }

  it("residential → CLEAN, no network penalty", () => {
    const r = withNetworkClass("residential", "residential");
    expect(r.verdict).toBe("clean");
    expect(r.ipInfo.residential.result).toBe(true);
  });

  it("mobile → CLEAN, tagged 'cellular' is in detectCellular logic", () => {
    const r = withNetworkClass("mobile", "mobile");
    expect(r.verdict).toBe("clean");
    expect(r.ipInfo.mobile.result).toBe(true);
  });

  it("datacenter → BLOCK, datacenter+hyperscaler tags fire (with network analyzer's vpn_component)", () => {
    const r = withNetworkClass("datacenter", "datacenter", {
      vpn_component: 1.0,
    });
    expect(r.verdict).toBe("block");
    expect(r.ipInfo.datacenter.result).toBe(true);
    expect(r.tags).toContain("hyperscaler");
  });

  it("corporate_proxy → CLEAN, corporate_shield tag, no penalty", () => {
    const r = withNetworkClass("corporate_proxy", "security_filter");
    expect(r.verdict).toBe("clean");
    expect(r.ipInfo.corporate_shield.result).toBe(true);
    expect(r.tags).toContain("corporate_shield");
  });

  it("privacy_relay → CLEAN, tag-only", () => {
    const r = withNetworkClass("privacy_relay", "privacy_relay");
    expect(r.verdict).toBe("clean");
    expect(r.ipInfo.privacy_relay.result).toBe(true);
    expect(r.tags).toContain("privacy_relay");
  });
});

// ═════════════════════════════════════════════════════════════════════════
// 7. MOBILE CLASSIFICATION — ASN, CIDR, or both?
// ═════════════════════════════════════════════════════════════════════════
//
// Both, with CIDR overlay winning when present. The chain is in
// `analyzeIpConsistency.deriveNetworkClass`:
//
//   1. PER-IP, in caller-supplied priority order [tcpIp, tlsIp, apiIp,
//      webrtcIp]:
//        a. Hand-curated CIDR overlay (cidr-overlay.ts) — small,
//           manually-vetted rules for known mixed-use ASNs (AT&T 7018
//           is part U-Verse residential, part Mobility cellular —
//           CIDR splits them).
//        b. Auto-discovered overlay (auto-overlay.ts) — S3-loaded rules
//           populated by the nightly ip-class-discoverer Lambda from
//           RDAP lookups.
//      First-IP-with-a-hit returns immediately; lower-priority IPs'
//      hits become a fallback.
//   2. ASN dict (asn-classifier) — regex-on-org-name + manual overrides.
//   3. Lower-priority IPs' CIDR hits (the fallback collected in step 1).
//   4. Legacy AsnCategory catalog.
//
// Why per-IP-priority-then-per-source: a Cisco-Umbrella session whose
// probe IP isn't in the overlay yet (new PoP) but whose webrtc/api IP
// matches an AT&T residential CIDR would otherwise misclassify as
// residential. The ASN dict (which knows AS36692 → security_filter)
// beats the residential leak.
//
// This file isn't the right place to fully test the IP classifier (see
// `src/analysis/ip-consistency/index.test.ts`), but the documentation
// matters: **when /16 is the same but ASN is mixed-use, CIDR splits
// the prefix.** Two phones on AT&T 7018 in 166.199.0.0/16 might
// classify as `mobile` if the CIDR overlay knows that range, or
// `residential` if not.

describe("§7 — mobile classification", () => {
  it("'mobile' tag follows network_class, not just ASN", () => {
    // The same AT&T ASN can produce either depending on which CIDR the
    // probe IP falls in. Here we just demonstrate that network_class is
    // the single source of truth at the projector level.
    const base = cleanSession();
    const r = project({
      ...base,
      analysis: {
        ...base.analysis,
        ip: {
          ...base.analysis.ip,
          asn: {
            number: "AS7018",
            category: "residential", // legacy field — mixed-use ASN default
            org: "AT&T",
            network_class: "mobile", // CIDR overlay said this is mobile
          },
        },
      },
    });
    expect(r.ipInfo.mobile.result).toBe(true);
    expect(r.ipInfo.residential.result).toBe(false);
    expect(r.ipInfo.asn.network_class).toBe("mobile");
  });
});

// ═════════════════════════════════════════════════════════════════════════
// 8. BROWSER-ENGINE BASELINE — the "anomaly counter"
// ═════════════════════════════════════════════════════════════════════════
//
// This is the per-(browser, version, incognito) histogram-based detector.
// Source: `analyzeBrowserEngine` and `browser-baselines.ts`.
//
// **What it does**: for each session, look up the histogram for the
// claimed (browser, version, incognito) tuple. For each invariant field
// (jsEngine, layoutEngine, navigator.vendor, evalToStringLength,
// stackFormatHash, windowPrefixes.{apple,moz,webkit}, css.keyCount,
// navigator.propertiesLength, headless.chromium, plus TLS fields like
// JA4 cipher hash and H2 pseudo-header order), compute the observed
// value's prevalence in the baseline.
//
// **Hard break** (`BROWSER_ENGINE_INCONSISTENT_HARD`, sev 0.95 →
// device_tampering = 100, joins the definitive set):
//   - The observed value has count == 0 in the baseline AND
//   - that field has totalForField ≥ MIN_HARD_BREAK_N (default 1000)
//
// Hard break gates per FIELD, not per baseline. That handles two
// edge cases:
//   1. TLS fields are skipped at training time on corp-shielded sessions,
//      so a Chrome 147 baseline might have totalForField=10000 for jsEngine
//      but only totalForField=8000 for tls.ja4_cipher_hash. Each field
//      gates on its own population.
//   2. A newly-added field with sparse data across an otherwise-mature
//      baseline doesn't fire spurious hard breaks.
//
// **Soft signal** (`BROWSER_ENGINE_INCONSISTENT_SOFT`, sev 0.5 →
// device_tampering = 60):
//   - Combined naive-Bayes log-likelihood across all fields is below
//     -8 AND
//   - baseline.source is "version" or "version_no_incognito" (NOT
//     engine_family — see cold-start protection below) AND
//   - baseline.n_sessions ≥ MIN_HARD_BREAK_N
//
// The naive-Bayes calculation uses Laplace smoothing with ε=0.5:
//   P(value | claimed) = (count + 0.5) / (totalForField + 0.5 · |V|)
// where |V| is the number of distinct values seen for that field.
//
// **Cold-start protection** (none of these will produce false positives
// during the warmup period for a new browser version):
//   - No baseline exists for (browser, version) → falls back to
//     (browser, version, NOT incognito), then engine-family. Either
//     fallback can hard-break (engine_family needs n ≥ 5000) but soft
//     never fires from engine_family.
//   - Baseline exists but n < 1000 → no hard breaks AND no soft signals.
//   - Baseline exists with n ≥ 1000 but a specific field's
//     totalForField < 1000 → no hard break on that field; other
//     well-populated fields still gate normally.
//
// **The 50/49/1 question** (legitimate bimodal distribution): if a
// browser version's stackFormatHash has two values at 50% / 49% with
// 1% in the long tail, what happens to a session with the 49%
// (minority-but-legit) value?
//
//   - With Laplace ε=0.5 over n=10000: P(xyz) ≈ 0.49.
//   - logP ≈ log(0.49) ≈ -0.71.
//   - That's well above the -3 outlier-display threshold.
//   - It contributes -0.71 to the combined logL.
//   - All other fields are at their dominant values, contributing close
//     to 0 (e.g. log(0.99) ≈ -0.01).
//   - Total logL ≈ -0.71, well above the -8 firing threshold.
//   - **No signal.** The 49% user is correctly cleared.
//
// What WOULD fire:
//   - A value with NO history (hard break, if baseline n ≥ 1000)
//   - A 1%-prevalence value plus other low-probability fields combining
//     to total logL < -8 (soft signal — possible outlier)

describe("§8 — browser-engine baselines", () => {
  // The browser-engine ANALYZER runs at ingestion time and writes its
  // signals to `analysis.browser_engine.signals`. The PROJECTOR (under
  // test in this file) reads those signals as already-decided evidence.
  // To document the projector's response to each kind of signal, these
  // tests inject the relevant signal directly into the row — exactly as
  // the analyzer would have written it. Bimodal-tolerance, hard-break,
  // and cold-start behavior are all properties of the ANALYZER itself
  // and are documented + tested in `src/analysis/browser-engine/index.test.ts`.

  function withBrowserEngineSignal(code: string, severity: number) {
    const base = cleanSession();
    return {
      ...base,
      analysis: {
        ...base.analysis,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        browser_engine: {
          signals: [{ code, severity, evidence: "" }],
        } as any,
      },
    };
  }

  it("BROWSER_ENGINE_INCONSISTENT_HARD → device_tampering = 100 (joins definitive set)", () => {
    // What the ANALYZER fires when the claimed (browser, version)'s
    // baseline has count=0 for an observed value AND the baseline is
    // well-populated (n ≥ MIN_HARD_BREAK_N = 1000).
    // Example: claims Safari but jsEngine=V8.
    const r = project(
      withBrowserEngineSignal("BROWSER_ENGINE_INCONSISTENT_HARD", 0.95),
    );
    expect(r.device_tampering).toBe(100);
    expect(r.verdict).toBe("block");
  });

  it("BROWSER_ENGINE_INCONSISTENT_SOFT → device_tampering = 60 (suspect)", () => {
    // What the ANALYZER fires when the combined naive-Bayes log-likelihood
    // across all fields is < -8 AND the baseline source is version-specific
    // (NOT engine_family — see analyzer cold-start protection) AND
    // baseline.n_sessions ≥ 1000.
    const r = project(
      withBrowserEngineSignal("BROWSER_ENGINE_INCONSISTENT_SOFT", 0.5),
    );
    expect(r.device_tampering).toBe(60);
    expect(r.verdict).toBe("suspect");
  });

  // ── Notes on the ANALYZER'S behavior (tested in its own file) ──────────
  //
  // The analyzer enforces these properties at the histogram level:
  //
  //  1. **Bimodal tolerance.** A field with a 50% / 49% / 1% distribution
  //     does NOT flag the 49%-prevalence user. With Laplace smoothing
  //     ε=0.5 over n=10000, P(xyz)≈0.49, logP≈-0.71. Other fields
  //     contribute ≈0 to the combined logL. Total logL ≈ -0.71, well
  //     above the -8 firing threshold. No signal.
  //
  //     Even the 1%-prevalence value alone (logP≈-4.6) doesn't fire — the
  //     soft signal threshold is across ALL fields combined.
  //
  //  2. **Hard break only when count=0 AND well-populated.** A never-seen
  //     value in a baseline with ≥ 1000 samples for THAT FIELD fires
  //     BROWSER_ENGINE_INCONSISTENT_HARD. The gating is per-field, not
  //     per-baseline — a sparsely-populated TLS field on an otherwise-
  //     mature baseline doesn't fire spurious breaks.
  //
  //  3. **Cold-start safe.** Soft signal requires baseline.source !==
  //     "engine_family" AND baseline.n_sessions ≥ 1000. The engine-family
  //     fallback aggregates legitimately-different versions (Firefox 149
  //     css.keyCount=382 vs 150=383) — without this gate, every real
  //     session against a family histogram would look like an outlier.
  //
  //     Both protections proven by the analyzer tests (see
  //     `src/analysis/browser-engine/index.test.ts §soft signal cold-start
  //     protection`).
  //
  //  4. **Corp-shield carve-out (training side).** The aggregator
  //     (`browser-baseline-builder`) drops corp-shielded sessions from
  //     TLS-field training to avoid every browser collapsing to the
  //     shield's stripped JA4. JS fields still contribute. The projector
  //     doesn't need its own carve-out for this signal — the analyzer
  //     simply has nothing to report when its baseline is clean.
});

// ═════════════════════════════════════════════════════════════════════════
// 9. END-TO-END — what real session profiles look like
// ═════════════════════════════════════════════════════════════════════════
//
// These are realistic combinations to anchor the mental model.

describe("§9 — end-to-end realistic scenarios", () => {
  it("real iPhone Safari on T-Mobile cellular → CLEAN", () => {
    const r = project(
      cleanSession({
        user_agent:
          "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1",
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        pat: {
          attested: true,
          issuer: "demo-issuer.private-access-tokens.fastly.com",
          tokenHash: "abc",
          redeemedAt: 1_700_000_000_000,
        } as any,
        analysis: {
          ...cleanSession().analysis,
          ip: {
            ...cleanSession().analysis.ip,
            asn: {
              number: "AS21928",
              category: "mobile",
              org: "T-MOBILE",
              network_class: "mobile",
            },
          },
        },
      }),
    );
    expect(r.verdict).toBe("clean");
    expect(r.ipInfo.mobile.result).toBe(true);
  });

  it("Cisco Umbrella employee with no other red flags → CLEAN, corporate_shield tag", () => {
    // This is the case that motivated multiple carve-outs. Without them
    // every Fortune 500 employee blocks because:
    //   - TLS interception → TLS_UA_MISMATCH (carve-out)
    //   - PoP egress timezone ≠ user TZ → TZ_GEOLOCATION_MISMATCH (carve-out)
    //   - MSS reduction by tunnel → LIKELY_VPN (carve-out via vpnScore)
    const r = project(
      cleanSession({
        analysis: {
          ...cleanSession().analysis,
          ip: {
            ...cleanSession().analysis.ip,
            asn: {
              number: "AS36692",
              category: "corporate_proxy",
              org: "Cisco OpenDNS / Umbrella",
              network_class: "security_filter",
            },
          },
          network: {
            ...cleanSession().analysis.network,
            vpn_component: 1.0,
            signals: [
              {
                code: "LIKELY_VPN",
                severity: 0.7,
                evidence: "snd_mss=1298",
              },
            ],
          },
          timezone: {
            ...cleanSession().analysis.timezone,
            signals: [
              {
                code: "TZ_GEOLOCATION_MISMATCH",
                severity: 0.6,
                evidence: "Chicago vs New_York",
              },
            ],
          },
        },
      }),
    );
    expect(r.verdict).toBe("clean");
    expect(r.tags).toContain("corporate_shield");
    expect(r.tags).not.toContain("location_mismatch");
    expect(r.network_tampering).toBe(0);
    expect(r.device_tampering).toBe(0);
  });

  it("WebDriver-driven Chrome on a hosting provider → BLOCK on automation", () => {
    // Hosting/datacenter ASNs feed `vpnScore` via category, BUT only when
    // category is `datacenter` or `vpn_proxy`. `hosting_proxy` (Bright
    // Data, SOAX, residential-proxy networks) is its own bucket and the
    // current scoring routes it through the proxy_waterfall threat_score
    // rather than vpnScore. Demonstrating the automation block here.
    const r = project(
      cleanSession({
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        request_headers: {
          headers: { "sec-ch-ua": '"Google Chrome";v="147"' },
          cookie_names: [],
        } as any,
        device: {
          headless: {
            headlessRating: 33, // navigator.webdriver === true
            headless: { webDriverIsOn: true },
          },
        },
        analysis: {
          ...cleanSession().analysis,
          ip: {
            ...cleanSession().analysis.ip,
            asn: {
              number: "AS16509",
              category: "datacenter",
              org: "AMAZON-02",
              network_class: "datacenter",
            },
          },
          network: {
            ...cleanSession().analysis.network,
            vpn_component: 1.0, // network analyzer sets this for datacenter ASNs
          },
        },
      }),
    );
    expect(r.verdict).toBe("block");
    expect(r.automation).toBe(100); // any strict marker → 100
    expect(r.network_tampering).toBe(100); // datacenter
  });

  it("anti-detect browser with stripped TLS on a residential IP → SUSPECT on device_tampering", () => {
    const r = project(
      cleanSession({
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        analysis: {
          ...cleanSession().analysis,
          ip: {
            ...cleanSession().analysis.ip,
            asn: {
              number: "AS7922",
              category: "residential",
              org: "COMCAST",
              network_class: "residential",
            },
          },
          ja4_ua: {
            signals: [
              {
                code: "TLS_UA_MISMATCH",
                severity: 0.7,
                evidence: "Chromium UA + 13 ciphers + no GREASE",
              },
            ],
          },
        } as any,
      }),
    );
    expect(r.verdict).toBe("suspect"); // device_tampering = 60
    expect(r.device_tampering).toBe(60);
    expect(r.network_tampering).toBe(0); // residential — no network signal
  });
});
