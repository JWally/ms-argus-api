/**
 * @fileoverview Merchant-safe response projection.
 *
 * Projects the full internal session + integrity record down to a small,
 * FingerprintJS-Pro-shaped surface that a merchant API consumer (or a
 * merchant's bot-building adversary who signed up for a $100 account)
 * can safely see.
 *
 * Design principles:
 *  - Shape tracks FPJS Pro product blocks: `identification`, `bot`, `vpn`,
 *    `proxy`, `incognito`, `tampering`, `ipLocation`, `ipInfo`. Makes
 *    integration familiar for customers coming from the market leader.
 *  - Deliberately tighter than FPJS: we do NOT expose `vpn.methods`,
 *    `tampering.anomalyScore`, `ipInfo.datacenter.name`, or
 *    `rawDeviceAttributes`/`components`. All addable later without
 *    breaking — removal would break consumers.
 *  - No raw signal names. Adversaries should not read which specific
 *    check fired ("TLS_PLATFORM_MISMATCH") — they get categorical
 *    `result` booleans and bucketed `confidence` instead.
 *  - No raw numeric component scores. The server's noisy-OR proxy score,
 *    vpn_component, etc. stay internal; merchants get a categorical
 *    low/medium/high `confidence`. This kills the scalar tuning oracle.
 *  - `networkIntegrity.score` is our differentiator — FPJS doesn't
 *    publish a WebRTC↔probe consensus score.
 *
 * @module helpers/merchant-projection
 */

import { createHash } from "node:crypto";
import type { IntegrityResultsData } from "./payload-schema";
import {
  networkTamperingScore,
  proxyScore,
  vpnScore,
} from "../scoring/network-tampering";
import {
  detectCellular,
  detectCorporateShield,
  detectNoWebrtc,
  probabilityFromUnit,
  type MerchantProjectionInput,
} from "../scoring/shared";
import {
  deriveWorkerScopeEvidence,
  type WorkerScopeEvidence,
} from "./worker-scope-evidence";
import {
  deriveDeviceHistory,
  deriveIpVelocity,
  type IpVelocityProjection,
  type MerchantDeviceHistory,
} from "../projections/activity";
import {
  automationProbability,
  detectDeveloperTools,
  hasIframeCryptoStuck,
} from "../scoring/automation";

// Re-export so external test files and downstream consumers that import the
// type from helpers/merchant-projection keep compiling unchanged.
export type {
  IpVelocityProjection,
  MerchantDeviceHistory,
  MerchantProjectionInput,
};

/** Truncated SHA-256 length (hex chars). 40 bits of entropy — ample for
 *  cross-session correlation at merchant scale; compact enough to read. */
const CRYPTO_DEVICE_ID_LEN = 10;

/**
 * Truncated SHA-256 hex of the SPKI-base64 pubkey. Exposed to merchants as a
 * stable cross-session identifier without handing them the raw key bytes.
 * Same input always → same output, so correlation works; merchants can't
 * use the hash to impersonate the client or reconstruct the key.
 */
function hashPubkey(pubkey: string): string {
  return createHash("sha256")
    .update(pubkey)
    .digest("hex")
    .slice(0, CRYPTO_DEVICE_ID_LEN);
}

/**
 * Categorical merchant-safe tag vocabulary. Composable — a request can be
 * `["vpn", "browser_tampering"]` simultaneously. Kept alongside the
 * FPJS-style product blocks as a convenience summary for dashboards.
 */
export type MerchantTag =
  | "vpn"
  | "proxy"
  | "hyperscaler"
  | "corporate_shield"
  | "privacy_relay"
  | "browser_tampering"
  | "automation"
  | "incognito"
  | "cellular"
  | "location_mismatch"
  | "language_mismatch"
  | "no_webrtc"
  // Apple Private Access Token outcomes. Tag-only at the moment — neither
  // moves device_tampering. apple_attestation_missing is observational
  // only; we'll decide whether/how to penalize after collecting real-world
  // data on its prevalence vs. confirmed-tampered traffic.
  | "apple_attested"
  | "apple_attestation_missing"
  // Positive privacy-browser identification — these are emitted when we
  // recognize the browser by its known fingerprinting-protection
  // signature (audio API wraps, plugin spoofing, etc.). Mutually
  // exclusive with `browser_tampering`: when one of these tags is set
  // we deliberately attribute the underlying lies to the browser
  // rather than counting them toward `device_tampering`. Merchants
  // can filter on these for analytics / policy (some merchants
  // welcome privacy browsers, some don't).
  | "brave_ios";

export interface BrowserDetails {
  browserName: string | null;
  browserVersion: string | null;
  os: string | null;
  osVersion: string | null;
  device: string | null;
  userAgent: string | null;
}

export interface MerchantIdentification {
  /** SHA-256 of the client's ECDSA pubkey. Cryptographic identity.
   *  Null on legacy bundles. */
  crypto_device_id: string | null;
  /** Whether the cryptographic identity signature verified. Null when the
   *  client didn't send a `device_identity` block. No verification reasons
   *  are exposed — those are internal pipeline state. */
  crypto_verified: boolean | null;
  /** Three-store client UUID (IndexedDB + localStorage + first-party cookie),
   *  respawned across stores by the client so it survives any single-store
   *  clear. Stable across sessions for the same browser profile. Null when
   *  every store failed (private mode + sandboxed iframe, etc). */
  client_uuid: string | null;
  /** Opaque id carried across sessions in the CloudFront-stamped third-party
   *  cookie. Null when the cookie is absent or failed verification. */
  tpc_id: string | null;
  /** Unix seconds when the cookie was originally minted at the CF edge.
   *  Null when the cookie is absent or failed verification. */
  tpc_created: number | null;
  /** "pass" iff the cookie verified against the current TLS token; "fail"
   *  when the cookie arrived but tampered/mismatched; null when absent. */
  tpc_verified: "pass" | "fail" | null;
  /**
   * Network-derived stable ID — backup identifier for fraud prevention when
   * crypto_device_id and tpc_id aren't available. Two-pass derivation:
   *   - "category_residential": hash(ip_/24 + ua) for residential / satellite
   *     networks. Stable for weeks-to-months per household.
   *   - "asn_fallback": hash(asn + ip_/24 + ua) for ASNs the classifier
   *     doesn't recognize. Lower trust — merchant should weight accordingly.
   *   - null + source "none": mobile / vpn / datacenter / corporate / etc.
   *     IP+UA hashing collapses strangers in these populations; rely on
   *     crypto_device_id or device fingerprinting instead.
   */
  network_id: string | null;
  network_id_source: "category_residential" | "asn_fallback" | "none";
  browserDetails: BrowserDetails;
}

export interface MerchantIpLocation {
  city: string | null;
  country: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
}

export interface MerchantIpInfo {
  asn: {
    number: number | null;
    organization: string | null;
    /**
     * Legacy 5-value categorization (datacenter / vpn_proxy / corporate_proxy
     * / privacy_relay / mobile). Kept for backwards compatibility with
     * pre-existing integrations. New consumers should prefer `network_class`
     * (broader, 12-value taxonomy) and the convenience booleans below.
     */
    category: string | null;
    /**
     * Broader consumer-network class derived from the IPtoASN+regex dataset
     * (mobile / residential / datacenter / vpn_proxy / hosting_proxy / cdn /
     * satellite / privacy_relay / security_filter / business / education /
     * government). Distinguishes residential vs cellular within mixed-use
     * ASNs (notably AT&T 7018). Null when the ASN isn't in the dataset.
     */
    network_class: string | null;
    /**
     * Optional enrichment from the RDAP auto-overlay (registrant operator +
     * sub-allocated customer when ARIN records one) and PeeringDB (operator-
     * self-declared type + IX presence count). Coverage is sparse: present
     * only when at least one field is known for this session's IP/ASN.
     * PeeringDB values are operator-self-declared and may shift between
     * weekly rebuilds — treat as a hint, not a contract.
     */
    metadata: {
      parent_org?: string;
      customer_org?: string;
      pdb_type?: string;
      ix_count?: number;
    } | null;
  };
  /** Convenience booleans for routing — all derived from `asn.network_class`. */
  datacenter: { result: boolean };
  /** True when network_class is mobile. Useful for stable-ID branching. */
  mobile: { result: boolean };
  /** True when network_class is residential. */
  residential: { result: boolean };
  /** True when network_class is vpn_proxy (declared VPN provider). */
  vpn: { result: boolean };
  /** True when network_class is hosting_proxy (residential proxy networks
   *  resold by Bright Data, SOAX, etc.). */
  hosting: { result: boolean };
  /** True when network_class is privacy_relay (Apple iCloud Private Relay). */
  privacy_relay: { result: boolean };
  /** True when network_class is security_filter (Cisco Umbrella, Zscaler,
   *  Cloudflare Access — corporate cloud-egress shields). */
  corporate_shield: { result: boolean };
}

export interface MerchantRequestHeaders {
  /** Curated subset of request headers (see CAPTURED_REQUEST_HEADER_NAMES). */
  headers: Record<string, string>;
  /** Cookie *names* present on the request — values are never captured. */
  cookie_names: string[];
}

/**
 * Verdict bucket derived from the three threat axes. Blocks at any
 * axis ≥ BLOCK_THRESHOLD; suspect at any axis ≥ SUSPECT_THRESHOLD.
 * Customers route on this; the three numerical axes are for explanation.
 */
export type Verdict = "clean" | "suspect" | "block";

const SUSPECT_THRESHOLD = 30;
const BLOCK_THRESHOLD = 70;

/**
 * The merchant-safe response shape. Returned as the top-level body of
 * `GET /v1/session/{cpi}/{session_id}` (spread, not wrapped).
 *
 * Three threat axes — all 0–100, all "lower is better":
 *   - automation:        is an automation framework driving this?
 *                        (headless markers, CDP, webdriver, framework tells)
 *   - device_tampering:  is the device lying about itself?
 *                        (Function.toString patches, CH-UA / JA4 / H2 vs UA
 *                         disagreement, worker-scope divergence)
 *   - network_tampering: is the network path being masked?
 *                        (VPN, proxy waterfall, datacenter ASN, geo / TZ
 *                         mismatch, WebRTC vs probe IP disagreement)
 *
 * Visitor-side manipulation only — third-party MITM/interception surfaces
 * separately as a tag, not on the network_tampering axis.
 */
export interface MerchantSafeResponse {
  session_id: string;
  /** Epoch ms. Null when the record pre-dates the field. */
  created_at: number | null;
  /** TTL epoch seconds (when this record will be purged). */
  ttl: number | null;

  /** Lower = better. Driven by headless / CDP / framework detection. */
  automation: number;
  /** Lower = better. Driven by tampering evidence (lies, CH-UA / JA4 / H2
   *  mismatch, worker divergence, locale spoofing). */
  device_tampering: number;
  /** Lower = better. Driven by VPN / proxy / WebRTC-probe consensus. */
  network_tampering: number;
  /** Routing convenience: derived from the three axes via fixed thresholds. */
  verdict: Verdict;

  identification: MerchantIdentification;

  /** Representative client IP. MAC-verified WebRTC IP when available, else
   *  probe consensus. Null when integrity score < 0.5. */
  ip: string | null;
  ipLocation: MerchantIpLocation;
  ipInfo: MerchantIpInfo;

  /** Direct observation, not probabilistic. */
  incognito: { result: boolean };
  /** Direct observation. Surfaces the existing devTools detector — useful
   *  for high-value flows where dev-tools open is a step-up-auth trigger. */
  developer_tools: { result: boolean };

  /** Derived cross-realm consistency evidence. No raw navigator values. */
  worker_scope_evidence: WorkerScopeEvidence | null;

  /** Categorical labels — composable with the threat axes. Useful for
   *  routing rules that need finer-grained context than the axis numbers. */
  tags: MerchantTag[];

  /** Curated request headers preserved at ingestion. Null for pre-capture records. */
  requestHeaders: MerchantRequestHeaders | null;

  /**
   * Per-IP velocity rollup for the current hour. Stamped at ingest from the
   * (ip, bucket) row in the ip-velocity table. Useful directly as a fraud
   * signal:
   *   - high `hits` + low `distinct_devices_est` ⇒ same device, retries
   *   - high `distinct_devices_est` on residential ⇒ proxy / botnet exit
   *   - high `block_rate` ⇒ historically problematic IP
   *
   * Null when the velocity table wasn't reachable at ingest, or for rows
   * ingested before this feature shipped (mid-2026).
   */
  ip_velocity_1h: IpVelocityProjection | null;

  /**
   * Per-device recurrence summary. Computed from the encrypted device-
   * history blob the SDK carries between scans (HKDF-derived AES-GCM key,
   * 50-visit ring buffer). Aggregates only — no individual visit records.
   *
   * Null when the client presented no blob (legitimate first visit shows
   * `freshDevice: true` inside `null`-equivalent counters; see field flags).
   */
  device_history: MerchantDeviceHistory | null;
}

// --- Tag derivation helpers (pure, testable) ---

function detectHyperscaler(input: MerchantProjectionInput): boolean {
  return input.integrity?.analysis.ip.asn.category === "datacenter";
}

function detectIncognito(input: MerchantProjectionInput): boolean {
  const isPrivate = (
    input.integrity?.device as
      | { incognito?: { isPrivate?: boolean } }
      | undefined
  )?.incognito?.isPrivate;
  return isPrivate === true;
}

/**
 * "proxy" tag fires when the waterfall's merchant-facing threat score
 * is >= 50. Decouples the tag from the legacy proxyScore() so tags
 * agree with the threat value shown on the merchant response.
 */
function detectProxy(input: MerchantProjectionInput): boolean {
  return (input.integrity?.analysis?.proxy_waterfall?.threat_score ?? 0) >= 50;
}

/**
 * Apple Private Relay / Cloudflare WARP / similar consumer privacy
 * relays. Not a fraud signal on its own — merchants decide.
 */
function detectPrivacyRelay(input: MerchantProjectionInput): boolean {
  return input.integrity?.analysis?.ip?.asn?.category === "privacy_relay";
}

/**
 * Visitor's claimed timezone contradicts CloudFront-observed IP timezone.
 * Restricted to TZ disagreement only — accept-language vs IP country lives
 * under the separate `language_mismatch` tag, since en-GB-on-US-IP and
 * similar are common-enough preferences that they shouldn't share a tag
 * with timezone manipulation.
 */
function detectLocationMismatch(input: MerchantProjectionInput): boolean {
  if (!input.integrity) return false;
  const e = collectTamperingEvidence(input.integrity);
  return e.tzGeoMismatch;
}

/**
 * Accept-Language vs CloudFront IP country differs. Surfaced as a soft
 * advisory tag — does *not* contribute to device_tampering. The US has
 * Vietnamese-speaking households in Houston and British-spelling enthusiasts
 * everywhere; an en-GB UI on a US IP is not fraud. Merchants who care can
 * filter on this tag themselves.
 */
function detectLanguageMismatch(input: MerchantProjectionInput): boolean {
  if (!input.integrity) return false;
  const e = collectTamperingEvidence(input.integrity);
  return e.langGeoCrossContinent || e.langGeoCrossCountry;
}
const UA_HEADER_KEY = "user-agent";
/**
 * Heuristic: does the visitor's UA claim an Apple platform (iOS Safari or
 * macOS Safari)? Used to gate the apple_attestation_missing tag — we only
 * surface "no attestation" as informational on UAs that *should* be able
 * to produce one. Excludes Chrome/Firefox/Edge on Mac (those don't
 * trigger PAT regardless of OS) by requiring AppleWebKit + Safari without
 * the Chrom* / Firefox / Edg fingerprints.
 */
function isAppleClaimedUA(
  integrity: IntegrityResultsData | undefined,
): boolean {
  if (!integrity) return false;
  const headers = integrity.request_headers?.headers ?? {};
  const ua = integrity.user_agent ?? headers[UA_HEADER_KEY] ?? "";
  if (!ua) return false;
  if (!/AppleWebKit\/[\d.]+/.test(ua)) return false;
  if (!/Safari\/[\d.]+/.test(ua)) return false;
  // Exclude Chromium-stack browsers (Chrome / Edge / Opera all carry
  // AppleWebKit + Safari tokens for legacy reasons).
  if (/Chrom(e|ium)\/|Edg(e|A|iOS)?\/|OPR\//.test(ua)) return false;
  // Firefox iOS uses a different UA format (FxiOS), but include it as
  // Apple-claimed since it runs on top of WKWebView and the OS handles
  // PAT for it the same way.
  return /iPhone|iPad|iPod|Macintosh/.test(ua);
}

/** PAT absence is scoreable only on iOS/iPadOS, where issuance is expected. */
function isAppleMobileClaimedUA(
  integrity: IntegrityResultsData | undefined,
): boolean {
  if (!isAppleClaimedUA(integrity)) return false;
  const headers = integrity?.request_headers?.headers ?? {};
  const ua = integrity?.user_agent ?? headers[UA_HEADER_KEY] ?? "";
  return /iPhone|iPad|iPod/.test(ua);
}

type TagPredicate = [MerchantTag, (i: MerchantProjectionInput) => boolean];

function buildTags(
  input: MerchantProjectionInput,
  probs: { bot: number; vpn: number; proxy: number; tampering: number },
): MerchantTag[] {
  const predicates: TagPredicate[] = [
    ["vpn", () => probs.vpn >= 50],
    ["proxy", detectProxy],
    ["hyperscaler", detectHyperscaler],
    ["corporate_shield", detectCorporateShield],
    ["privacy_relay", detectPrivacyRelay],
    ["browser_tampering", () => probs.tampering >= 50],
    ["automation", () => probs.bot >= 50],
    ["incognito", detectIncognito],
    ["cellular", detectCellular],
    ["location_mismatch", detectLocationMismatch],
    ["language_mismatch", detectLanguageMismatch],
    ["no_webrtc", detectNoWebrtc],
    // Positive trust signal — successful PAT round-trip end-to-end.
    ["apple_attested", (i) => i.integrity?.pat?.attested === true],
    // Observational only — Apple-claimed UA without an attestation. No
    // shield carve-out by design (PAT is L7 and most enterprise proxies
    // bypass Apple services); the data will tell us whether one's needed.
    [
      "apple_attestation_missing",
      (i) =>
        isAppleClaimedUA(i.integrity) && !(i.integrity?.pat?.attested === true),
    ],
    // Privacy-browser positive identification. See `detectBraveIos` for
    // the signature. When this fires the underlying lies are attributed
    // to the browser and do NOT contribute to device_tampering (handled
    // upstream in `collectTamperingEvidence`).
    [
      "brave_ios",
      (i) => (i.integrity ? detectBraveIos(i.integrity).matched : false),
    ],
  ];
  return predicates.filter(([, p]) => p(input)).map(([tag]) => tag);
}

/**
 * A verified PAT caps soft automation evidence but cannot erase hard residue.
 * Missing PAT adds a suspect-tier penalty only for iOS/iPadOS outside known
 * corporate shields, where the origin round trip is expected to work.
 */
const PAT_AUTOMATION_HARD_FLOOR = 75;
const PAT_VALID_AUTOMATION_CAP = 25;
const PAT_MISSING_AUTOMATION_PENALTY = 25;

function applyPatAdjustment(
  automation: number,
  input: MerchantProjectionInput,
): number {
  if (input.integrity?.pat?.attested === true) {
    if (automation >= PAT_AUTOMATION_HARD_FLOOR) return automation;
    return Math.min(automation, PAT_VALID_AUTOMATION_CAP);
  }

  if (
    isAppleMobileClaimedUA(input.integrity) &&
    !isCorporateShieldedAsn(input.integrity ?? ({} as IntegrityResultsData))
  ) {
    return Math.min(100, automation + PAT_MISSING_AUTOMATION_PENALTY);
  }
  return automation;
}

interface Ja4UaSignalInfo {
  ja4Mismatch: boolean;
  h2Mismatch: boolean;
  /** True iff any of the above arrived with sev >= 0.9 (high-confidence). */
  strongMismatch: boolean;
}

function readJa4UaSignals(integrity: IntegrityResultsData): Ja4UaSignalInfo {
  const sigs: Array<{ code: string; severity: number }> = [
    ...((
      integrity.analysis as {
        ja4_ua?: { signals?: Array<{ code: string; severity: number }> };
      }
    ).ja4_ua?.signals ?? []),
    ...(integrity.analysis.worker.signals ?? []),
  ];
  const ja4 = sigs.find((s) => s.code === "JA4_UA_BROWSER_MISMATCH");
  const h2 = sigs.find((s) => s.code === "H2_UA_BROWSER_MISMATCH");
  return {
    ja4Mismatch: !!ja4,
    h2Mismatch: !!h2,
    strongMismatch: (ja4?.severity ?? 0) >= 0.9 || (h2?.severity ?? 0) >= 0.9,
  };
}

function hasJa4UaMismatch(integrity: IntegrityResultsData): boolean {
  return readJa4UaSignals(integrity).ja4Mismatch;
}

/**
 * TLS-vs-UA mismatch (cipher count + GREASE presence). Distinct from
 * JA4_UA_BROWSER_MISMATCH — that needs the JA4 cipher hash to be in the
 * known-browser table, which fails open when a TLS-terminating proxy
 * re-originates with a stripped cipher list (Cisco Umbrella, Zscaler,
 * mitmproxy/Burp). TLS_UA_MISMATCH is the safety net for that case —
 * emitted by `analyzeJa4Ua` from the rules in
 * `analysis/ja4-ua/tls-rules.ts` over the raw `cipher_count` / `has_grease`
 * fields the h2-probe captures.
 */
function hasTlsUaMismatch(integrity: IntegrityResultsData): boolean {
  const sigs = (
    integrity.analysis as {
      ja4_ua?: { signals?: Array<{ code: string }> };
    }
  ).ja4_ua?.signals;
  return Array.isArray(sigs) && sigs.some((s) => s.code === "TLS_UA_MISMATCH");
}

/**
 * Corporate-shield carve-out for the TLS_UA_MISMATCH signal. When a corp
 * security gateway (Cisco Umbrella / Zscaler / Cloudflare Access) is in the
 * path, TLS interception with a stripped cipher list is *expected behavior*,
 * not a tampering signal. The shield is already surfaced as a tag and tells
 * merchants why the TLS layer looks munged. Same shape as the network-axis
 * carve-out in applyWebrtcFusion / corporate-shield zeroing.
 */
function isCorporateShieldedAsn(integrity: IntegrityResultsData): boolean {
  return integrity.analysis?.ip?.asn?.category === "corporate_proxy";
}

/**
 * Apple Private Relay / Cloudflare WARP carve-out for the kernel-OS-mismatch
 * signal. Privacy-relay terminates the client's TCP at a Linux egress box
 * (Cloudflare/Akamai), so the kernel observes Linux-typical TCP options
 * even when the actual client is iOS/macOS — same architectural shape as the
 * corporate-shield case.
 *
 * BUT: unlike corporate-shield ASNs (Cisco Umbrella / Zscaler), where ASN
 * ownership is essentially 1:1 with proxy infrastructure, CDN ASNs like
 * Cloudflare AS13335 and Akamai AS16625 host millions of unrelated tenants
 * (Workers, Pages, R2, third-party CDN customers). Granting a kernel-OS-
 * mismatch carve-out on `category=privacy_relay` alone would let an attacker
 * spin up a Cloudflare Worker, proxy traffic through it claiming iOS UA,
 * and bypass the device-tampering check.
 *
 * To close that gap we require three independent fingerprints to converge
 * before treating the relay path as legitimate Apple traffic:
 *   1. JA4 family is safari (TLS ClientHello matches Safari's BoringSSL stack —
 *      extension order, GREASE positions, cipher list)
 *   2. H2 family is safari (HTTP/2 SETTINGS + frame ordering matches Safari)
 *   3. UA OS is iOS or macOS
 *
 * Defeating all three requires literally running Safari on a real Apple
 * device — a Linux/Python script behind a Cloudflare Worker fails JA4 + H2
 * immediately. Sophisticated attackers running Safari on real iPhones can
 * still clear this gate, but at that point the cost-per-session is high
 * enough that the kernel-OS axis stops being the right detection layer.
 *
 * Like the corporate-shield carve-out, this only suppresses the SCORE
 * contribution. The raw KERNEL_OS_MISMATCH_DARWIN signal stays on
 * `analysis.kernel_os.signals` for forensic review.
 */
function isVerifiedAppleRelay(integrity: IntegrityResultsData): boolean {
  // Path 1 (authoritative): the row was stamped with apple_relay_egress at
  // ingest time because the client IP matched Apple's published Private
  // Relay egress range (mask-api.icloud.com/egress-ip-ranges.csv, loaded by
  // services/network/apple-relay.ts and looked up in buildIntegrityItem).
  // This is ground truth — only iOS 15+/iPadOS 15+/macOS Monterey+ devices
  // with iCloud+ subscription originate from these CIDRs. Empty list (S3
  // fetch failure / first deploy before refresh job) leaves the field
  // absent and we fall through to path 2.
  if ((integrity as { apple_relay_egress?: unknown }).apple_relay_egress) {
    return true;
  }

  // Path 2 (heuristic fallback): JA4 + H2 + UA convergence on Safari.
  // Catches the case where the IP list isn't yet loaded but the TLS
  // fingerprint passes through unstripped. Less reliable than path 1 —
  // Fastly egress sometimes strips the H2 fingerprint to null, which
  // fails this check (the original FP we observed on 146.75.248.145).
  if (integrity.analysis?.ip?.asn?.category !== "privacy_relay") return false;
  const ja4Ua = (
    integrity.analysis as {
      ja4_ua?: {
        ja4_browser_family?: string | null;
        h2_browser_family?: string | null;
        ua_os?: string | null;
      };
    }
  ).ja4_ua;
  if (!ja4Ua) return false;
  return (
    ja4Ua.ja4_browser_family === "safari" &&
    ja4Ua.h2_browser_family === "safari" &&
    (ja4Ua.ua_os === "iOS" || ja4Ua.ua_os === "macOS")
  );
}

/**
 * Browser-engine consistency signals from `analyzeBrowserEngine`. Two
 * tiers, both feed device_tampering:
 *   - HARD: claimed browser_version's baseline has count=0 for an
 *     observed value (and baseline is well-populated). Joins
 *     isDefinitiveTampering → device_tampering = 100.
 *   - SOFT: combined naive-Bayes log-likelihood is below threshold but
 *     no individual field is structurally impossible. Slot at 60.
 */
function readBrowserEngineSignals(integrity: IntegrityResultsData): {
  hard: boolean;
  soft: boolean;
} {
  const sigs = (
    integrity.analysis as {
      browser_engine?: { signals?: Array<{ code: string }> };
    }
  ).browser_engine?.signals;
  if (!Array.isArray(sigs)) return { hard: false, soft: false };
  return {
    hard: sigs.some((s) => s.code === "BROWSER_ENGINE_INCONSISTENT_HARD"),
    soft: sigs.some((s) => s.code === "BROWSER_ENGINE_INCONSISTENT_SOFT"),
  };
}

/**
 * True when JA4 (TLS hello) AND H2 (HTTP/2 SETTINGS + frame order) both
 * identify the client as Safari and the UA's OS family is Darwin
 * (iOS / macOS). This is the "wire-level corroboration" gate that
 * demotes KERNEL_OS_MISMATCH_DARWIN from structural tier-100 to soft
 * tier-60: if all three independent fingerprints (JA4, H2, UA) agree
 * on Safari/Darwin but TCP options say no-ECN, the most plausible
 * explanation is a network-path artifact (CGNAT / ECN-stripping
 * middlebox) — not a Linux box pretending to be iOS.
 *
 * Empirical justification: 14 of 119 (12%) real AT&T residential
 * iPhone Safari sessions in dev-jw over a 7-day window produced
 * `options=7`. A Linux→iOS spoofer can't fake Safari's BoringSSL
 * stack JA4 or its H2 frame ordering, so the corroboration is a
 * tight gate that recovers the FPs without unblocking real spoofs.
 */
function ja4AndH2CorroborateDarwin(integrity: IntegrityResultsData): boolean {
  const ja4Ua = (
    integrity.analysis as {
      ja4_ua?: {
        ja4_browser_family?: string | null;
        h2_browser_family?: string | null;
        ua_os?: string | null;
      };
    }
  ).ja4_ua;
  if (!ja4Ua) return false;
  return (
    ja4Ua.ja4_browser_family === "safari" &&
    ja4Ua.h2_browser_family === "safari" &&
    (ja4Ua.ua_os === "iOS" || ja4Ua.ua_os === "macOS")
  );
}

function readKernelOsSignals(integrity: IntegrityResultsData): {
  hard: boolean;
  soft: boolean;
} {
  const sigs = (
    integrity.analysis as {
      kernel_os?: { signals?: Array<{ code: string }> };
    }
  ).kernel_os?.signals;
  if (!Array.isArray(sigs)) return { hard: false, soft: false };
  const darwinMismatch = sigs.some(
    (s) => s.code === "KERNEL_OS_MISMATCH_DARWIN",
  );
  const linuxMismatch = sigs.some((s) => s.code === "KERNEL_OS_MISMATCH_LINUX");
  // Wire corroboration: when JA4 + H2 both say Safari and UA agrees,
  // the Darwin TCP-mismatch is almost certainly a network artifact
  // (CGNAT / ECN-stripping middlebox), not a Linux spoof. Demote
  // hard → soft so the row lands at tier-60 (suspect) instead of
  // tier-100 (block). A Linux box pretending to be iOS still gets
  // hard because its JA4 + H2 won't match Safari's BoringSSL stack.
  const corroborated = darwinMismatch && ja4AndH2CorroborateDarwin(integrity);
  return {
    hard: darwinMismatch && !corroborated,
    soft: linuxMismatch || corroborated,
  };
}

/** Read the device.lies.data keys — each key identifies a tampered API. */
function readLieKeys(integrity: IntegrityResultsData | undefined): string[] {
  const data = (
    integrity?.device as
      | { lies?: { data?: Record<string, unknown> } }
      | undefined
  )?.lies?.data;
  return data ? Object.keys(data) : [];
}

/** (A) Detect RTCPeerConnection API tampering — the bot patched WebRTC itself. */
const WEBRTC_API_LIE_PATTERN =
  /createDataChannel|createOffer|setLocalDescription|setRemoteDescription|iceConnectionState|connectionState|localDescription|addIceCandidate|generateCertificate/;

function detectWebrtcApiTampering(
  integrity: IntegrityResultsData | undefined,
): boolean {
  return readLieKeys(integrity).some((k) => WEBRTC_API_LIE_PATTERN.test(k));
}

/**
 * (E) UA claims a Chromium browser but the request carries no Sec-CH-UA
 * header. Real Chromium always emits Sec-CH-UA on same/cross-origin POSTs.
 * Pairs with JA4 mismatch: this catches the case where UA + JA4 agree on
 * Chromium but the client hints are missing (stealth-strip headers).
 */
/**
 * Carve-out: if the encrypted body ships navigator.userAgentData.brands
 * (populated by the SDK from navigator.userAgentData on Chromium — exposed
 * in both window AND worker scope), the SDK was running on a real Chromium
 * browser that knows about CH. Missing request header is then structural
 * (Brave Shields privacy strip, or Chrome's cross-origin policy on Worker
 * fetches) rather than stealth-strip Puppeteer. A stealth-strip Puppeteer
 * would null BOTH the header and the body data; honest Chromium nulls
 * only the header.
 */
function hasBodyClientHints(integrity: IntegrityResultsData): boolean {
  const navData = (
    integrity.device as
      | { navigator?: { userAgentData?: { brands?: unknown } } }
      | undefined
  )?.navigator?.userAgentData;
  if (!navData || typeof navData !== "object") return false;
  const brands = (navData as { brands?: unknown[] }).brands;
  return Array.isArray(brands) && brands.length > 0;
}

function detectUaFamilyHeaderMismatch(
  integrity: IntegrityResultsData | undefined,
): boolean {
  if (!integrity) return false;
  const headers = integrity.request_headers?.headers ?? {};
  const secChUa = headers["sec-ch-ua"];
  if (secChUa && secChUa.length > 0) return false;
  const ua = integrity.user_agent ?? headers["user-agent"] ?? "";
  // UA token "Chrome/<ver>" reliably indicates Chromium-stack Chrome/Edge.
  const isChromiumStackUa =
    /Chrome\/\d/.test(ua) && !/Edg(e|A|iOS)\//.test(ua + " nope");
  if (!isChromiumStackUa) return false;
  // Honest Chromium ships UA-CH in body even when the request header is
  // absent — see hasBodyClientHints.
  return !hasBodyClientHints(integrity);
}

/** Has-lie helpers for the tampering decision (D). */
function hasPlatformLie(integrity: IntegrityResultsData | undefined): boolean {
  return readLieKeys(integrity).some((k) => /Navigator\.platform/i.test(k));
}

function hasUaWorkerDivergence(
  integrity: IntegrityResultsData | undefined,
): boolean {
  return !!integrity?.analysis.worker.divergences?.some(
    (d) => d.field === "userAgent",
  );
}

/**
 * Tampering probability. Hard signals (many lies / JA4-UA mismatch /
 * multiple scope divergences / WebRTC API tampering) → 100. Compound
 * (5+ lies AND {UA divergence | platform lie}) → 100. Sec-CH-UA absence
 * on Chromium-claimed UA → floor 60. Otherwise the graded tiers.
 */
interface TamperingEvidence {
  lies: number;
  divergences: number;
  ja4Mismatch: boolean;
  webrtcApiTampered: boolean;
  uaDivergence: boolean;
  platformLie: boolean;
  uaHeaderMismatch: boolean;
  /** Any client-hints vs UA mismatch (Group 3, sev >= 0.8). */
  chUaMismatch: boolean;
  /** Any locale-internal mismatch (Group A, sev >= 0.75). */
  localeTamper: boolean;
  /** Probe-side TLS profile vs UA mismatch — cipher-count / GREASE delta.
   *  Already corporate-shield-suppressed at collection time, so any value
   *  surviving here is a real TLS interception / spoofing signal. */
  tlsUaMismatch: boolean;
  /** Browser-engine claim vs observed engine-invariants: at least one
   *  field has zero prevalence in the claimed browser_version's baseline
   *  (e.g. UA claims Safari but jsEngine=V8). Definitive tampering. */
  browserEngineHardBreak: boolean;
  /** Browser-engine claim vs observed: combined naive-Bayes likelihood
   *  is low but no individual field is structurally impossible.
   *  Outlier-but-possibly-legit; floor 60. */
  browserEngineSoft: boolean;
  /** Server kernel reports `tcpi_options` with no ECN bit on a UA
   *  claiming iOS or macOS. Real Darwin negotiates ECN by default — a
   *  WebKit JA4 + UA combination on a non-ECN socket cannot be a real
   *  Apple device. Definitive tampering: highest-confidence device
   *  signal because the kernel reports it about its own socket and the
   *  client cannot lie about it from JS. */
  kernelOsMismatchHard: boolean;
  /** Claimed Linux/Android UA but server kernel sees ECN-on. Most Linux
   *  installs ship with `tcp_ecn=2` (passive only), so an actively-ECN
   *  Linux client is unusual but not structurally impossible. Floor 60. */
  kernelOsMismatchSoft: boolean;
  /** Timezone location doesn't match IP geo (existing TZ_GEOLOCATION_MISMATCH). */
  tzGeoMismatch: boolean;
  /** Accept-Language vs CF country cross-continent mismatch (severe). */
  langGeoCrossContinent: boolean;
  /** Accept-Language vs CF country same-continent mismatch (mild). */
  langGeoCrossCountry: boolean;
  /** Iframe-crypto liveness probe reported the nested iframe was constructable
   *  but `subtle.generateKey({ECDH, P-256})` never resolved within 1s. The
   *  Marionette / Camoufox signature — no legitimate browser does this. Used
   *  to boost tampering alongside the automation=100 signal already wired
   *  in `botProbability`. */
  iframeCryptoStuck: boolean;
  /** Worker-scope cross-check oracle availability. Set by the worker
   *  analyzer when the client shipped no worker scopes at all (only
   *  main thread, or no `workerScope` object). Feeds tier-50 in the
   *  tampering ladder (same slot as iframeCryptoStuck).
   *
   *  Earlier iterations also tracked a "no_shared" state, but that
   *  fired on every legitimate Android Chrome session and pre-iOS-16
   *  Safari (Chromium intentionally never shipped SharedWorker on
   *  Android). The production rule is now: ANY worker present →
   *  oracle is sufficient. Only zero-workers scores. See
   *  ARGUS_URGENT_FIXES #2. */
  workerOracleMissing: "main_only" | false;
  /**
   * CF TLS attestation (`sigint.aws_cf`) tamper/freshness state. The
   * applyTlsJson path always lands a `tampered` and `expired` flag on
   * the row when SIGINT_AES_KEY is configured. Pre-2026-05-25 the
   * analyzer downstream read `aws_cf.{country,ip,asn,tz}` regardless
   * of these flags, letting an attacker forge geo/network/timezone
   * with a junk sig and have the analyzer believe it. Tiers:
   *
   *   - tampered=true → tier-100 (isDefinitiveTampering). SipHash sig
   *     mismatch is structurally provable forgery; no honest browser
   *     produces this.
   *   - expired=true (sig OK) AND ageSec > 300 → tier-100. Five+
   *     minutes past freshness with a valid sig means someone is
   *     replaying a token that was issued for a different session.
   *   - ageSec < -90 (future-dated) → tier-100. Egregious clock skew
   *     or fabrication; either way don't trust.
   *   - expired=true (sig OK) AND ageSec ∈ (90, 300] → tier-60. The
   *     "slow page / idle tab" gray zone. Suspicious but possibly
   *     honest.
   *
   * Note: cookieTampered intentionally NOT here — absent cookie is
   * normal for first-visit / cleared cookies and doesn't imply
   * tampering.
   */
  cfTampered: boolean;
  cfReplayed: boolean;
  cfSlowPage: boolean;
  /**
   * PAT attestation was attempted (client shipped a `patToken`) but
   * verification failed at the API. Pre-2026-05-25 this was silent on
   * the row, indistinguishable from "user did not attempt PAT." Now
   * scores as tier-60: a credible spoof — the attacker manufactured a
   * token-shaped string but the HMAC didn't verify.
   */
  patAttestationFailed: boolean;
  /**
   * device_identity verification was attempted (client shipped a
   * pubkey+sig pair) but ECDSA verify failed. Same shape as
   * patAttestationFailed: tier-60 credible spoof. Note: the signing
   * input is weak (xor(h2Token, hardcoded_key)) per ARGUS_URGENT_FIXES
   * #5, so verified=true isn't a strong trust signal — but
   * verified=false with sig_present=true IS clear evidence the client
   * tried and failed.
   */
  deviceIdentitySigFailed: boolean;
  /**
   * Device-history blob presented but failed AES-GCM auth-tag
   * verification (or otherwise corrupt). Honest clients either present
   * a server-issued valid blob OR no blob at all (first visit / cleared
   * IDB). A corrupt blob means the client tampered with bytes only the
   * server can produce — tier-60 credible spoof. See
   * ARGUS_URGENT_FIXES #5 Phase 2 / analysis/device-history.
   */
  deviceHistoryTampered: boolean;
}

function readChUaMismatch(integrity: IntegrityResultsData): boolean {
  const chUa = (
    integrity.analysis as {
      client_hints_ua?: { hasStrongMismatch?: boolean };
    }
  ).client_hints_ua;
  return chUa?.hasStrongMismatch === true;
}

function readLocaleGeoSignals(integrity: IntegrityResultsData): {
  localeTamper: boolean;
  crossContinent: boolean;
  crossCountry: boolean;
} {
  const lg = (
    integrity.analysis as {
      locale_geo?: {
        hasLocaleTamper?: boolean;
        signals?: Array<{ code: string }>;
      };
    }
  ).locale_geo;
  const codes = (lg?.signals ?? []).map((s) => s.code);
  return {
    localeTamper: lg?.hasLocaleTamper === true,
    crossContinent: codes.includes("ACCEPT_LANG_GEO_CROSS_CONTINENT"),
    crossCountry: codes.includes("ACCEPT_LANG_GEO_CROSS_COUNTRY"),
  };
}

function readTzGeoMismatch(integrity: IntegrityResultsData): boolean {
  const tz = integrity.analysis.timezone;
  return (tz?.signals ?? []).some((s) => s.code === "TZ_GEOLOCATION_MISMATCH");
}

/**
 * Brave on iOS positive-identification signature.
 *
 * Background: Apple requires all iOS browsers to use WebKit, so "Brave for
 * iOS" is structurally Safari with Brave's privacy shields layered over the
 * top via content-blocker rules + JS shims. The user-visible Brave logo
 * does not show up in UA, sec-ch-ua, JA4, h2, or kernel-OS signals —
 * every network/protocol surface looks identical to plain iOS Safari.
 *
 * Brave does, however, leave one unambiguous fingerprint: its Shields
 * wrap a specific set of fingerprinting-related APIs to add noise or
 * return sanitized values:
 *   - `AnalyserNode.{getFloatFrequencyData, getByteFrequencyData,
 *      getFloatTimeDomainData, getByteTimeDomainData}` — audio noise
 *      injection (defeats audio fingerprinting)
 *   - `AudioBuffer.getChannelData` — same
 *   - `PluginArray.{item, namedItem}` + `Navigator.plugins` — sanitized
 *      empty plugin list (defeats plugin enumeration)
 *   - `Navigator.hardwareConcurrency` — quantized to coarse buckets
 *
 * Real Safari does none of these. The lies-scanner's seven structural
 * checks (toString shape, descriptor presence, own-property keys, etc.)
 * fire on every one of these wrapped APIs, producing ~35-50 "lies"
 * concentrated in this exact key set. Without a carve-out this trips
 * `isDefinitiveTampering` (lies >= 20) and the user gets
 * `device_tampering = 100` for using a privacy browser correctly.
 *
 * This detector matches when:
 *   - UA family is Safari AND UA OS is iOS, AND
 *   - At least 4 of the 5 Brave-Shields audio APIs are in the lies
 *     dictionary (the audio bundle is what Brave reliably wraps), AND
 *   - At least 1 of the Brave-Shields plugin APIs is in the lies
 *     dictionary (covers Brave's plugin sanitization)
 *
 * The intersection requirement defeats a bot that wraps audio APIs
 * alone or plugins alone — Brave reliably hits both surfaces because
 * each defends a different fingerprinting class.
 *
 * Returns the set of attributable lies + the matched flag. Callers
 * subtract `attributedLies` from `totalLies` before the
 * `lies >= 20 = definitive tampering` rule. Brave's lies still appear
 * in the raw `device.lies.data` for diagnostics; only the score is
 * carved out.
 */
const BRAVE_IOS_AUDIO_KEYS = [
  "AnalyserNode.getFloatFrequencyData",
  "AnalyserNode.getByteFrequencyData",
  "AnalyserNode.getFloatTimeDomainData",
  "AnalyserNode.getByteTimeDomainData",
  "AudioBuffer.getChannelData",
] as const;

const BRAVE_IOS_PLUGIN_KEYS = [
  "PluginArray.item",
  "PluginArray.namedItem",
  "Navigator.plugins",
] as const;

const BRAVE_IOS_NAV_KEYS = ["Navigator.hardwareConcurrency"] as const;

const BRAVE_IOS_ALL_KEYS: ReadonlySet<string> = new Set<string>([
  ...BRAVE_IOS_AUDIO_KEYS,
  ...BRAVE_IOS_PLUGIN_KEYS,
  ...BRAVE_IOS_NAV_KEYS,
]);

interface BraveIosDetection {
  matched: boolean;
  attributedLies: number;
}

function detectBraveIos(integrity: IntegrityResultsData): BraveIosDetection {
  const ja4 = (
    integrity.analysis as {
      ja4_ua?: { ua_browser_family?: string; ua_os?: string };
    }
  ).ja4_ua;
  // Brave-iOS requires the underlying UA to claim Safari on iOS. We use
  // `ja4_ua.ua_*` (the parsed UA values the JA4 analyzer already
  // produced) rather than re-parsing the UA here. A spoofed UA pretending
  // to be iOS Safari would also fail browser-engine baseline, JA4, and
  // kernel-OS checks downstream — those signals still fire even when
  // this carve-out matches.
  if (ja4?.ua_browser_family !== "safari" || ja4?.ua_os !== "iOS") {
    return { matched: false, attributedLies: 0 };
  }

  const liesData =
    (
      integrity.device as
        | { lies?: { data?: Record<string, string[]> } }
        | undefined
    )?.lies?.data ?? {};

  const audioHits = BRAVE_IOS_AUDIO_KEYS.filter(
    (k) => liesData[k] !== undefined,
  ).length;
  const pluginHits = BRAVE_IOS_PLUGIN_KEYS.filter(
    (k) => liesData[k] !== undefined,
  ).length;

  // Conservative threshold: Brave Shields reliably wraps the entire
  // audio cluster (all 5 methods) and the plugin cluster (both
  // PluginArray methods + Navigator.plugins). Require ≥4 audio AND
  // ≥1 plugin to avoid attributing a partial-audio-spoof bot to
  // Brave. Bots that mimic Brave's full pattern aren't penalized via
  // lies — but they remain visible to every other detector
  // (worker divergence, kernel-OS, JA4 fork-of-Safari, etc.).
  if (audioHits < 4 || pluginHits < 1) {
    return { matched: false, attributedLies: 0 };
  }

  let attributedLies = 0;
  for (const [key, lies] of Object.entries(liesData)) {
    if (BRAVE_IOS_ALL_KEYS.has(key) && Array.isArray(lies)) {
      attributedLies += lies.length;
    }
  }
  return { matched: true, attributedLies };
}

function collectTamperingEvidence(
  integrity: IntegrityResultsData,
): TamperingEvidence {
  const rawLies =
    (integrity.device as { lies?: { totalLies?: number } } | undefined)?.lies
      ?.totalLies ?? 0;
  // Brave-iOS positive-identification carve-out. Brave's Shields wrap
  // audio + plugin APIs to defeat fingerprinting; the wraps trip ~50
  // structural lies that would otherwise tip definitive tampering.
  // We attribute those lies to the browser, not the device. See
  // `detectBraveIos` for the signature + the rationale.
  const braveIos = detectBraveIos(integrity);
  const lies = Math.max(0, rawLies - braveIos.attributedLies);
  // Worker-scope divergences emitted by analysis/worker/index.ts. The
  // analyzer's COMPARE_FIELDS list is `userAgent`, `platform`,
  // `hardwareConcurrency`, `deviceMemory`, `languages`, `webglRenderer`,
  // `webglVendor`, `webgl2Renderer`, `webgl2Vendor`, `appVersion`,
  // `product`, `onLine` — every one of these is structurally constant
  // across realms in real browsers EXCEPT `onLine`, which can flip if
  // the network state changes between scope captures. Exclude `onLine`
  // and count everything else: each remaining divergence is conclusive
  // evidence of automation tooling overriding navigator on the main
  // realm without propagating to workers.
  const divergences = (integrity.analysis.worker.divergences ?? []).filter(
    (d) => d.field !== "onLine",
  ).length;
  const locale = readLocaleGeoSignals(integrity);
  // Corporate-shield carve-outs.
  //
  // (a) TLS_UA_MISMATCH: TLS interception by Cisco Umbrella / Zscaler /
  //     Cloudflare Access produces the same probe-side TLS_UA_MISMATCH as
  //     a genuine MITM. The shield is already surfaced as its own tag.
  //
  // (b) TZ_GEOLOCATION_MISMATCH: corporate shields egress through PoPs in
  //     timezones that often don't match the user's home timezone (a Chicago
  //     employee whose corp shield egresses through Ashburn → client TZ
  //     America/Chicago vs CF TZ America/New_York). Same shape as (a) — a
  //     real signal in general, structurally false for shielded users. Also
  //     drops the noisy `location_mismatch` tag for those rows since the
  //     tag detector reads the same evidence.
  //
  // Both carve-outs only gate the SCORE contribution. The raw signals stay
  // in the analyzer output (analysis.ja4_ua.signals, analysis.timezone.signals)
  // so diagnostics are unchanged.
  const shielded = isCorporateShieldedAsn(integrity);
  // Privacy-relay carve-out for the kernel-OS axis only — see
  // isVerifiedAppleRelay for why this is gated on JA4+H2+UA convergence
  // rather than the asn.category alone (which is true for any Cloudflare
  // Worker / Akamai tenant traffic that the classifier may incidentally
  // tag as privacy_relay).
  const appleRelay = isVerifiedAppleRelay(integrity);
  const tlsUaMismatch = hasTlsUaMismatch(integrity) && !shielded;
  const tzGeoMismatch = readTzGeoMismatch(integrity) && !shielded;
  const engineSignals = readBrowserEngineSignals(integrity);
  const kernelSignals = readKernelOsSignals(integrity);
  return {
    lies,
    divergences,
    ja4Mismatch: hasJa4UaMismatch(integrity),
    webrtcApiTampered: detectWebrtcApiTampering(integrity),
    uaDivergence: hasUaWorkerDivergence(integrity),
    platformLie: hasPlatformLie(integrity),
    uaHeaderMismatch: detectUaFamilyHeaderMismatch(integrity),
    chUaMismatch: readChUaMismatch(integrity),
    localeTamper: locale.localeTamper,
    tlsUaMismatch,
    tzGeoMismatch,
    langGeoCrossContinent: locale.crossContinent,
    langGeoCrossCountry: locale.crossCountry,
    browserEngineHardBreak: engineSignals.hard,
    browserEngineSoft: engineSignals.soft,
    // Corporate-shield TLS-intercepting proxies (Umbrella, Zscaler, etc.)
    // re-originate the connection from their egress, so the socket the
    // server kernel observes is the proxy's, not the user's. ECN almost
    // never gets propagated through these stacks, which falsely flips
    // the Apple-without-ECN heuristic on every legitimate iOS/macOS user
    // behind the proxy. Suppress at scoring time only — the raw signal
    // stays on `analysis.kernel_os.signals` for forensic review.
    kernelOsMismatchHard: kernelSignals.hard && !shielded && !appleRelay,
    kernelOsMismatchSoft: kernelSignals.soft && !shielded && !appleRelay,
    iframeCryptoStuck: hasIframeCryptoStuck(integrity),
    workerOracleMissing: readWorkerOracleMissing(integrity),
    ...readCfTamperEvidence(integrity),
    patAttestationFailed: readPatAttestationFailed(integrity),
    deviceIdentitySigFailed: readDeviceIdentitySigFailed(integrity),
    deviceHistoryTampered: readDeviceHistoryTampered(integrity),
  };
}

/**
 * PAT attestation attempted-and-failed. Reads `integrity.patAttempt`
 * set by redeem-pat-token. Returns true only when the client shipped a
 * patToken AND verifyPatAttestation rejected it. Returns false for
 * "no token shipped" (legitimate non-iOS) and "token shipped and
 * verified" (legitimate iOS).
 */
function readPatAttestationFailed(integrity: IntegrityResultsData): boolean {
  const a = (
    integrity as { patAttempt?: { attempted?: unknown; verified?: unknown } }
  ).patAttempt;
  return a?.attempted === true && a?.verified === false;
}

/**
 * device_identity sig-present-but-verify-failed. Reads
 * `integrity.identification` set by buildIdentificationField. The shape
 * is `{ pubkey, verified, reason, sig_present }`. We score the
 * sig_present=true && verified=false case at tier-60. Absence (no
 * device_identity block on the row) is unscored — legacy SDK bundles
 * pre-migration produce that and aren't suspicious by itself.
 */
function readDeviceIdentitySigFailed(integrity: IntegrityResultsData): boolean {
  const id = (
    integrity as {
      identification?: { sig_present?: unknown; verified?: unknown };
    }
  ).identification;
  return id?.sig_present === true && id?.verified === false;
}

/**
 * Device-history AES-GCM auth-tag failure on a presented blob. Reads
 * `integrity.analysis.device_history.tampered` set by the analyzer.
 * Returns false when the client presented no blob (absent / fresh
 * device) or when the blob decrypted cleanly. Returns true ONLY when
 * the client presented bytes that decoded but failed integrity check.
 */
function readDeviceHistoryTampered(integrity: IntegrityResultsData): boolean {
  const dh = (
    integrity.analysis as {
      device_history?: { tampered?: unknown };
    }
  ).device_history;
  return dh?.tampered === true;
}

/**
 * Tier the CF TLS attestation tamper / freshness state for the
 * tampering scorer. Reads sigint.aws_cf's `tampered`, `expired`, and
 * `ageSec` (set by applyTlsJson). See TamperingEvidence.cfTampered
 * for the tier mapping. Honest sessions return {false, false, false}.
 */
function readCfTamperEvidence(integrity: IntegrityResultsData): {
  cfTampered: boolean;
  cfReplayed: boolean;
  cfSlowPage: boolean;
} {
  const cf = (
    integrity.sigint as
      | { aws_cf?: { tampered?: unknown; expired?: unknown; ageSec?: unknown } }
      | undefined
  )?.aws_cf;
  if (!cf) return { cfTampered: false, cfReplayed: false, cfSlowPage: false };
  const tampered = cf.tampered === true;
  if (tampered) {
    return { cfTampered: true, cfReplayed: false, cfSlowPage: false };
  }
  const expired = cf.expired === true;
  const ageSec = typeof cf.ageSec === "number" ? cf.ageSec : null;
  // Future-dated (< -90) and long-stale (> 300s) both → replayed.
  // No legitimate path produces either.
  const replayed = ageSec !== null && (ageSec < -90 || ageSec > 300);
  return {
    cfTampered: false,
    cfReplayed: replayed,
    cfSlowPage: !replayed && expired && ageSec !== null,
  };
}

/**
 * Read the WORKER_ORACLE_MAIN_ONLY signal (if any) emitted by
 * analysis/worker. Returns "main_only" when no worker scopes were
 * shipped at all, false when at least one worker (dedicated or shared)
 * is present. The "any worker is enough" rule replaces the earlier
 * NO_SHARED tier — see analyzeWorkerScopes for the Android Chrome /
 * pre-iOS-16 Safari false-positive that motivated the simplification.
 */
function readWorkerOracleMissing(
  integrity: IntegrityResultsData,
): "main_only" | false {
  const sigs = integrity.analysis.worker.signals ?? [];
  if (sigs.some((s) => s.code === "WORKER_ORACLE_MAIN_ONLY"))
    return "main_only";
  return false;
}

/**
 * Worker-scope divergence on ANY of the structurally-constant navigator
 * fields is conclusive. Real browsers propagate navigator state from the
 * parent realm to dedicated/shared workers identically — no browser has
 * ever shipped otherwise, and no privacy mode / extension produces this
 * split. The only mechanism that does is automation tooling overriding
 * the UA on the main thread without propagating to workers.
 * `uaDivergence` is the userAgent-specific narrow check; the count
 * covers the other COMPARE_FIELDS (platform, hardwareConcurrency, webgl
 * renderer/vendor, languages, appVersion, etc.).
 */
function hasDivergenceTampering(e: TamperingEvidence): boolean {
  return e.divergences >= 1 || e.uaDivergence || e.platformLie;
}

/**
 * Structurally-impossible UA / engine / OS / TLS observations. Each is a
 * "real browsers can't produce this" signal.
 *
 * - chUaMismatch: client-hints vs UA disagreement (platform/mobile/brand).
 * - browserEngineHardBreak: UA's baseline says some observed field has
 *   zero prevalence (e.g. Safari UA + V8 jsEngine).
 * - cfTampered / cfReplayed: CF TLS attestation forged (sig mismatch)
 *   or replayed from another session (valid sig but >5min stale, or
 *   future-dated). See cfTampered / cfReplayed for the tier mapping.
 * - kernelOsMismatchHard: server's own kernel sees a non-Darwin TCP
 *   options bitmask on a UA claiming iOS/macOS. The client cannot lie
 *   about this from JS — bits negotiated at SYN time.
 */
function hasStructuralTampering(e: TamperingEvidence): boolean {
  return (
    e.chUaMismatch ||
    e.browserEngineHardBreak ||
    e.cfTampered ||
    e.cfReplayed ||
    e.kernelOsMismatchHard
  );
}

function isDefinitiveTampering(e: TamperingEvidence): boolean {
  if (e.lies >= 20 || e.ja4Mismatch) return true;
  if (hasDivergenceTampering(e)) return true;
  if (e.webrtcApiTampered) return true;
  return hasStructuralTampering(e);
}

/**
 * Tier-60 signals: each one is "credible spoof but not structurally
 * impossible." Any one trips the floor. Listed here as an array so
 * `tamperingProbabilityFromEvidence` stays under the cyclomatic-
 * complexity cap.
 *
 * - lies: enough small lies
 * - uaHeaderMismatch: Chromium UA with sec-ch-ua header missing/wrong
 * - localeTamper: intl APIs vs navigator vs worker disagreement
 * - tlsUaMismatch: probe-side TLS profile lie (corp-shield carve-out
 *   already applied upstream)
 * - browserEngineSoft: naive-Bayes baseline below threshold but no
 *   single field structurally impossible
 * - kernelOsMismatchSoft: Linux UA + ECN negotiated (most distros ship
 *   tcp_ecn=2; ops teams who flip ECN on are the carve-out)
 *
 * Worker divergences are NOT in this tier — they're handled by
 * `isDefinitiveTampering` directly (any divergence on a structurally-
 * constant COMPARE_FIELD is 100, not 60).
 */
function hasTier60Signal(e: TamperingEvidence): boolean {
  return (
    e.lies >= 5 ||
    e.uaHeaderMismatch ||
    e.localeTamper ||
    e.tlsUaMismatch ||
    e.browserEngineSoft ||
    e.kernelOsMismatchSoft ||
    // CF TLS attestation past freshness with a valid sig but within the
    // "slow page / idle tab" envelope (90-300s past). Credible spoof but
    // not structurally impossible — gray zone with real-user FP risk if
    // we pushed it higher.
    e.cfSlowPage ||
    // Attestation attempted-and-failed cases (PAT + device_identity).
    // Both are "client manufactured a sig-shaped string but the HMAC /
    // ECDSA verify rejected it." No honest user produces a malformed
    // signature; tier-60 credible spoof. See TamperingEvidence
    // docstrings for the per-field rationale.
    e.patAttestationFailed ||
    e.deviceIdentitySigFailed ||
    // Device-history blob presented but AES-GCM auth-tag verification
    // failed. Same shape: client manufactured bytes only the server
    // can validly produce. Honest clients present a valid server-
    // issued blob OR no blob; presenting a corrupt one is a tell.
    e.deviceHistoryTampered
  );
}

function tamperingProbabilityFromEvidence(e: TamperingEvidence): number {
  if (isDefinitiveTampering(e)) return 100;
  if (hasTier60Signal(e)) return 60;
  // Iframe-crypto liveness probe failed: the nested iframe was constructable
  // but `subtle.generateKey({ECDH,P-256})` never resolved within 1s. The
  // Marionette / Camoufox signature. Camoufox's whole purpose is detection
  // evasion — its presence implies tampering even when the spoofed UA and
  // fingerprint values pass every other check. Tier 50: more confident than
  // tzGeoMismatch (35, often benign for travelers), less than tier60Signal
  // signals which include cipher-level evidence.
  // Tier 50: confident tells that aren't structurally impossible.
  //   - iframeCryptoStuck: Marionette / Camoufox signature.
  //   - workerOracleMissing=main_only: zero worker scopes shipped. Real
  //     browsers running our SDK always produce at least a dedicated
  //     Worker (Android Chrome included — it just lacks SharedWorker).
  //     Zero-workers is "no honest-browser carve-out exists" territory:
  //     either a heavily-locked-down embed (rare) or an attacker who
  //     didn't want to instrument multiple realms. See
  //     ARGUS_URGENT_FIXES #2.
  if (e.iframeCryptoStuck || e.workerOracleMissing === "main_only") return 50;
  // TZ location vs IP TZ disagreement — VPN/proxy tell, often benign for
  // travelers but still worth surfacing.
  if (e.tzGeoMismatch) return 35;
  if (e.lies >= 1) return 25;
  // langGeoCrossContinent / langGeoCrossCountry intentionally do NOT feed
  // device_tampering. en-GB on a US IP and similar accept-language quirks
  // are widespread legitimate user preferences (British-spelling fans,
  // expat communities, multi-lingual households in major US cities). They
  // surface as the soft `language_mismatch` tag for merchants who want
  // to filter on them, with no score penalty.
  return 0;
}

function tamperingProbability(input: MerchantProjectionInput): number {
  if (!input.integrity) return 0;
  return tamperingProbabilityFromEvidence(
    collectTamperingEvidence(input.integrity),
  );
}

function tamperingWithoutWorkerDivergence(
  integrity: IntegrityResultsData,
): number {
  const evidence = collectTamperingEvidence(integrity);
  return tamperingProbabilityFromEvidence({
    ...evidence,
    divergences: 0,
    uaDivergence: false,
  });
}

function parseAsnNumber(raw: string | null | undefined): number | null {
  if (!raw) return null;
  const cleaned = String(raw).replace(/^AS/i, "");
  const n = Number(cleaned);
  return Number.isFinite(n) && n > 0 ? n : null;
}

interface AwsCfSigint {
  asn?: string | null;
  country?: string | null;
  city?: string | null;
  lat?: string | null;
  lon?: string | null;
  tz?: string | null;
  ip?: string | null;
  ts?: number | null;
  /** Opaque id stamped into the third-party cookie at TLS edge. */
  id?: string | null;
  /** Unix seconds when the cookie was minted. */
  issuedAt?: number | null;
  /** True when the submitted cookie didn't verify (absent counts as tampered). */
  cookieTampered?: boolean | null;
  /** True when the cookie's id+issuedAt match the current TLS token. */
  cookieMatchesToken?: boolean | null;
}

function readAwsCf(input: MerchantProjectionInput): AwsCfSigint | undefined {
  return (input.integrity?.sigint as { aws_cf?: AwsCfSigint } | undefined)
    ?.aws_cf;
}

function toFloat(raw: string | number | null | undefined): number | null {
  if (raw === null || raw === undefined || raw === "") return null;
  const n = typeof raw === "number" ? raw : Number(raw);
  return Number.isFinite(n) ? n : null;
}

function deriveIpLocation(input: MerchantProjectionInput): MerchantIpLocation {
  const awsCf = readAwsCf(input);
  return {
    city: awsCf?.city ?? null,
    country: awsCf?.country ?? null,
    latitude: toFloat(awsCf?.lat),
    longitude: toFloat(awsCf?.lon),
    timezone: awsCf?.tz ?? null,
  };
}

/**
 * All convenience-boolean flags derive from `network_class` (the broader
 * 12-value taxonomy) so the `category` field can stay legacy without
 * influencing routing. `datacenter` previously read from `category` —
 * standardized here so all booleans share one source of truth.
 */
function deriveNetworkFlags(networkClass: string | null): {
  datacenter: { result: boolean };
  mobile: { result: boolean };
  residential: { result: boolean };
  vpn: { result: boolean };
  hosting: { result: boolean };
  privacy_relay: { result: boolean };
  corporate_shield: { result: boolean };
} {
  return {
    datacenter: { result: networkClass === "datacenter" },
    mobile: { result: networkClass === "mobile" },
    residential: { result: networkClass === "residential" },
    vpn: { result: networkClass === "vpn_proxy" },
    hosting: { result: networkClass === "hosting_proxy" },
    privacy_relay: { result: networkClass === "privacy_relay" },
    corporate_shield: { result: networkClass === "security_filter" },
  };
}

function deriveIpInfo(input: MerchantProjectionInput): MerchantIpInfo {
  const asnFromIntegrity = input.integrity?.analysis.ip.asn;
  if (asnFromIntegrity) {
    const networkClass = asnFromIntegrity.network_class ?? null;
    return {
      asn: {
        number: parseAsnNumber(asnFromIntegrity.number),
        organization: asnFromIntegrity.org,
        category: asnFromIntegrity.category,
        network_class: networkClass,
        metadata: asnFromIntegrity.metadata ?? null,
      },
      ...deriveNetworkFlags(networkClass),
    };
  }
  const awsCf = readAwsCf(input);
  return {
    asn: {
      number: parseAsnNumber(awsCf?.asn),
      organization: null,
      category: null,
      network_class: null,
      metadata: null,
    },
    ...deriveNetworkFlags(null),
  };
}

function deriveIp(input: MerchantProjectionInput): string | null {
  return input.integrity?.analysis.ip.ip ?? readAwsCf(input)?.ip ?? null;
}

interface NavigatorShape {
  userAgent?: string;
  userAgentParsed?: string;
  system?: string;
  device?: string;
  oscpu?: string;
}

function readNavigator(
  integrity: IntegrityResultsData | undefined,
): NavigatorShape | undefined {
  return (integrity?.device as { navigator?: NavigatorShape } | undefined)
    ?.navigator;
}

function deriveBrowserDetails(input: MerchantProjectionInput): BrowserDetails {
  const nav = readNavigator(input.integrity);
  const parsed = nav?.userAgentParsed ?? "";
  // "Firefox 148" → ["Firefox", "148"]
  const [browserName, browserVersion] = parsed
    ? [
        parsed.replace(/\s+\d.*$/, "") || null,
        (parsed.match(/\d.*$/) ?? [null])[0],
      ]
    : [null, null];
  return {
    browserName,
    browserVersion,
    os: nav?.system ?? null,
    osVersion: null,
    device: nav?.device ?? null,
    userAgent: nav?.userAgent ?? input.integrity?.user_agent ?? null,
  };
}

interface TpcFields {
  tpc_id: string | null;
  tpc_created: number | null;
  tpc_verified: "pass" | "fail" | null;
}

const TPC_EMPTY: TpcFields = {
  tpc_id: null,
  tpc_created: null,
  tpc_verified: null,
};

function hasSignalCode(
  signals: Array<{ code: string }> | undefined,
  code: string,
): boolean {
  return !!signals?.some((s) => s.code === code);
}

function readAsnCategory(
  input: MerchantProjectionInput,
): string | null | undefined {
  return input.integrity?.analysis.ip.asn.category;
}

/**
 * Compose the merchant-facing networkIntegrity score from:
 *   - raw probe-consistency score (ip-consistency/index.ts tiers)
 *   - corp-shield clamp (residential-ish footprint: probe scatter expected)
 *   - JA4/H2 browser-family mismatch clamp (C): strong TLS forgery evidence
 *   - compound proxy/VPN noisy-OR downgrade (B): multiple hiding signals stack
 *   - webrtc-blocked on non-residential ASN (F): privacy excuse doesn't fit
 *
 * Forgery evidence (raw=0) is never up-rated — crypto failures can't be
 * masked by ASN category or tier math.
 */
/** (F) Non-residential ASN categories where "webrtc blocked" is suspicious. */
const NON_PRIVACY_CATEGORIES = new Set([
  "datacenter",
  "hosting",
  "proxy",
  "vpn",
]);

function applyProxyVpnDowngrade(
  input: MerchantProjectionInput,
  score: number,
): number {
  const proxyP = input.integrity?.analysis.network.proxy_component ?? 0;
  const vpnP = input.integrity?.analysis.network.vpn_component ?? 0;
  return score * (1 - proxyP) * (1 - vpnP);
}

function applyWebrtcBlockedPenalty(
  input: MerchantProjectionInput,
  score: number,
): number {
  const webrtcBlocked = hasSignalCode(
    input.integrity?.analysis.ip.signals,
    "WEBRTC_BLOCKED",
  );
  if (!webrtcBlocked) return score;
  const category = readAsnCategory(input);
  if (!category || !NON_PRIVACY_CATEGORIES.has(category)) return score;
  return score * 0.5;
}

/**
 * @internal — exported only for unit tests of the network-integrity tiers.
 * Not part of the merchant API surface; the score is folded into
 * `network_tampering` in the projected response. Do not depend on it from
 * other modules.
 */
export function computeNetworkIntegrityScore(
  input: MerchantProjectionInput,
  rawScore: number,
): number {
  if (rawScore === 0) return 0; // forgery — do not override

  // Corp-shield clamp. Known corporate gateway → probe scatter is expected
  // and the tier's 0.1 floor is a false positive for that context.
  const corpShield = detectCorporateShield(input);
  let score = corpShield ? 1.0 : rawScore;

  // (C) JA4/H2 mismatch at sev >= 0.9 is strong TLS-layer forgery — clamp
  // aggressively even under corp shield (still spoofing your TLS stack).
  if (input.integrity && readJa4UaSignals(input.integrity).strongMismatch) {
    score = Math.min(score, 0.2);
  }

  // (B + F) Noisy-OR proxy/VPN downgrade + webrtc-blocked-on-non-residential
  // penalty. Skipped on corp shield since the ASN is a known-benign gateway.
  if (!corpShield) {
    score = applyProxyVpnDowngrade(input, score);
    score = applyWebrtcBlockedPenalty(input, score);
  }

  return Math.max(0, Math.min(1, score));
}

/**
 * Derive the third-party-cookie identification fields from aws_cf sigint.
 * On "pass" we surface the cookie id and issuedAt. On "fail" (tampered or
 * mismatched) we null the id/created because their values come from the
 * untrusted cookie itself. On absence we null everything (the cookie
 * mechanism never engaged).
 */
function deriveThirdPartyCookie(input: MerchantProjectionInput): TpcFields {
  const awsCf = readAwsCf(input);
  if (!awsCf) return TPC_EMPTY;

  const tampered = awsCf.cookieTampered === true;
  const matches = awsCf.cookieMatchesToken;

  let tpc_verified: "pass" | "fail" | null;
  if (tampered) tpc_verified = "fail";
  else if (matches === true) tpc_verified = "pass";
  else if (matches === false) tpc_verified = "fail";
  else tpc_verified = null;

  if (tpc_verified !== "pass") {
    return { tpc_id: null, tpc_created: null, tpc_verified };
  }
  return {
    tpc_id: awsCf.id ?? null,
    tpc_created: awsCf.issuedAt ?? null,
    tpc_verified: "pass",
  };
}

function readClientUuid(
  integrity: IntegrityResultsData | undefined,
): string | null {
  const raw = (integrity?.device as { client_uuid?: unknown } | undefined)
    ?.client_uuid;
  return typeof raw === "string" && raw.length > 0 ? raw : null;
}

function deriveIdentification(
  input: MerchantProjectionInput,
): MerchantIdentification {
  const { integrity } = input;
  const crypto_device_id = integrity?.identification
    ? hashPubkey(integrity.identification.pubkey)
    : null;
  const crypto_verified = integrity?.identification?.verified ?? null;
  const tpc = deriveThirdPartyCookie(input);

  // network_id and network_id_source are pre-computed by analyzeIpConsistency
  // during ingestion (so the helpers/ layer doesn't need to import services/).
  // Older records that pre-date the field default to ("none", null).
  const ipBlock = integrity?.analysis.ip;
  const network_id = ipBlock?.network_id ?? null;
  const network_id_source =
    (ipBlock?.network_id_source as MerchantIdentification["network_id_source"]) ??
    "none";

  return {
    crypto_device_id,
    crypto_verified,
    client_uuid: readClientUuid(integrity),
    tpc_id: tpc.tpc_id,
    tpc_created: tpc.tpc_created,
    tpc_verified: tpc.tpc_verified,
    network_id,
    network_id_source,
    browserDetails: deriveBrowserDetails(input),
  };
}

function deriveRequestHeaders(
  input: MerchantProjectionInput,
): MerchantRequestHeaders | null {
  const captured = input.integrity?.request_headers;
  if (!captured) return null;
  return {
    headers: { ...captured.headers },
    cookie_names: [...captured.cookie_names],
  };
}

function deriveVerdict(
  automation: number,
  device_tampering: number,
  network_tampering: number,
): Verdict {
  const peak = Math.max(automation, device_tampering, network_tampering);
  if (peak >= BLOCK_THRESHOLD) return "block";
  if (peak >= SUSPECT_THRESHOLD) return "suspect";
  return "clean";
}

/**
 * Project the internal session / integrity record down to the merchant-
 * safe shape. Safe to call with partial inputs — missing data yields
 * conservative defaults.
 */
export function buildMerchantResponse(
  input: MerchantProjectionInput,
): MerchantSafeResponse {
  const { session_id, integrity } = input;

  const rawNetworkScore = integrity?.analysis.ip.integrity ?? 0.5;
  const networkIntegrityScore = computeNetworkIntegrityScore(
    input,
    rawNetworkScore,
  );

  // networkIntegrityScore stays computed (used by `analysis.ip.integrity`-
  // dependent paths upstream and for any future internal consumer); it is
  // not exposed and not summed into network_tampering — see the
  // networkTamperingScore() docstring for the double-count rationale.
  void networkIntegrityScore;

  const automation = applyPatAdjustment(automationProbability(input), input);
  const device_tampering = tamperingProbability(input);
  const network_tampering = networkTamperingScore(input);
  const verdict = deriveVerdict(
    automation,
    device_tampering,
    network_tampering,
  );

  // Tags still need the constituent probabilities to fire individual labels
  // (vpn / proxy / browser_tampering / automation) at their own thresholds.
  const tagProbs = {
    bot: automation,
    vpn: probabilityFromUnit(vpnScore(input)),
    proxy: probabilityFromUnit(proxyScore(input)),
    tampering: device_tampering,
  };

  return {
    session_id,
    created_at: integrity?.created_at ?? null,
    ttl: (integrity as { ttl?: number } | undefined)?.ttl ?? null,

    automation,
    device_tampering,
    network_tampering,
    verdict,

    identification: deriveIdentification(input),

    ip: deriveIp(input),
    ipLocation: deriveIpLocation(input),
    ipInfo: deriveIpInfo(input),

    incognito: { result: detectIncognito(input) },
    developer_tools: { result: detectDeveloperTools(input) },
    worker_scope_evidence: integrity
      ? deriveWorkerScopeEvidence(
          integrity,
          tamperingWithoutWorkerDivergence(integrity),
        )
      : null,

    tags: buildTags(input, tagProbs),

    requestHeaders: deriveRequestHeaders(input),

    ip_velocity_1h: deriveIpVelocity(input),

    device_history: deriveDeviceHistory(input),
  };
}
