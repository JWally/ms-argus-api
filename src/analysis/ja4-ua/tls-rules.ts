/**
 * TLS-vs-UA consistency rules.
 *
 * Mirrors the heuristics in `ms-argus-sigint/src-go/h2-probe/main.go`
 * (`buildTLSSignals`), but lifted into TS so that:
 *
 *   1. Carve-outs (Brave, Tor, hardened-Chromium forks) can be added
 *      without redeploying the EC2 ASG / instance refresh of the probe.
 *   2. Decisions can use API-side context the probe doesn't have, like
 *      the `sec-ch-ua` brand list.
 *
 * The probe's own `ua_mismatch` / `ua_hints` fields are still emitted and
 * stored on the session for forensics; the analyzer no longer reads them
 * (see `analyzeJa4Ua`).
 *
 * Threshold values are kept identical to the probe's so behavior is
 * unchanged for non-carved-out clients. To re-tune, edit the constants
 * here — the probe code is now informational only.
 */

/**
 * Chrome (BoringSSL) ships 15 ciphers in its TLS 1.3 ClientHello — the
 * canonical FoxIO JA4 reference fingerprint is `t13d1516h2_8daaf6152771_…`
 * where `15` is the GREASE-stripped cipher count. Observed Chrome in the
 * wild ranges 15–17 depending on feature flags (post-quantum X25519MLKEM768
 * adds one, etc.). Anything noticeably below 15 implies a TLS-terminating
 * proxy that re-originated the connection with a stripped list (Cisco
 * Umbrella, Zscaler, mitmproxy/Burp, scripted clients). 12 is conservative:
 * clear of the legitimate 15–17 band, comfortably above the ~5–10 range
 * typical of stripping proxies.
 *
 * Previous value 20 — set in the original Go probe (`ms-argus-sigint`)
 * before the FoxIO reference data was consulted. It fired on every stock
 * Chrome session (see session 33ab1d3a-3d0f-46da-8b91-6adda535e8b0 and the
 * 23 other sessions from 149.115.96.182 / Vexus Fiber, all of which had
 * cipher_count=15 and were misclassified as device_tampering=60).
 */
const CHROMIUM_MIN_CIPHERS = 12;
const FIREFOX_MAX_CIPHERS = 25;
const SAFARI_MAX_CIPHERS = 30;

/**
 * Chromium-fork brands (matched case-insensitively against `sec-ch-ua`
 * brand list entries) that ship a trimmed cipher list by design. When any
 * one is present, suppress the cipher-count and missing-GREASE rules for
 * Chromium UAs — the UA correctly identifies as Chromium, the TLS profile
 * just doesn't match stock Chrome.
 *
 * Add new strings as more forks surface in the wild. Real Brave session
 * brands look like:
 *   `"Brave";v="1.74", "Chromium";v="146", "Not_A Brand";v="24"`
 */
const HARDENED_CHROMIUM_BRANDS: ReadonlySet<string> = new Set(["brave"]);

export type TlsUaBrowserFamily = "chromium" | "firefox" | "safari" | null;

export interface TlsRuleInput {
  cipherCount: number | null;
  hasGREASE: boolean | null;
  uaBrowser: TlsUaBrowserFamily;
  /** Brand names from `sec-ch-ua` (already GREASE-stripped). */
  brands: readonly string[];
}

export interface TlsRuleResult {
  /** Names of the rules that fired, e.g. `chromium_ua_low_ciphers:15`. */
  hints: string[];
}

function isHardenedChromiumFork(brands: readonly string[]): boolean {
  return brands.some((b) => HARDENED_CHROMIUM_BRANDS.has(b.toLowerCase()));
}

/**
 * (1) Chromium UA without GREASE. Real Chromium ships GREASE; hardened
 * forks (Brave, etc.) keep it. Bots impersonating Chrome usually drop it.
 */
function checkChromiumGrease(
  input: TlsRuleInput,
  hardened: boolean,
): string | null {
  if (input.hasGREASE !== false) return null;
  if (input.uaBrowser !== "chromium" || hardened) return null;
  return "chromium_ua_without_grease";
}

/**
 * (2) Cipher-count thresholds. Carved out for hardened-Chromium forks
 * because trimmed cipher lists are a feature, not a bot tell.
 */
function checkCipherCount(
  input: TlsRuleInput,
  hardened: boolean,
): string | null {
  const { cipherCount, uaBrowser } = input;
  if (cipherCount === null) return null;
  if (
    uaBrowser === "chromium" &&
    cipherCount < CHROMIUM_MIN_CIPHERS &&
    !hardened
  ) {
    return `chromium_ua_low_ciphers:${cipherCount}`;
  }
  if (uaBrowser === "firefox" && cipherCount > FIREFOX_MAX_CIPHERS) {
    return `firefox_ua_high_ciphers:${cipherCount}`;
  }
  if (uaBrowser === "safari" && cipherCount > SAFARI_MAX_CIPHERS) {
    return `safari_ua_high_ciphers:${cipherCount}`;
  }
  return null;
}

/**
 * (3) GREASE on a UA that doesn't identify as any known browser. Real
 * browsers (Chromium, Firefox, modern Safari) all GREASE; scripted
 * clients impersonating an unknown UA shouldn't. The probe's legacy hint
 * name `grease_without_chromium_ua` is dropped — Apple shipped GREASE in
 * iOS 17 / Safari 16 (2022) so it's no longer chromium-specific.
 */
function checkGreaseOnUnknownUa(input: TlsRuleInput): string | null {
  if (input.hasGREASE !== true || input.uaBrowser !== null) return null;
  return "grease_without_known_browser_ua";
}

export function evaluateTlsUaConsistency(input: TlsRuleInput): TlsRuleResult {
  const hardened = isHardenedChromiumFork(input.brands);
  const hints = [
    checkChromiumGrease(input, hardened),
    checkCipherCount(input, hardened),
    checkGreaseOnUnknownUa(input),
  ].filter((h): h is string => h !== null);
  return { hints };
}
