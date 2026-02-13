/**
 * JA4/H2 Coherence Detector
 *
 * Cross-validates TLS cipher hash and H2 pseudo-header order against claimed
 * browser identity. TLS libraries (BoringSSL, NSS, Secure Transport) are
 * physically bound to specific OS/browser combinations — mismatches indicate
 * spoofing.
 *
 * @module services/profile/anomaly/ja4-coherence
 */

import type { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";
import {
  resolveBrowserIdentity,
  type BrowserIdentity,
} from "../../../helpers/browser-identity";

const F_JA4 = "fingerprint.ja4";

/** TLS stack lookup by JA4 cipher hash (12-char hex after first underscore). */
const TLS_STACKS: Record<string, { stack: string; platforms: Set<string> }> = {
  "8daaf6152771": {
    stack: "boringssl",
    platforms: new Set(["Windows", "macOS", "Linux", "Android", "Chrome OS"]),
  },
  e72c3b3287f1: {
    stack: "boringssl-edge",
    platforms: new Set(["Windows", "macOS", "Linux"]),
  },
  "55b375c5d22e": {
    stack: "boringssl-quic",
    platforms: new Set(["Windows", "macOS", "Linux", "Chrome OS"]),
  },
  "66859890b71d": {
    stack: "boringssl-quic-edge",
    platforms: new Set(["Windows", "Linux"]),
  },
  "5b57614c22b0": {
    stack: "nss",
    platforms: new Set(["Windows", "macOS", "Linux"]),
  },
  a09f3c656075: {
    stack: "securetransport",
    platforms: new Set(["iOS", "macOS"]),
  },
  "2802a3db6c62": {
    stack: "securetransport-legacy",
    platforms: new Set(["iOS", "macOS"]),
  },
};

/** H2 pseudo-header order → browser family. */
const H2_FAMILIES: Record<string, string> = {
  "m,a,s,p": "chromium",
  "m,s,p,a": "apple",
  "m,s,a,p": "apple",
  "m,p,a,s": "firefox",
};

/** TLS stack → expected browser family. */
const STACK_H2_FAMILY: Record<string, string> = {
  boringssl: "chromium",
  "boringssl-edge": "chromium",
  "boringssl-quic": "chromium",
  "boringssl-quic-edge": "chromium",
  nss: "firefox",
  securetransport: "apple",
  "securetransport-legacy": "apple",
};

/** Browsers whose baseline key maps to a TLS family for cross-validation. */
const BROWSER_TLS_FAMILY: Record<string, string> = {
  chrome: "chromium",
  edge: "chromium",
  opera: "chromium",
  firefox: "firefox",
  safari: "apple",
};

/** Known modern browsers that always negotiate h2+ ALPN. */
const REAL_BROWSERS = new Set(["chrome", "safari", "firefox", "edge", "opera"]);

/** Parse JA4 string into components. */
function parseJa4(ja4: string): {
  proto: string;
  cipherHash: string;
  alpn: string;
} | null {
  // JA4 format: "t13d1516h2_8daaf6152771_e5627efa2ab1"
  const parts = ja4.split("_");
  if (parts.length < 2) return null;
  const prefix = parts[0]; // e.g. "t13d1516h2"
  const cipherHash = parts[1]; // e.g. "8daaf6152771"
  const proto = prefix[0] === "q" ? "quic" : "tcp";
  const alpn = prefix.length >= 2 ? prefix.slice(-2) : "";
  return { proto, cipherHash, alpn };
}

/**
 * Rule 1: TLS stack doesn't exist on claimed OS.
 * Hard-impossible: e.g., Secure Transport on Windows, BoringSSL on iOS.
 */
function checkTlsPlatformMismatch(
  stack: { stack: string; platforms: Set<string> },
  identity: BrowserIdentity,
): AnomalySignal | null {
  if (stack.platforms.has(identity.os)) return null;
  return createSignal("IDENTITY", AnomalyCodes.TLS_PLATFORM_MISMATCH, 0.95, {
    expected: `TLS stack ${stack.stack} valid on: ${[...stack.platforms].join(", ")}`,
    actual: `claimed OS: ${identity.os}`,
    fields: [F_JA4, "browser.os"],
  });
}

/**
 * Rule 2: TLS stack doesn't match claimed browser.
 * Suppressed on iOS where all browsers use Secure Transport.
 */
function checkTlsBrowserMismatch(
  stack: { stack: string },
  identity: BrowserIdentity,
): AnomalySignal | null {
  if (identity.os === "iOS") return null;

  const expectedFamily = STACK_H2_FAMILY[stack.stack];
  if (!expectedFamily) return null;
  const browserFamily = BROWSER_TLS_FAMILY[identity.baselineKey];
  if (!browserFamily) return null;

  if (expectedFamily === browserFamily) return null;
  return createSignal("IDENTITY", AnomalyCodes.TLS_BROWSER_MISMATCH, 0.9, {
    expected: `TLS stack ${stack.stack} → ${expectedFamily}`,
    actual: `browser ${identity.browser} (${identity.baselineKey}) → ${browserFamily}`,
    fields: [F_JA4, "browser.baselineKey"],
  });
}

/**
 * Rule 3: H2 pseudo-header order conflicts with TLS cipher hash.
 * Suppressed for VPN pattern (QUIC + apple H2 + boringssl cipher).
 */
function checkH2TlsMismatch(
  stack: { stack: string },
  h2Order: string,
  proto: string,
): AnomalySignal | null {
  const h2Family = H2_FAMILIES[h2Order];
  if (!h2Family) return null;
  const tlsFamily = STACK_H2_FAMILY[stack.stack];
  if (!tlsFamily) return null;
  if (h2Family === tlsFamily) return null;

  // Suppress VPN pattern: QUIC transport + apple H2 + boringssl TLS
  if (proto === "quic" && h2Family === "apple" && tlsFamily === "chromium") {
    return null;
  }

  return createSignal("IDENTITY", AnomalyCodes.H2_TLS_MISMATCH, 0.85, {
    expected: `H2 order "${h2Order}" → ${h2Family} matches TLS ${stack.stack} → ${tlsFamily}`,
    actual: `H2 says ${h2Family}, TLS says ${tlsFamily}`,
    fields: ["fingerprint.h2_pseudo_header_order", F_JA4],
  });
}

/** Rule 4: QUIC from claimed iOS device — informational VPN indicator. */
function checkQuicIosVpn(
  proto: string,
  identity: BrowserIdentity,
): AnomalySignal | null {
  if (proto !== "quic" || identity.os !== "iOS") return null;
  return createSignal("NETWORK", AnomalyCodes.QUIC_IOS_VPN, 0.1, {
    expected: "iOS uses TCP (QUIC not natively supported for third-party apps)",
    actual: `QUIC transport from claimed ${identity.os} device`,
    fields: [F_JA4, "browser.os"],
  });
}

/** Rule 5: No ALPN negotiation but UA claims a modern browser. */
function checkNoAlpnBrowser(
  alpn: string,
  identity: BrowserIdentity,
): AnomalySignal | null {
  if (alpn !== "00" && alpn !== "h1") return null;
  if (!REAL_BROWSERS.has(identity.baselineKey)) return null;

  return createSignal("IDENTITY", AnomalyCodes.NO_ALPN_BROWSER, 0.9, {
    expected: `browser ${identity.browser} negotiates h2+ ALPN`,
    actual: `ALPN: ${alpn === "00" ? "none" : alpn}`,
    fields: [F_JA4, "browser.browser"],
  });
}

/** Collect TLS-stack-dependent signals when we have a known cipher hash. */
function collectStackSignals(
  stack: { stack: string; platforms: Set<string> },
  identity: BrowserIdentity,
  fingerprint: Fingerprint,
  proto: string,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];
  const s1 = checkTlsPlatformMismatch(stack, identity);
  if (s1) signals.push(s1);

  const s2 = checkTlsBrowserMismatch(stack, identity);
  if (s2) signals.push(s2);

  if (fingerprint.h2_pseudo_header_order) {
    const s3 = checkH2TlsMismatch(
      stack,
      fingerprint.h2_pseudo_header_order,
      proto,
    );
    if (s3) signals.push(s3);
  }
  return signals;
}

/**
 * Detect JA4/H2 coherence anomalies.
 *
 * Cross-validates TLS cipher hash, H2 pseudo-header order, and ALPN
 * against claimed browser identity from the raw device payload.
 */
export function detectJa4Coherence(
  fingerprint: Fingerprint,
  raw?: unknown,
  sigint?: unknown,
): AnomalySignal[] {
  if (!fingerprint.ja4) return [];
  const parsed = parseJa4(fingerprint.ja4);
  if (!parsed) return [];

  const identity = resolveBrowserIdentity(raw, sigint);
  const stack = TLS_STACKS[parsed.cipherHash];

  const signals = stack
    ? collectStackSignals(stack, identity, fingerprint, parsed.proto)
    : [];

  const s4 = checkQuicIosVpn(parsed.proto, identity);
  if (s4) signals.push(s4);

  const s5 = checkNoAlpnBrowser(parsed.alpn, identity);
  if (s5) signals.push(s5);

  return signals;
}
