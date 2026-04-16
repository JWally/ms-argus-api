/**
 * Shared TLS / H2 Reference Maps
 *
 * Maps JA4 cipher hashes to TLS stacks, TLS stacks to browser families,
 * and H2 pseudo-header orders to browser families. Used by both
 * ja4-coherence and engine-coherence detectors.
 *
 * @module services/profile/anomaly/tls-maps
 */

/** TLS stack lookup by JA4 cipher hash (12-char hex after first underscore). */
export const TLS_STACKS: Record<
  string,
  { stack: string; platforms: Set<string> }
> = {
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

/** TLS stack → expected browser family. */
export const STACK_H2_FAMILY: Record<string, string> = {
  boringssl: "chromium",
  "boringssl-edge": "chromium",
  "boringssl-quic": "chromium",
  "boringssl-quic-edge": "chromium",
  nss: "firefox",
  securetransport: "apple",
  "securetransport-legacy": "apple",
};

/** Parse JA4 string into components. */
export function parseJa4(ja4: string): {
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
