/**
 * Network-derived stable identifier for fraud prevention.
 *
 * Acts as a backup ID alongside `crypto_device_id` (ECDSA pubkey hash) and
 * `tpc_id` (CloudFront-stamped third-party cookie). Useful when neither of
 * those is available (first visit, no cookie, no device-identity bundle).
 *
 * Two-pass derivation:
 *
 *   Pass 1 — Recognized network class:
 *     residential / satellite
 *       → hash(ip_/24 + ua_normalized)
 *       Residential and Starlink IPs are stable per-household for
 *       weeks-to-months and carry ~6–8 bits of usable entropy. Combined
 *       with UA they give a collision class around 1-in-65k–8M.
 *     mobile / privacy_relay / vpn_proxy / hosting_proxy / datacenter /
 *     cdn / business / security_filter / education / government
 *       → null  (shared/transient IPs — IP+UA hashing collapses many
 *                strangers into the same bucket. Merchant must rely on
 *                crypto_device_id or device FP for these populations.)
 *
 *   Pass 2 — Unrecognized ASN (long-tail carriers, regional ISPs, the
 *            ~96% of ASNs the regex/overrides don't cover):
 *     → hash(asn + ip_/24 + ua_normalized)
 *     The ASN itself acts as a discriminator; the merchant treats this as
 *     lower-trust ("asn_fallback") and weights accordingly. We can't tell
 *     whether the network is residential or cellular, but the ASN gives
 *     more entropy than nothing and is correct often enough to be useful.
 */
import { createHash } from "node:crypto";
import type { NetworkCategory } from "./asn-classifier";

export type NetworkIdSource = "category_residential" | "asn_fallback" | "none";

export interface NetworkIdInput {
  /** ASN number from CloudFront (already free of any IP-lookup cost). */
  asn: number | null;
  /** Broader network class from the ASN dataset (mobile / residential / …). */
  networkClass: NetworkCategory | null;
  /** Representative client IP — `analysis.ip.ip` from the integrity record. */
  ip: string | null;
  /** User-Agent header. */
  userAgent: string | null;
}

export interface NetworkIdResult {
  /** 16-hex-char (64-bit) stable ID, or null when no useful ID is derivable. */
  id: string | null;
  /** Which strategy produced this ID — informs merchant trust levels. */
  source: NetworkIdSource;
}

/**
 * Categories where IP+UA hashing is meaningful — the IP is stable per
 * subscriber and the user-density per-IP is low (typically one household).
 *
 * Residential consumer broadband and Starlink fit this profile. Everything
 * else (mobile CGNAT, corporate egress, university wifi, government wifi,
 * VPN exits, datacenters) collapses too many strangers behind one IP for
 * IP+UA to function as an identifier — treat them as null and rely on
 * crypto_device_id or device fingerprinting downstream.
 */
const RESIDENTIAL_CLASSES = new Set<NetworkCategory>([
  "residential",
  "satellite",
]);

/**
 * Strip Chrome/Firefox/Safari minor build versions so the ID survives
 * routine browser auto-updates (Chrome ships every ~6 weeks). Keeps the
 * major version + platform for cross-version collision avoidance.
 *
 * Examples:
 *   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.6478.127 Safari/537.36"
 *     → "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36"
 *   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) Version/17.5"
 *     → "Mozilla/5.0 (iPhone; CPU iPhone OS 17 like Mac OS X) Version/17"
 */
export function normalizeUa(ua: string): string {
  return ua
    .replace(/(Chrome|Firefox|Safari|Edg|OPR|Version)\/(\d+)\.[\d.]+/g, "$1/$2")
    .replace(/CPU iPhone OS (\d+)[\d_]+/g, "CPU iPhone OS $1")
    .replace(/Android (\d+)\.[\d.]+/g, "Android $1")
    .replace(/Mac OS X (\d+)[\d_]+/g, "Mac OS X $1")
    .replace(/Windows NT \d+\.\d+/g, "Windows NT")
    .trim();
}

/**
 * Convert an IPv4 address to its /24 base address as a string. Drops the
 * last octet to absorb minor IP rotations within an ISP's allocated block
 * (CGNAT-lite, DHCP renewal jitter).
 *
 * Returns null for invalid IPs or IPv6 (separate /64 logic if you ever want it).
 */
export function ipv4To24(ip: string): string | null {
  const m = /^(\d+)\.(\d+)\.(\d+)\.\d+$/.exec(ip.trim());
  if (!m) return null;
  const a = +m[1],
    b = +m[2],
    c = +m[3];
  if ([a, b, c].some((n) => n < 0 || n > 255)) return null;
  return `${a}.${b}.${c}.0/24`;
}

function shortHash(parts: readonly (string | number | null)[]): string {
  return createHash("sha256")
    .update(parts.map((p) => String(p ?? "")).join("|"))
    .digest("hex")
    .slice(0, 16);
}

export function deriveNetworkId(input: NetworkIdInput): NetworkIdResult {
  const { asn, networkClass, ip, userAgent } = input;
  if (!ip || !userAgent) return { id: null, source: "none" };
  const ipKey = ipv4To24(ip);
  if (!ipKey) return { id: null, source: "none" };
  const ua = normalizeUa(userAgent);

  // Pass 1: known network class. Only emit IP-based IDs for true
  // single-household-per-IP populations (residential / satellite). For any
  // other recognized class — mobile, vpn_proxy, datacenter, business,
  // education, gov, etc. — IP+UA collapses too many strangers together to
  // function as an identifier; return null and let merchants fall back to
  // crypto_device_id or device fingerprinting.
  if (networkClass && RESIDENTIAL_CLASSES.has(networkClass)) {
    return {
      id: shortHash([networkClass, ipKey, ua]),
      source: "category_residential",
    };
  }
  if (networkClass && networkClass !== "unknown") {
    return { id: null, source: "none" };
  }

  // Pass 2: unrecognized ASN — fall back to ASN+IP+UA. The ASN itself adds
  // discrimination; lower trust than category-derived IDs (we don't actually
  // know whether this is a residential or cellular network), so merchant
  // weights it accordingly via the source field.
  if (asn != null) {
    return {
      id: shortHash(["asn", asn, ipKey, ua]),
      source: "asn_fallback",
    };
  }

  return { id: null, source: "none" };
}
