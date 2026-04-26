/**
 * CIDR overlay for mixed-use ASNs.
 *
 * Some ASNs route both consumer-broadband and cellular traffic (notably
 * AT&T 7018, which carries both U-Verse and AT&T Mobility). The dynamic
 * IPtoASN dataset can't disambiguate these because its key is ASN-only.
 * This file holds ARIN-derived sub-allocation CIDRs that resolve the IP to
 * a more specific category.
 *
 * Resolution order at lookup time:
 *   1. ASN dict (asn-classifier) — wins for ~99% of consumer ASNs
 *   2. CIDR overlay (this file) — resolves mixed-use ASNs
 *   3. ASN-fallback ID (network-id) — when neither classifies
 *
 * Sources:
 *   - ARIN RDAP queries on 2026-04-25 against representative IPs from the
 *     integrity archive (verified 17/18 agreement with the WebRTC-split
 *     ground-truth signal across AT&T 7018 iPhone sessions).
 *   - Public knowledge of T-Mobile / Verizon Wireless cellular blocks.
 *
 * To add a new mixed-use ASN:
 *   1. Run `whois -h whois.arin.net <example_ip>` (or RDAP equivalent) to
 *      find the sub-allocation name and parent CIDR.
 *   2. Append an entry below.
 *   3. Re-deploy. No build pipeline rebuild needed (unlike the ASN dict).
 */
import type { NetworkCategory } from "./categorize";

interface CidrOverlayEntry {
  cidr: string;
  category: NetworkCategory;
  /** Human-readable note (ARIN sub-allocation name, source, etc.) */
  note: string;
}

const ATT_MOBILITY = "ATT-MOBILITY-LLC";
const ATT_UVERSE = "AT&T SBCIS-SBIS (U-Verse)";
const TMOBILE = "T-MOBILE-USA cellular";
const VZW = "CELLCO Verizon Wireless";

const RAW_OVERLAY: CidrOverlayEntry[] = [
  // ─── AT&T (ASN 7018 — mixed: U-Verse residential + Mobility cellular)
  {
    cidr: "107.64.0.0/10",
    category: "mobile",
    note: `${ATT_MOBILITY} (4M IPs)`,
  },
  { cidr: "104.176.0.0/12", category: "mobile", note: ATT_MOBILITY },
  {
    cidr: "107.192.0.0/11",
    category: "residential",
    note: "AT&T SIS-80-4-2012 (U-Verse fiber/DSL)",
  },
  { cidr: "108.192.0.0/10", category: "residential", note: ATT_UVERSE },
  { cidr: "76.192.0.0/10", category: "residential", note: ATT_UVERSE },
  {
    cidr: "75.0.0.0/9",
    category: "residential",
    note: "AT&T residential (legacy SBC)",
  },
  { cidr: "99.87.192.0/18", category: "residential", note: ATT_UVERSE },
  { cidr: "99.88.0.0/13", category: "residential", note: ATT_UVERSE },
  { cidr: "99.96.0.0/13", category: "residential", note: ATT_UVERSE },
  { cidr: "99.104.0.0/16", category: "residential", note: ATT_UVERSE },
  { cidr: "99.105.0.0/17", category: "residential", note: ATT_UVERSE },

  // ─── AT&T Mobility (some sub-allocations show under ASN 20057 instead of 7018)
  {
    cidr: "32.128.0.0/9",
    category: "mobile",
    note: `${ATT_MOBILITY} (legacy)`,
  },
  { cidr: "166.137.0.0/16", category: "mobile", note: ATT_MOBILITY },
  { cidr: "166.139.0.0/16", category: "mobile", note: ATT_MOBILITY },
  { cidr: "166.146.0.0/15", category: "mobile", note: ATT_MOBILITY },
  { cidr: "166.196.0.0/14", category: "mobile", note: ATT_MOBILITY },
  { cidr: "166.216.0.0/15", category: "mobile", note: ATT_MOBILITY },

  // ─── T-Mobile USA cellular (ASN 21928 covers some non-cellular too)
  { cidr: "172.56.0.0/14", category: "mobile", note: TMOBILE },
  { cidr: "172.58.0.0/15", category: "mobile", note: TMOBILE },
  { cidr: "208.54.0.0/16", category: "mobile", note: TMOBILE },

  // ─── Verizon Wireless (ASN 6167 / 22394 sometimes carry non-cellular)
  { cidr: "174.192.0.0/9", category: "mobile", note: VZW },
  { cidr: "70.192.0.0/11", category: "mobile", note: VZW },
  { cidr: "97.0.0.0/10", category: "mobile", note: VZW },
  { cidr: "159.4.0.0/16", category: "mobile", note: VZW },

  // ─── US Cellular (ASN 6614 — `mobile.uscc.com` PTR; verified via SOAX-mobile
  //     batch 2026-04-26: USCC exits 166.181.x and 166.182.x came back as
  //     `network_class: null` because ASN 6614 isn't in the dynamic dict. Both
  //     /16s are USL-63 in ARIN RDAP.)
  { cidr: "166.181.0.0/16", category: "mobile", note: "US Cellular (USL-63)" },
  { cidr: "166.182.0.0/16", category: "mobile", note: "US Cellular (USL-63)" },

  // ─── RFC 6598 CGNAT shared address space (ISP-internal — never directly routable)
  {
    cidr: "100.64.0.0/10",
    category: "mobile",
    note: "RFC6598 CGNAT shared address space",
  },

  // ─── Starlink (consumer-grade satellite — separate ASN, included for completeness)
  {
    cidr: "143.105.0.0/16",
    category: "satellite",
    note: "STARLINK customer block",
  },
];

import { compileCidrList, lookupInRanges } from "./cidr-tree";

const COMPILED = compileCidrList(
  RAW_OVERLAY.map((e) => ({
    cidr: e.cidr,
    category: e.category,
    meta: { note: e.note },
  })),
);

/**
 * Look up an IPv4 address against the hand-curated overlay. Returns the
 * matching category + note when the IP falls inside any overlay range,
 * else null. O(log n) binary search; ~30 entries → ~5 comparisons.
 */
export function lookupCidrOverlay(
  ip: string,
): { category: NetworkCategory; note: string } | null {
  const hit = lookupInRanges(COMPILED, ip);
  if (!hit) return null;
  return {
    category: hit.category,
    note: (hit.meta as { note: string } | undefined)?.note ?? "",
  };
}
