/**
 * Known ASN catalog for IP classification.
 *
 * Categories:
 * - datacenter:     cloud/hosting providers — real browsers don't originate here
 * - vpn_proxy:      known VPN and proxy service infrastructure
 * - corporate_proxy:enterprise security gateways (Zscaler, Umbrella, etc.)
 * - privacy_relay:  consumer privacy relays (Apple Private Relay, Cloudflare
 *                   WARP). Network-layer looks like a proxy, but users are
 *                   legitimate consumers — don't auto-fail.
 * - mobile:         cellular carriers — used with SAME_SUBNET_CGNAT to tag cellular
 */

export type AsnCategory =
  | "datacenter"
  | "vpn_proxy"
  | "corporate_proxy"
  | "privacy_relay"
  | "mobile";

interface AsnEntry {
  category: AsnCategory;
  org: string;
}

const ASN_CATALOG: Record<string, AsnEntry> = {
  // ── Datacenter / Cloud / Hosting ──────────────────────────────
  // AWS
  "16509": { category: "datacenter", org: "Amazon.com" },
  "14618": { category: "datacenter", org: "Amazon.com" },
  "8987": { category: "datacenter", org: "Amazon Data Services Ireland" },
  // Google
  "15169": { category: "datacenter", org: "Google" },
  "396982": { category: "datacenter", org: "Google" },
  "19527": { category: "datacenter", org: "Google" },
  "139070": { category: "datacenter", org: "Google Asia Pacific" },
  // Microsoft / Azure
  "8075": { category: "datacenter", org: "Microsoft Corporation" },
  "8068": { category: "datacenter", org: "Microsoft Corporation" },
  // DigitalOcean
  "14061": { category: "datacenter", org: "DigitalOcean" },
  // OVH
  "16276": { category: "datacenter", org: "OVH SAS" },
  // Hetzner
  "24940": { category: "datacenter", org: "Hetzner Online" },
  // Linode / Akamai
  "63949": { category: "datacenter", org: "Akamai Connected Cloud (Linode)" },
  // Vultr
  "20473": { category: "datacenter", org: "The Constant Company (Vultr)" },
  // Oracle Cloud
  "31898": { category: "datacenter", org: "Oracle Corporation" },
  // Alibaba Cloud
  "45102": { category: "datacenter", org: "Alibaba Cloud" },
  // Tencent Cloud
  "132203": { category: "datacenter", org: "Tencent Cloud" },
  // Scaleway
  "12876": { category: "datacenter", org: "Scaleway (Online SAS)" },
  // Contabo
  "40021": { category: "datacenter", org: "Contabo" },
  // Hostinger
  "47583": { category: "datacenter", org: "Hostinger" },

  // ── Provider-owned VPN Networks ───────────────────────────────
  // Current RIR registrations validated 2026-07-22. Do not put rented or
  // mixed-use hosting ASNs here: this catalog is a hard-verdict fallback.
  "199218": { category: "vpn_proxy", org: "ProtonVPN" },
  "203619": { category: "vpn_proxy", org: "IVPN Limited" },
  "209103": { category: "vpn_proxy", org: "ProtonVPN" },
  "214879": { category: "vpn_proxy", org: "SkyVPN" },
  "216025": { category: "vpn_proxy", org: "Mullvad VPN AB" },
  "57138": { category: "vpn_proxy", org: "Mullvad VPN AB" },
  "397282": { category: "vpn_proxy", org: "Castle VPN" },
  "397540": { category: "vpn_proxy", org: "Windscribe" },
  // M247 (hosts NordVPN, CyberGhost, and many others)
  "9009": { category: "vpn_proxy", org: "M247 Ltd" },

  // ── Corporate Proxy / Security Gateways ───────────────────────
  // Cisco Umbrella
  "36692": { category: "corporate_proxy", org: "Cisco OpenDNS / Umbrella" },
  // Zscaler
  "398324": { category: "corporate_proxy", org: "Zscaler" },
  "22616": { category: "corporate_proxy", org: "Zscaler" },
  "62044": { category: "corporate_proxy", org: "Zscaler" },
  // Palo Alto Prisma Access
  "396507": {
    category: "corporate_proxy",
    org: "Palo Alto Networks / Prisma Access",
  },

  // ── Privacy Relays (consumer privacy, not fraud signal) ───────
  // Cloudflare (main AS) — hosts the CDN, WARP consumer VPN, and
  // edges for Apple Private Relay (egress side). Consumer traffic
  // from AS13335 is almost always a legit privacy-conscious user.
  "13335": { category: "privacy_relay", org: "Cloudflare" },
  // Cloudflare WARP (1.1.1.1 consumer VPN)
  "209242": { category: "privacy_relay", org: "Cloudflare WARP" },
  // Apple — iCloud Private Relay (Apple One, iCloud+ subscribers)
  "714": { category: "privacy_relay", org: "Apple Inc." },
  "6185": { category: "privacy_relay", org: "Apple Inc." },
  // Akamai — second-hop egress for Apple Private Relay
  "16625": {
    category: "privacy_relay",
    org: "Akamai Technologies (Apple Private Relay egress)",
  },
  "20940": {
    category: "privacy_relay",
    org: "Akamai International (Apple Private Relay egress)",
  },

  // ── Mobile Carriers (US) ──────────────────────────────────────
  // T-Mobile / Sprint (merged)
  "21928": { category: "mobile", org: "T-Mobile USA" },
  "20057": { category: "mobile", org: "AT&T Mobility" },
  "22394": { category: "mobile", org: "Cellco Partnership (Verizon Wireless)" },
  "6167": { category: "mobile", org: "Cellco Partnership (Verizon Wireless)" },
  "10507": { category: "mobile", org: "Sprint PCS (legacy)" },
  // Cricket (AT&T)
  "19108": { category: "mobile", org: "Cricket Wireless / AT&T" },
  // US Cellular (regional)
  "6315": { category: "mobile", org: "United States Cellular Corp." },
  // ── Mobile Carriers (UK / EU) ─────────────────────────────────
  "25135": { category: "mobile", org: "Vodafone UK (mobile)" },
  "5607": { category: "mobile", org: "Sky UK (mobile)" },
  "12576": { category: "mobile", org: "EE Limited (UK mobile)" },
  "6805": { category: "mobile", org: "Telefonica Deutschland (O2)" },
  // ── Mobile Carriers (APAC) ────────────────────────────────────
  "45609": { category: "mobile", org: "Bharti Airtel (India mobile)" },
  "55836": { category: "mobile", org: "Reliance Jio (India mobile)" },
  "17639": { category: "mobile", org: "Globe Telecom (PH mobile)" },
  "17858": { category: "mobile", org: "LG U+ (KR mobile)" },
  "9605": { category: "mobile", org: "NTT DOCOMO (JP mobile)" },
};

/**
 * Look up an ASN in the catalog.
 * @returns category and org name, or null if ASN is not cataloged (presumed residential)
 */
export function lookupAsn(
  asn: string | number | undefined | null,
): AsnEntry | null {
  if (asn == null) return null;
  return ASN_CATALOG[String(asn)] ?? null;
}
