/**
 * Known ASN catalog for IP classification.
 *
 * Categories:
 * - datacenter: cloud/hosting providers — real browsers don't originate here
 * - vpn_proxy: known VPN and proxy service infrastructure
 * - corporate_proxy: enterprise security gateways (Zscaler, Umbrella, etc.)
 */

export type AsnCategory = "datacenter" | "vpn_proxy" | "corporate_proxy";

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
  // Cloudflare (also used for WARP/Gateway — dual categorized below)
  "13335": { category: "datacenter", org: "Cloudflare" },
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

  // ── VPN / Proxy Providers ─────────────────────────────────────
  // NordVPN (operates under Datacamp Limited)
  "212238": { category: "vpn_proxy", org: "Datacamp Limited (NordVPN)" },
  "57523": { category: "vpn_proxy", org: "Datacamp Limited (NordVPN)" },
  // ExpressVPN (Kape Technologies)
  "394711": { category: "vpn_proxy", org: "Kape Technologies (ExpressVPN)" },
  // Mullvad
  "198093": { category: "vpn_proxy", org: "Mullvad VPN" },
  // Surfshark
  "212029": { category: "vpn_proxy", org: "Surfshark" },
  // ProtonVPN
  "209103": { category: "vpn_proxy", org: "Proton AG" },
  // IPVanish
  "33438": { category: "vpn_proxy", org: "Highwinds Network Group (IPVanish)" },
  // M247 (hosts NordVPN, CyberGhost, and many others)
  "9009": { category: "vpn_proxy", org: "M247 Ltd" },

  // ── Corporate Proxy / Security Gateways ───────────────────────
  // Cisco Umbrella
  "36692": { category: "corporate_proxy", org: "Cisco OpenDNS / Umbrella" },
  // Zscaler
  "398324": { category: "corporate_proxy", org: "Zscaler" },
  "22616": { category: "corporate_proxy", org: "Zscaler" },
  "62044": { category: "corporate_proxy", org: "Zscaler" },
  // Cloudflare WARP / Gateway
  "209242": { category: "corporate_proxy", org: "Cloudflare WARP" },
  // Palo Alto Prisma Access
  "396507": {
    category: "corporate_proxy",
    org: "Palo Alto Networks / Prisma Access",
  },
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
