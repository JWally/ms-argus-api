/**
 * Shared regex categorizer for sub-allocation / ASN org names.
 *
 * One source of truth used by:
 *   - ip-class-builder Lambda (weekly IPtoASN org-name → ASN→category dict)
 *   - ip-class-discoverer Lambda (nightly RDAP sub-allocation → CIDR rule)
 *
 * Order matters — first match wins. Mobile patterns precede residential so
 * "MOBILE BROADBAND" is classified as mobile rather than residential.
 *
 * The categorizer accepts multiple candidate strings per call (name, entity
 * org, nameservers) — useful for non-English RIR responses where the `name`
 * field is a numeric handle but the carrier brand surfaces in nameserver
 * delegations (e.g. LACNIC's BR responses use `vivo.com.br` nameservers
 * for Telefónica Vivo mobile but a generic numeric `name`).
 */

export type NetworkCategory =
  | "mobile"
  | "residential"
  | "datacenter"
  | "vpn_proxy"
  | "hosting_proxy"
  | "cdn"
  | "satellite"
  | "privacy_relay"
  | "security_filter"
  | "business"
  | "education"
  | "government";

interface CategoryRule {
  pattern: RegExp;
  category: NetworkCategory;
}

const RULES: CategoryRule[] = [
  // ─── Mobile (English)
  {
    pattern:
      /\bMOBILITY\b|\bMOBIL\b|\bMOBILE\b(?!\s*(?:HOME|BROADBAND-FIXED))/i,
    category: "mobile",
  },
  { pattern: /\bWIRELESS\b(?!.*\bFIXED\b)/i, category: "mobile" },
  { pattern: /\bCELLULAR\b|\bCELLCO\b|\bCELLNET\b/i, category: "mobile" },
  { pattern: /\bCINGULAR\b|\bATT\s*-?\s*MOBILITY\b/i, category: "mobile" },
  { pattern: /\bT-?MOBILE\b|\bTMOB\b/i, category: "mobile" },
  { pattern: /\bSPRINTLINK\b|\bSPRINT-?MOBILE\b/i, category: "mobile" },
  {
    pattern: /\bVERIZON-?WIRELESS\b|\bVZW\b|\bVZ-WIRELESS\b/i,
    category: "mobile",
  },
  { pattern: /\b(?:LTE|4G|5G)-NETWORK\b/i, category: "mobile" },
  { pattern: /\bGSM\b|\bUMTS\b/i, category: "mobile" },

  // ─── Mobile (multilingual)
  // Spanish: móvil / movil
  { pattern: /\bMÓVIL\b|\bMOVIL\b/i, category: "mobile" },
  // Portuguese: móvel / movel + Brazilian carriers
  { pattern: /\bMÓVEL\b|\bMOVEL\b|\bCELULAR\b/i, category: "mobile" },
  // German
  { pattern: /\bMOBILFUNK\b/i, category: "mobile" },
  // French
  { pattern: /\bCELLULAIRE\b/i, category: "mobile" },

  // ─── Mobile carrier brand names (RDAP discoveries 2026-04-26)
  // UK: EE/3 mobile sub-allocations
  { pattern: /\bEE-MOBILE\b|\bMSM-EXTERNAL\b/i, category: "mobile" },
  // German: O2/Telefónica + Vodafone-DE D2 historical mobile brand
  {
    pattern: /\bMOBILE-POOL-NET\b|\bD2VODAFONE\b|\bO2\b/i,
    category: "mobile",
  },
  // Vodafone strategic-connectivity = mobile in RIPE labels.
  // No trailing \b on VF[_-]STRATEGIC because RDAP names like
  // "VF_Strategic_Connectivity" continue with `_` (a JS word char).
  {
    pattern: /\bVF[_-]STRATEGIC|\bVODAFONE-?(?:UK|DE|MOBILE)\b/i,
    category: "mobile",
  },
  // Brazilian mobile brands (LACNIC name field is numeric — match on
  // entity-org / nameserver instead)
  {
    pattern: /\bVIVO\b|\bCLARO-?(?:MOVEL|MOBILE)\b|\bTIM-?(?:BR|MOBILE)\b/i,
    category: "mobile",
  },
  // Latin-American Movistar mobile branding
  {
    pattern: /\bMOVISTAR-?(?:MOVIL|MÓVIL|MOBIL|MOBILE)\b/i,
    category: "mobile",
  },
  // French Orange mobile
  { pattern: /\bORANGE-?MOBILE\b/i, category: "mobile" },
  // Telstra Mobile sub-allocations are numbered TELSTRAINTERNET\d+
  // (whereas Telstra fixed uses different naming patterns)
  { pattern: /\bTELSTRAINTERNET\d+\b/i, category: "mobile" },

  // ─── Satellite
  { pattern: /\bSTARLINK\b|\bSPACEX\b/i, category: "satellite" },
  {
    pattern: /\bVIASAT\b|\bHUGHES(NET)?\b|\bINMARSAT\b|\bIRIDIUM\b/i,
    category: "satellite",
  },

  // ─── Residential consumer broadband
  { pattern: /\bBROADBAND\b|\bBSKYB\b/i, category: "residential" },
  {
    pattern: /\bFIBRE\b|\bFIBER\b|\bFTTH\b|\bFTTP\b|\bFIOS\b/i,
    category: "residential",
  },
  {
    pattern: /\bCABLE(?!.*BUSINESS)\b|\bDOCSIS\b|\bHFC\b/i,
    category: "residential",
  },
  { pattern: /\bDSL\b|\bADSL\b|\bVDSL\b/i, category: "residential" },
  { pattern: /\bLIGHTSPEED\b|\bLIGHTWAVE\b/i, category: "residential" },
  // RIPE label "LLU" (Local Loop Unbundling) is fixed-line wholesale broadband
  { pattern: /\bLLU\b/i, category: "residential" },
  {
    pattern: /\bRESIDENTIAL\b|\bRES-CON\b|\bHOME-NETWORK\b/i,
    category: "residential",
  },
  // AT&T legacy SBC + U-Verse + SIS sub-allocation series
  {
    pattern: /\bSBCIS\b|\bSBC-INTERNET\b|\bUVERSE\b|\bU-VERSE\b|\bSIS-\d+\b/i,
    category: "residential",
  },
  {
    pattern: /\bCOMCAST\b(?!.*BUSINESS)|\bXFINITY\b/i,
    category: "residential",
  },
  {
    pattern: /\bCHARTER\b(?!.*BUSINESS)|\bSPECTRUM\b/i,
    category: "residential",
  },
  {
    pattern: /\bCOX(?!.*BUSINESS)\b|\bASN-CXA-ALL-CCI\b/i,
    category: "residential",
  },
  { pattern: /\bCENTURYLINK\b|\bLUMEN\b|\bQWEST\b/i, category: "residential" },
  { pattern: /\bFRONTIER-?(?:FRTR|COMM|NET)?\b/i, category: "residential" },
  {
    pattern:
      /\bVIRGIN-?MEDIA\b|\bVIRGINMEDIA\b|\bVIRGIN-?BROADBAND\b|\bNTL\b(?!\w)/i,
    category: "residential",
  },
  { pattern: /\bEIRCOM\b|\bEIR\b/i, category: "residential" },
  {
    pattern: /\bBT-?(?:UK|NET|GROUP|CENTRAL)\b|\bBTNET\b|\bBTOPENWORLD\b/i,
    category: "residential",
  },
  {
    pattern: /\bPLUSNET\b|\bTALKTALK\b|\bSKY-?BROADBAND\b/i,
    category: "residential",
  },
  // German fixed-line: ARCOR (DSL brand acquired by Vodafone), TEDE-LLU
  // (Telefónica DE wholesale fixed)
  {
    pattern: /\bARCOR\b|\bTEDE-?LLU\b|\bDEUTSCHE-?TELEKOM\b(?!.*MOBILE)/i,
    category: "residential",
  },
  {
    pattern: /\bORANGE\b|\bFREE-AS\b|\bSFR-AS\b|\bBOUYGUES-?TELECOM\b/i,
    category: "residential",
  },
  {
    pattern: /\bVODAFONE-?(?:DE|UK)\b(?!.*MOBILE)/i,
    category: "residential",
  },
  {
    pattern:
      /\bROGERS-?(?:CABLE|COMM)?\b|\bBELL-?CANADA\b|\bSHAW-?COMM\b|\bTELUS-?COMM\b/i,
    category: "residential",
  },

  // ─── CDN
  { pattern: /\bCLOUDFLARENET?\b|\bCLOUDFLARE-?NET\b/i, category: "cdn" },
  { pattern: /\bAKAMAI\b/i, category: "cdn" },
  { pattern: /\bFASTLY\b/i, category: "cdn" },
  { pattern: /\bEDGECAST\b|\bINCAPSULA\b|\bIMPERVA\b/i, category: "cdn" },

  // ─── Datacenter / hyperscaler
  {
    pattern: /\bAMAZON\b(?!.*MUSIC)|\bAWS\b|\bAMZN\b/i,
    category: "datacenter",
  },
  {
    pattern: /\bGOOGLE-?(?:CLOUD)?\b|\bGCP\b|\bGOOG\b/i,
    category: "datacenter",
  },
  { pattern: /\bMICROSOFT\b|\bMSFT\b|\bAZURE\b/i, category: "datacenter" },
  { pattern: /\bORACLE-?(?:CLOUD|PUBLIC|BMCS)\b/i, category: "datacenter" },
  { pattern: /\bIBM(?:-CLOUD)?\b|\bSOFTLAYER\b/i, category: "datacenter" },
  { pattern: /\bDIGITALOCEAN\b|\bDIGITAL-OCEAN\b/i, category: "datacenter" },
  { pattern: /\bLINODE\b/i, category: "datacenter" },
  { pattern: /\bVULTR\b|\bCHOOPA\b/i, category: "datacenter" },
  { pattern: /\bOVH(SAS)?\b|\bOVH-?CLOUD\b/i, category: "datacenter" },
  { pattern: /\bHETZNER\b/i, category: "datacenter" },
  { pattern: /\bRACKSPACE\b/i, category: "datacenter" },
  { pattern: /\bSCALEWAY\b|\bONLINE-NET\b/i, category: "datacenter" },
  { pattern: /\bALIBABA\b|\bALICLOUD\b|\bALIYUN\b/i, category: "datacenter" },
  { pattern: /\bTENCENT\b/i, category: "datacenter" },

  // ─── Datacenter REITs / colocation operators
  // These don't ship their own hyperscaler product line — they lease cage/
  // rack space to others (BrowserStack, SaaS startups, niche hosts). RDAP
  // names typically include the operator brand plus a facility code
  // (e.g. "QTS-SUW1-ATL1", "EQUINIX-IX-LON5").
  { pattern: /\bQTS\b|\bQUALITY-?TECH\b/i, category: "datacenter" },
  { pattern: /\bEQUINIX\b/i, category: "datacenter" },
  { pattern: /\bCORESITE\b|\bCORE-?SITE\b/i, category: "datacenter" },
  { pattern: /\bCYXTERA\b/i, category: "datacenter" },
  { pattern: /\bCOLOGIX\b/i, category: "datacenter" },
  { pattern: /\bDIGITAL-?REALTY\b|\bDLR-?DC\b/i, category: "datacenter" },
  { pattern: /\bTELEHOUSE\b/i, category: "datacenter" },
  { pattern: /\bINTERXION\b/i, category: "datacenter" },
  { pattern: /\bIRON-?MOUNTAIN\b/i, category: "datacenter" },
  // Cloud-device farms (BrowserStack, Sauce Labs, LambdaTest). Real iOS/
  // Android hardware but the egress is colocation-grade, not consumer
  // residential — merchants can treat as datacenter for risk purposes.
  { pattern: /\bBROWSERSTACK\b/i, category: "datacenter" },
  { pattern: /\bSAUCELABS\b|\bSAUCE-?LABS\b/i, category: "datacenter" },
  { pattern: /\bLAMBDATEST\b/i, category: "datacenter" },

  // ─── VPN backbone / proxy infrastructure
  { pattern: /\bM247\b/i, category: "vpn_proxy" },
  { pattern: /\bLEASEWEB\b/i, category: "vpn_proxy" },
  { pattern: /\bDATAPACKET\b|\bDATACAMP\b|\bCDNEXT\b/i, category: "vpn_proxy" },
  {
    pattern:
      /\bPRIVATE-?INTERNET-?ACCESS\b|\bMULLVAD\b|\bEXPRESSVPN\b|\bSURFSHARK\b|\bPROTONVPN(?:-\d+)?\b|\bWINDSCRIBE\b|\bCASTLEVPN\b|^\s*(?:IVPN|SKYVPN)\s*$/i,
    category: "vpn_proxy",
  },
  { pattern: /\bHIVELOCITY\b|\bHVC-AS\b/i, category: "hosting_proxy" },
  { pattern: /\bSPRIOUS\b|\bAS-?SPRIO\b/i, category: "hosting_proxy" },
  { pattern: /\bBLAZINGSEO\b/i, category: "hosting_proxy" },

  // ─── Privacy relay
  {
    pattern: /\bAPPLE-?(?:ENGINEERING|ICLOUD|RELAY|EGRESS)\b/i,
    category: "privacy_relay",
  },

  // ─── Business / corporate
  {
    pattern: /\bCOMCAST-?BUSINESS\b|\bCHARTER-?BUSINESS\b|\bCOX-?BUSINESS\b/i,
    category: "business",
  },
  {
    pattern: /\bBUSINESS\b|\bCORPORATE\b|\bENTERPRISE\b|\bB2B\b/i,
    category: "business",
  },

  // ─── Security middleboxes
  { pattern: /\bCISCO-?UMBRELLA\b|\bOPENDNS\b/i, category: "security_filter" },
  {
    pattern: /\bZSCALER\b|\bNETSKOPE\b|\bPALO-?ALTO\b/i,
    category: "security_filter",
  },

  // ─── Education / government
  {
    pattern: /\bUNIVERSITY\b|\bCOLLEGE\b|\b\.EDU\b|\bACADEMIC\b/i,
    category: "education",
  },
  {
    pattern: /\bDEPARTMENT-?OF\b|\bMINISTRY-?OF\b|\bGOV(ERNMENT)?\b/i,
    category: "government",
  },
];

/**
 * Run the categorizer against one or more candidate strings (sub-allocation
 * name, entity org name, nameserver hostnames, etc). Returns the first
 * matching category, or null if no rule matched any candidate.
 *
 * Pass multiple candidates from highest-to-lowest specificity — for ARIN
 * the `name` field is authoritative; for LACNIC the `name` is often a
 * numeric handle so callers should also pass entity-org / nameservers.
 */
export function categorize(
  ...candidates: (string | null | undefined)[]
): NetworkCategory | null {
  for (const c of candidates) {
    if (!c) continue;
    for (const rule of RULES) {
      if (rule.pattern.test(c)) return rule.category;
    }
  }
  return null;
}
