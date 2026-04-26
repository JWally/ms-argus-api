/**
 * IP classification dataset builder.
 *
 * Pulls the public IPtoASN BGP-derived dataset, runs each ASN's organization
 * name through a regex categorizer, applies manual overrides for ASNs whose
 * names don't pattern-match cleanly, and uploads the resulting
 * `asn-categories.json.gz` to the IP_CLASS_BUCKET.
 *
 * Runtime Lambdas (matching workers, ingestion handlers) consume the file
 * via S3 GetObject on cold start to map an ASN number → category bucket
 * (mobile / residential / datacenter / vpn_proxy / etc.) without a network
 * call per request.
 *
 * Cadence: weekly EventBridge schedule + on-deploy custom-resource invoke
 * so the bucket is seeded the first time the stack is created.
 */
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { gunzipSync, gzipSync } from "node:zlib";
import { ASN_OVERRIDES } from "../services/network/asn-overrides";

interface CategoryRule {
  pattern: RegExp;
  category: string;
}

// Order matters — first match wins. Mobile patterns precede residential so
// "MOBILE BROADBAND" is classified as mobile rather than residential.
const RULES: CategoryRule[] = [
  // ─── Mobile
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
  {
    pattern: /\bRESIDENTIAL\b|\bRES-CON\b|\bHOME-NETWORK\b/i,
    category: "residential",
  },
  {
    pattern: /\bSBCIS\b|\bSBC-INTERNET\b|\bUVERSE\b|\bU-VERSE\b/i,
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
    pattern: /\bBT-?(?:UK|NET|GROUP)\b|\bBTNET\b|\bBT-CENTRAL\b/i,
    category: "residential",
  },
  {
    pattern: /\bPLUSNET\b|\bTALKTALK\b|\bSKY-?BROADBAND\b/i,
    category: "residential",
  },
  {
    pattern: /\bORANGE\b|\bFREE-AS\b|\bSFR-AS\b|\bBOUYGUES-?TELECOM\b/i,
    category: "residential",
  },
  {
    pattern: /\bDEUTSCHE-?TELEKOM\b|\bVODAFONE-?(?:DE|UK)\b(?!.*MOBILE)/i,
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

  // ─── VPN backbone / proxy infrastructure
  { pattern: /\bM247\b/i, category: "vpn_proxy" },
  { pattern: /\bLEASEWEB\b/i, category: "vpn_proxy" },
  { pattern: /\bDATAPACKET\b|\bDATACAMP\b|\bCDNEXT\b/i, category: "vpn_proxy" },
  {
    pattern:
      /\bPRIVATE-?INTERNET-?ACCESS\b|\bMULLVAD\b|\bEXPRESSVPN\b|\bSURFSHARK\b/i,
    category: "vpn_proxy",
  },
  { pattern: /\bHIVELOCITY\b|\bHVC-AS\b/i, category: "hosting_proxy" },
  { pattern: /\bSPRIOUS\b|\bAS-?SPRIO\b/i, category: "hosting_proxy" },

  // ─── Privacy relay
  {
    pattern: /\bAPPLE-?ENGINEERING\b|\bAPPLE-?ICLOUD\b/i,
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

const IPTOASN_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz";

function classify(orgName: string): string | null {
  if (!orgName) return null;
  for (const rule of RULES) {
    if (rule.pattern.test(orgName)) return rule.category;
  }
  return null;
}

async function fetchAndDecompress(url: string): Promise<string> {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(60_000),
    headers: { "user-agent": "ms-argus-api ip-class-builder" },
  });
  if (!res.ok) throw new Error(`fetch failed: ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  return gunzipSync(buf).toString("utf-8");
}

interface BuildResult {
  asnsTotal: number;
  asnsClassified: number;
  bytesUploaded: number;
  bucket: string;
  key: string;
}

function parseAsnTable(tsv: string): Map<number, string> {
  const asnToOrg = new Map<number, string>();
  for (const line of tsv.split("\n")) {
    const parts = line.split("\t");
    if (parts.length < 5) continue;
    const asn = Number(parts[2]);
    if (!Number.isFinite(asn) || asn === 0) continue;
    const org = parts[4];
    const existing = asnToOrg.get(asn) ?? "";
    if (org.length > existing.length) asnToOrg.set(asn, org);
  }
  return asnToOrg;
}

function buildClassificationDict(
  asnToOrg: Map<number, string>,
): Record<string, string> {
  const asns: Record<string, string> = {};
  for (const [asn, org] of asnToOrg) {
    const cat = classify(org);
    if (cat) asns[String(asn)] = cat;
  }
  for (const [asn, cat] of Object.entries(ASN_OVERRIDES)) asns[asn] = cat;
  return asns;
}

export async function handler(): Promise<BuildResult> {
  const bucket = process.env.IP_CLASS_BUCKET;
  const key = process.env.IP_CLASS_KEY ?? "asn-categories.json.gz";
  if (!bucket) throw new Error("IP_CLASS_BUCKET env var is required");

  const tsv = await fetchAndDecompress(IPTOASN_URL);
  const asnToOrg = parseAsnTable(tsv);
  const asns = buildClassificationDict(asnToOrg);

  const payload = {
    generated_at: new Date().toISOString(),
    source: IPTOASN_URL,
    asns_total: asnToOrg.size,
    asns_classified: Object.keys(asns).length,
    asns,
  };
  const gz = gzipSync(Buffer.from(JSON.stringify(payload)), { level: 9 });

  const s3 = new S3Client({});
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: gz,
      ContentEncoding: "gzip",
      ContentType: "application/json",
      CacheControl: "max-age=86400",
    }),
  );

  return {
    asnsTotal: asnToOrg.size,
    asnsClassified: Object.keys(asns).length,
    bytesUploaded: gz.length,
    bucket,
    key,
  };
}
