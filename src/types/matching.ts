import type { Fingerprint } from "./fingerprint";

/**
 * Evidence codes explaining which signals contributed to a match decision.
 * Used for observability, debugging, and support escalations.
 */
export type EvidenceCode =
  | "EVERCOOKIE_MATCH" // T0.5: Matched on evercookie ID
  | "SIGINT_ID_MATCH" // T0.5: Matched on third-party cookie from sigint
  | "PUBLIC_KEY_MATCH" // T0.5: Matched on ECDSA public key
  | "STABLE_HASH_MATCH" // T1: Matched on stable fingerprint hash
  | "FUZZY_HASH_MATCH" // T1: Matched on fuzzy fingerprint hash
  | "SIMHASH_MATCH" // T1.5: Matched via SimHash LSH (fuzzy_hash Hamming distance)
  | "IP_JA4_BUCKET" // T2: Matched in IP+JA4 bucket
  | "GPU_SCREEN_TZ_BUCKET" // T2: Matched in GPU+Screen+Timezone bucket
  | "AUDIO_CANVAS_BUCKET" // T2: Matched in Audio+Canvas bucket
  | "MATHS_WINDOW_BUCKET" // T2: Matched in Maths+WindowFeatures bucket
  | "HTML_CSS_BUCKET" // T2: Matched in HtmlElement+CSS bucket
  | "WEBGL_STRUCT_BUCKET" // T2: Matched in WebGL+Extensions+SVG bucket
  | "SESSION_ANCHOR_BUCKET" // T2: Matched in IP+UA+Screen with 10min validity
  | "IP_UA_ANCHOR_BUCKET" // T2: Matched in IP+UA with 3min validity
  | "NEW_DEVICE"; // No match found, new device created

/**
 * Anomaly signal exposed in session response
 */
export interface SessionAnomalySignal {
  type: "CROSS_FIELD" | "NETWORK" | "HARDWARE" | "IDENTITY";
  code: string;
  severity: number;
  evidence: {
    expected: string;
    actual: string;
    fields?: string[];
  };
}

/**
 * Session cache value stored in DynamoDB
 */
export interface SessionCacheValue {
  status: "pending" | "complete" | "degraded";
  device_id: string;
  risk_score: number;
  confidence: number;
  match_tier: number;
  match_version: number;
  idempotency_key: string;
  flags: string[];
  evidence_codes: EvidenceCode[];
  anomalies?: SessionAnomalySignal[];
  simhash_details?: SimHashDetails;
  fuzzy_match_info?: FuzzyMatchInfo;
  updated_at: number;
}

/**
 * Sigint data from ms-argus-web (third-party signals)
 * Contains TLS fingerprint, TCP probe, STUN, and favicon cache data
 */
export interface SigintData {
  tlsFingerprint?: {
    /** Third-party cookie ID (the _fpid cookie from id.argus.pw) */
    id?: string;
    /** Whether this is a new visitor (cookie just created) */
    new?: boolean;
    /** Client IP as seen by CloudFront edge */
    ip?: string | null;
    /** ASN of client IP */
    asn?: string | null;
    /** Country code */
    country?: string | null;
    /** JA3 TLS fingerprint */
    ja3?: string | null;
    /** JA4 TLS fingerprint */
    ja4?: string | null;
  } | null;
  tcpProbe?: {
    /** TCP round-trip time in milliseconds */
    rttMs?: number;
    /** Proxy likelihood score 0-1 */
    proxyScore?: number;
    /** VPN likelihood score 0-1 */
    vpnScore?: number;
  } | null;
  stun?: {
    /** Local IP addresses from WebRTC */
    localIps?: string[];
    /** Public IP address */
    publicIp?: string | null;
  } | null;
  faviconCache?: {
    /** Persistent device ID via favicon cache timing */
    deviceId?: string | null;
  } | null;
}

/**
 * Fingerprint payload from SQS (sent by Go ingestion handler)
 */
export interface FingerprintPayload {
  session_id: string;
  fingerprint: Fingerprint;
  /** Sigint data from ms-argus-web */
  sigint?: SigintData;
  tcp_blob?: string;
  tls_blob?: string;
  headers: Record<string, string>;
  timestamp: number;
}

/**
 * SimHash match details for debugging and analytics.
 * Exposed when a match is made via Tier 1.5 SimHash LSH.
 */
export interface SimHashDetails {
  /** The incoming fingerprint's fuzzy_hash */
  incoming_hash: string;
  /** The matched device's fuzzy_hash */
  matched_hash: string;
  /** Number of bits different (0-64) */
  hamming_distance: number;
  /** Similarity score (1 - distance/64), range 0-1 */
  similarity: number;
  /** Number of LSH bands that matched (2-4) */
  bands_matched: number;
}

/**
 * Fuzzy hash comparison info for all match tiers.
 * Shows how much the incoming fingerprint has drifted from the stored profile.
 * Computed at Tier 0.5, 1, and 1.5 where we have the stored fuzzy_hash available.
 */
export interface FuzzyMatchInfo {
  /** The incoming fingerprint's fuzzy_hash */
  incoming_hash: string;
  /** The matched device's stored fuzzy_hash */
  stored_hash: string;
  /** Number of bits different (0-64), -1 if comparison not possible */
  hamming_distance: number;
  /** Similarity score (1 - distance/64), range 0-1 */
  similarity: number;
}

/**
 * Result of device matching
 */
export interface MatchResult {
  device_id: string;
  confidence: number;
  match_tier: number;
  is_new_device: boolean;
  risk_score: number;
  flags: string[];
  evidence_codes: EvidenceCode[];
  simhash_details?: SimHashDetails;
  fuzzy_match_info?: FuzzyMatchInfo;
}

/**
 * Tier 1 index entry.
 * Includes fuzzy_hash for drift detection at match time.
 */
export interface Tier1IndexEntry {
  hash_key: string;
  device_id: string;
  risk_score?: number;
  flags?: string[];
  /** Device's fuzzy_hash at time of index write, for drift comparison */
  fuzzy_hash?: string;
  ttl: number;
}

/**
 * Tier 2 bucket entry
 */
export interface Tier2BucketEntry {
  bucket_key: string;
  device_ids: string[];
  ttl: number;
}
