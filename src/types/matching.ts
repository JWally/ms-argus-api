/**
 * Matching service types.
 *
 * Core type definitions for the device matching pipeline including
 * evidence codes, session cache values, and match results.
 * @module
 */
import type { Fingerprint } from "./fingerprint";

/**
 * Evidence codes explaining which signals contributed to a match decision.
 *
 * Used for observability, debugging, and support escalations.
 * Each code indicates which matching tier and signal produced the match.
 */
export type EvidenceCode =
  | "EVERCOOKIE_MATCH" // T0.5: Matched on evercookie ID
  | "SIGINT_ID_MATCH" // T0.5: Matched on third-party cookie from sigint
  | "PUBLIC_KEY_MATCH" // T0.5: Matched on ECDSA public key
  | "STABLE_HASH_MATCH" // T1: Matched on stable fingerprint hash
  | "FUZZY_HASH_MATCH" // T1: Matched on fuzzy fingerprint hash
  | "SIMHASH_MATCH" // T1.5: Matched via SimHash LSH (fuzzy_hash Hamming distance)
  | "SESSION_ANCHOR_BUCKET" // Anchor: Matched in IP+UA+Screen with 10min validity
  | "IP_UA_ANCHOR_BUCKET" // Anchor: Matched in IP+UA with 3min validity
  | "VECTOR_SIMILARITY" // T2: Matched via Qdrant vector similarity
  | "HIGH_SIMILARITY" // T2: Vector similarity score >= 0.9
  | "NEW_DEVICE"; // No match found, new device created

/** Anomaly signal exposed in session response. */
export interface SessionAnomalySignal {
  /** Category of anomaly detected */
  type: "CROSS_FIELD" | "NETWORK" | "HARDWARE" | "IDENTITY" | "STATISTICAL";
  /** Specific anomaly code (e.g., "SCREEN_CSS_MISMATCH") */
  code: string;
  /** Severity score from 0.0 (info) to 1.0 (critical) */
  severity: number;
  /** Evidence explaining the anomaly */
  evidence: {
    /** Expected value based on other signals */
    expected: string;
    /** Actual value observed */
    actual: string;
    /** Fields involved in cross-field anomalies */
    fields?: string[];
  };
}

/** Session cache value stored in DynamoDB. */
export interface SessionCacheValue {
  /** Processing status: pending, complete, or degraded */
  status: "pending" | "complete" | "degraded";
  /** Matched device ID (empty string if degraded) */
  device_id: string;
  /** Device risk score (0.0 to 1.0) */
  risk_score: number;
  /** Match confidence (0.0 to 1.0) */
  confidence: number;
  /** Matching tier that produced the result (-1 if failed) */
  match_tier: number;
  /** Timestamp for cache versioning */
  match_version: number;
  /** Idempotency key to detect duplicate requests */
  idempotency_key: string;
  /** Risk flags for the device */
  flags: string[];
  /** Evidence codes showing how match was made */
  evidence_codes: EvidenceCode[];
  /** Anomalies detected during matching */
  anomalies?: SessionAnomalySignal[];
  /** Fuzzy hash comparison info */
  fuzzy_match_info?: FuzzyMatchInfo;
  /** Vector match details for Tier 2 Qdrant matches */
  vector_match_details?: VectorMatchDetails;
  /** Last update timestamp (epoch ms) */
  updated_at: number;
}

/**
 * Sigint data from ms-argus-web (third-party signals)
 * Contains TLS fingerprint, TCP probe, STUN, and favicon cache data
 */
export interface SigintData {
  aws_cf?: {
    /** Third-party cookie ID (the _fpid cookie from id.argus.pw) */
    id?: string;
    /** Unix seconds when the _fpid cookie was originally minted (tamper-evident at CF edge) */
    issuedAt?: number;
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
    /** Unix seconds when this token was minted — used for freshness check */
    ts?: number;
    /** SipHash-2-4 of `id|issuedAt|ip|asn|ts` from the CF edge */
    sig?: string;
    /** Set by API during verification: true if `ts` is outside the ±90s window */
    expired?: boolean;
    /** Set by API during verification: true if token sig missing / mismatched / unverifiable */
    tampered?: boolean;
    /** Set by API: true if the `_fpid` cookie sig failed validation or the cookie was absent */
    cookieTampered?: boolean;
    /** Set by API: true if cookie's uuid/issuedAt matches what's in the token payload */
    cookieMatchesToken?: boolean;
  } | null;
  tcp_probe?: {
    /** TCP round-trip time in milliseconds */
    rttMs?: number;
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
 * Vector match details for Tier 2 Qdrant matches.
 * Exposes similarity scores and candidate distribution for transparency.
 */
export interface VectorMatchDetails {
  /** Raw similarity score from Qdrant (0.0 to 1.0) */
  similarity_score: number;
  /** Total candidates found above threshold */
  candidates_in_range: number;
  /** Score of 2nd best candidate, if exists (for gap analysis) */
  runner_up_score: number | null;
  /** Top N candidate scores for distribution analysis */
  top_scores: number[];
  /** Embedding dimension used */
  embedding_dimension: number;
  /** Primary features that drove this match (highest weighted) */
  primary_match_features: string[];
}

/** Result of device matching. */
export interface MatchResult {
  /** Matched or newly created device ID */
  device_id: string;
  /** Match confidence (0.0 to 1.0) */
  confidence: number;
  /** Matching tier that produced the result */
  match_tier: number;
  /** True if device was just created */
  is_new_device: boolean;
  /** Device risk score (0.0 to 1.0) */
  risk_score: number;
  /** Risk flags for the device */
  flags: string[];
  /** Evidence codes showing how match was made */
  evidence_codes: EvidenceCode[];
  /** Fuzzy hash comparison info */
  fuzzy_match_info?: FuzzyMatchInfo;
  /** Vector match details for Tier 2 Qdrant matches */
  vector_match_details?: VectorMatchDetails;
  /** IP history context for session response */
  ip_history_context?: {
    known_ip: boolean;
    known_asn: boolean;
    unique_ips_24h: number;
    unique_asns_24h: number;
    confidence_adjustment: number;
  };
}

/**
 * Tier 1 index entry.
 *
 * Includes fuzzy_hash for drift detection at match time.
 */
export interface Tier1IndexEntry {
  /** Index key (prefixed hash, e.g., "stable#abc123") */
  hash_key: string;
  /** Device ID this hash maps to */
  device_id: string;
  /** Cached risk score for fast response */
  risk_score?: number;
  /** Cached flags for fast response */
  flags?: string[];
  /** Device's fuzzy_hash at time of index write, for drift comparison */
  fuzzy_hash?: string;
  /** TTL timestamp (epoch seconds) */
  ttl: number;
}
