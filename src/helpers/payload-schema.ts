/**
 * V3 Payload structure from ms-argus-web
 *
 * Top-level structure:
 * - identifiers: session_id, evercookie_id, public_key
 * - hashes: stable, fuzzy, and named component hashes
 * - device: detailed device fingerprint data (nested objects)
 * - sigint: network intelligence (aws_cf, tcp_probe, h2, faviconCache)
 */

export interface PayloadIdentifiers {
  session_id: string;
  evercookie_id?: string;
  public_key?: string;
}

export interface PayloadHashes {
  stable: string;
  fuzzy: string;
  // Named component hashes - allow any string keys
  [key: string]: string | undefined;
}

// Device section contains deeply nested fingerprint data
// Loosely typed since structure is complex and component-specific
export type PayloadDevice = Record<string, Record<string, unknown> | undefined>;

export interface SigintTlsFingerprint {
  id?: string;
  /** Unix seconds when the _fpid cookie was originally minted (tamper-evident at CF edge) */
  issuedAt?: number;
  new?: boolean;
  ip?: string | null;
  asn?: string | null;
  country?: string | null;
  ja3?: string | null;
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
}

// TCP Probe response - web client sends full TcpProbeResponse with nested rtt_fingerprint
export interface SigintTcpProbe {
  // Flat structure (legacy/simplified)
  rttMs?: number;
  // Nested structure (actual web client payload)
  tcp_info?: Record<string, number> | null;
  rtt_fingerprint?: {
    tcp_rtt_us?: number;
    tls_handshake_us?: number;
    http_first_byte_us?: number;
    total_connection_us?: number;
    snd_mss?: number;
    rcv_mss?: number;
    pmtu?: number;
    tls_to_tcp_ratio?: number;
    total_to_tcp_ratio?: number;
  } | null;
  tls_signals?: {
    has_grease: boolean;
    cipher_count: number;
  } | null;
  /** JA4 TLS fingerprint computed from ClientHello at the probe server */
  ja4?: string;
  http2_fingerprint?: Record<string, unknown> | null;
  client_hints?: Record<string, string> | null;
  user_agent?: string;
  client_ip?: string;
  domain?: string;
}

export interface SigintStun {
  // API schema naming (legacy)
  localIps?: string[];
  publicIp?: string | null;
  // Web client naming
  localIp?: string | null;
  reflexiveIp?: string | null;
  // Common fields
  natDetected?: boolean;
  stunServer?: string;
}

export interface SigintFaviconCache {
  id?: string;
  bits?: string;
  created?: string;
  lastSeen?: string;
  method?: string;
}

export interface SigintTiming {
  tlsFingerprintMs?: number;
  tcpProbeMs?: number;
  stunMs?: number;
  faviconCacheMs?: number;
  totalMs?: number;
}

export interface SigintH2Probe {
  settings_order?: string[];
  header_table_size?: number;
  enable_push?: number;
  max_concurrent_streams?: number;
  initial_window_size?: number;
  max_frame_size?: number;
  max_header_list_size?: number;
  window_update?: number;
  priority_frames?: Array<{
    stream_id: number;
    exclusive: boolean;
    depends_on: number;
    weight: number;
  }>;
  pseudo_header_order?: string;
  header_order?: string[];
  fingerprint?: string;
  protocol?: string;
  ja4?: string;
  tls_signals?: {
    has_grease: boolean;
    cipher_count: number;
  };
  user_agent?: string;
}

export interface PayloadSigint {
  aws_cf?: SigintTlsFingerprint;
  tcp_probe?: SigintTcpProbe;
  h2?: SigintH2Probe | null;
  faviconCache?: SigintFaviconCache;
  timing?: SigintTiming;
  errors?: unknown[];
}

export interface ArgusPayload {
  identifiers: PayloadIdentifiers;
  hashes: PayloadHashes;
  device: PayloadDevice;
  /**
   * Client-side stable device identity. Pubkey is the SPKI-base64 of a
   * persistent non-extractable ECDSA P-256 keypair (generated once, stored in
   * IndexedDB). Sig is ECDSA over `xor(sigintH2Token, K)` — proves possession
   * of the private key AND a fresh h2-probe call in the last 90s.
   */
  device_identity?: {
    pubkey: string;
    sig: string;
  };
  sigint?: PayloadSigint;
  /** HMAC-signed token from TCP probe — redeemed by matching-worker for full probe data */
  sigintTcpToken?: string;
  /** HMAC-signed token from H2 probe — redeemed by matching-worker for full probe data */
  sigintH2Token?: string;
  /** Full TLS fingerprint JSON string from VM sigint fetch */
  sigintTls?: string;
}

/**
 * JSON Schema for payload validation via middy validator
 *
 * Philosophy: Validate the critical structural parts but allow flexibility
 * in the deeply nested device data. We want to catch:
 * - Missing required fields (identifiers, hashes, device)
 * - Wrong types for critical fields (session_id, stable, fuzzy)
 * - Completely malformed payloads
 *
 * But NOT be overly strict about:
 * - Extra fields (additionalProperties: true)
 * - Deep device object structure (varies by component)
 */
export const payloadJsonSchema = {
  type: "object",
  required: ["identifiers", "hashes", "device"],
  additionalProperties: true,
  properties: {
    identifiers: {
      type: "object",
      required: ["session_id"],
      additionalProperties: true,
      properties: {
        session_id: { type: "string", minLength: 1 },
        evercookie_id: { type: "string" },
        public_key: { type: "string" },
      },
    },
    hashes: {
      type: "object",
      required: ["stable", "fuzzy"],
      additionalProperties: { type: "string" },
      properties: {
        stable: { type: "string", minLength: 1 },
        fuzzy: { type: "string", minLength: 1 },
      },
    },
    device: {
      type: "object",
      additionalProperties: true,
      // Device contains nested component objects - don't be strict here
    },
    device_identity: {
      type: ["object", "null"],
      additionalProperties: false,
      required: ["pubkey", "sig"],
      properties: {
        pubkey: { type: "string", minLength: 1 },
        sig: { type: "string", minLength: 1 },
      },
    },
    sigint: {
      type: "object",
      additionalProperties: true,
      properties: {
        aws_cf: {
          type: ["object", "null"],
          additionalProperties: true,
          properties: {
            id: { type: ["string", "null"] },
            ip: { type: ["string", "null"] },
            ja3: { type: ["string", "null"] },
            ja4: { type: ["string", "null"] },
          },
        },
        tcp_probe: {
          type: ["object", "null"],
          additionalProperties: true,
          properties: {
            rttMs: { type: "number" },
          },
        },
        faviconCache: {
          type: ["object", "null"],
          additionalProperties: true,
          properties: {
            id: { type: ["string", "null"] },
          },
        },
        h2: {
          type: ["object", "null"],
          additionalProperties: true,
        },
        timing: {
          type: ["object", "null"],
          additionalProperties: true,
        },
        errors: {
          type: "array",
        },
      },
    },
  },
} as const;

/**
 * Extract session_id from a validated payload
 * @param payload - Validated Argus payload
 * @returns Session ID string
 */
export function getSessionId(payload: ArgusPayload): string {
  return payload.identifiers.session_id;
}

/**
 * Check if object has valid identifiers section
 * @param obj - Object to check
 * @returns True if identifiers section is valid
 */
function hasValidIdentifiers(obj: Record<string, unknown>): boolean {
  if (!obj.identifiers || typeof obj.identifiers !== "object") return false;
  const ids = obj.identifiers as Record<string, unknown>;
  return typeof ids.session_id === "string";
}

/**
 * Check if object has valid hashes section
 * @param obj - Object to check
 * @returns True if hashes section is valid
 */
function hasValidHashes(obj: Record<string, unknown>): boolean {
  if (!obj.hashes || typeof obj.hashes !== "object") return false;
  const hashes = obj.hashes as Record<string, unknown>;
  return typeof hashes.stable === "string" && typeof hashes.fuzzy === "string";
}

/**
 * Type guard for ArgusPayload (use after middy validation)
 * @param input - Unknown input to validate
 * @returns True if input is a valid ArgusPayload
 */
export function isArgusPayload(input: unknown): input is ArgusPayload {
  if (!input || typeof input !== "object") return false;
  const obj = input as Record<string, unknown>;
  return (
    hasValidIdentifiers(obj) &&
    hasValidHashes(obj) &&
    !!obj.device &&
    typeof obj.device === "object"
  );
}

export interface SessionResponseIdentifiers {
  session_id: string;
  device_id: string;
  evercookie_id?: string;
  public_key?: string;
}

export interface SessionResponseAnalysis {
  status: "pending" | "complete" | "degraded" | "error";
  confidence: number;
  match_tier: number;
  is_new_device: boolean;
  risk_score: number;
  flags: string[];
  evidence_codes: string[];
  anomalies?: Array<{
    type: string;
    code: string;
    severity: string;
    evidence?: Record<string, unknown>;
  }>;
  simhash_details?: Record<string, unknown>;
  fuzzy_match_info?: Record<string, unknown>;
  vector_match_details?: Record<string, unknown>;
}

export interface SessionResponse {
  identifiers: SessionResponseIdentifiers;
  analysis: SessionResponseAnalysis;
  hashes: PayloadHashes;
  device: PayloadDevice;
  sigint?: PayloadSigint;
}

/**
 * Require a field of a specific type in an object
 * @param obj - Object to check
 * @param field - Field name to require
 * @param type - Expected type ("string", "number", "object")
 * @param path - Optional path for error messages
 * @throws Error if field is missing or wrong type
 */
function requireField(
  obj: Record<string, unknown>,
  field: string,
  type: string,
  path?: string,
): void {
  const val = obj[field];
  if (
    type === "object" ? !val || typeof val !== "object" : typeof val !== type
  ) {
    throw new Error(`Invalid response: missing ${path ?? field}`);
  }
}

/**
 * Validate a session response object
 * @param response - Unknown response to validate
 * @returns Validated SessionResponse
 * @throws Error if response is invalid
 */
export function validateSessionResponse(response: unknown): SessionResponse {
  if (!response || typeof response !== "object") {
    throw new Error("Invalid response: not an object");
  }
  const obj = response as Record<string, unknown>;

  requireField(obj, "identifiers", "object");
  const ids = obj.identifiers as Record<string, unknown>;
  requireField(ids, "session_id", "string");
  requireField(ids, "device_id", "string");

  requireField(obj, "analysis", "object");
  const analysis = obj.analysis as Record<string, unknown>;
  requireField(analysis, "status", "string", "analysis.status");
  requireField(analysis, "confidence", "number", "analysis.confidence");

  requireField(obj, "hashes", "object");
  const hashes = obj.hashes as Record<string, unknown>;
  requireField(hashes, "stable", "string", "hashes.stable");
  requireField(hashes, "fuzzy", "string", "hashes.fuzzy");

  requireField(obj, "device", "object");
  return response as SessionResponse;
}

/**
 * Integrity results data shape stored in DynamoDB (IntegrityResults table).
 *
 * Lives here rather than next to the session-get handler because both
 * handlers and helpers (notably merchant-projection) need this type.
 * Putting it in a handler module created a helper→handler import that
 * violated the layering rule and produced a circular dependency.
 *
 * `tampered` / `vm_signals` / `vm_hash` / `signal_count` were removed
 * with the harden-jsvm cleanup — the client stopped generating them
 * (vm:* signal strip on 2026-04-13) and nothing on the server side ever
 * read them: stored, never queried. Existing DDB rows still carry the
 * fields; new writes omit them.
 */
export interface IntegrityResultsData {
  session_id: string;
  device: Record<string, unknown>;
  meta: Record<string, unknown>;
  sigint: Record<string, string>;
  /**
   * Device-identity verification outcome. Present when the client sent a
   * `device_identity` block in the payload (pubkey + sig over xor'd h2-token).
   * Absent on legacy bundles pre-migration.
   */
  identification?: {
    pubkey: string;
    verified: boolean;
    reason: string | null;
    sig_present: boolean;
  };
  analysis: {
    network: {
      /** Noisy-OR combined proxy score [0,1] — merchant-facing. */
      proxy_score: number;
      /** Continuous RTT-ratio-derived score [0,1] — internal. */
      proxy_component: number;
      /** Continuous MSS-derived score [0,1] — internal. */
      vpn_component: number;
      signals: Array<{ code: string; severity: number; evidence: unknown }>;
    };
    worker: {
      lied: boolean;
      divergences: Array<{
        field: string;
        main: unknown;
        web: unknown;
        shared: unknown;
      }>;
      signals: Array<{ code: string; severity: number; evidence: string }>;
    };
    timezone: {
      lied: boolean;
      checks: {
        offsetMatchesComputed: boolean;
        locationMatchesCfTimezone: boolean | null;
        offsetMatchesWorker: boolean | null;
        clientReportedLie: boolean;
      };
      cfTimezone: string | null;
      clientTimezone: string | null;
      signals: Array<{ code: string; severity: number; evidence: string }>;
    };
    ip: {
      lied: boolean;
      ips: {
        api: string | null;
        tls: string | null;
        tcp: string | null;
        webrtc: string | null;
      };
      asn: {
        number: string | null;
        category: string | null;
        org: string | null;
        /** Broader consumer-network classification from IPtoASN dataset. */
        network_class?: string | null;
      };
      /**
       * Network-derived stable user ID. Computed during ingestion by
       * analyzeIpConsistency and stored on the integrity record so the
       * merchant-projection layer can read it without re-importing services.
       */
      network_id?: string | null;
      network_id_source?: "category_residential" | "asn_fallback" | "none";
      checks: {
        probesConsistent: boolean;
        webrtcMatchesProbes: boolean | null;
      };
      /** Network-trust score 0.0–1.0. See analyzeIpConsistency. */
      integrity: number;
      /** Representative client IP. Null at integrity < 0.5. */
      ip: string | null;
      signals: Array<{ code: string; severity: number; evidence: string }>;
    };
    /** Locale / geo cross-verification. See analyzeLocaleGeo. */
    locale_geo?: {
      signals: Array<{ code: string; severity: number; evidence: string }>;
      hasLocationMismatch: boolean;
      hasLocaleTamper: boolean;
    };
    /** Client-hints vs UA cross-verification. See analyzeClientHintsUa. */
    client_hints_ua?: {
      signals: Array<{ code: string; severity: number; evidence: string }>;
      hasStrongMismatch: boolean;
    };
    /** Proxy-detection waterfall verdict. See classifyProxy. */
    proxy_waterfall?: {
      /** Internal verdict label — stored, not merchant-facing. */
      verdict: "SAFE" | "HIGH" | "KILL";
      /** Rule # that fired (0-8) — stored, not merchant-facing. */
      rule: number;
      /** Short reason code — stored, not merchant-facing. */
      reason: string;
      /** Merchant-facing threat score in [0, 100]. */
      threat_score: number;
      shared_prefix: number | null;
      ratio: number | null;
    };
  };
  client_ip: string;
  user_agent: string;
  /**
   * Curated request headers captured at ingestion — see CAPTURED_REQUEST_HEADER_NAMES
   * in handlers/ingestion/base-handler.ts. Cookie values are *not* stored;
   * only names, in `cookie_names`.
   */
  request_headers?: {
    headers: Record<string, string>;
    cookie_names: string[];
  };
  created_at: number;
}
