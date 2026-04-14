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
  new?: boolean;
  ip?: string | null;
  asn?: string | null;
  country?: string | null;
  ja3?: string | null;
  ja4?: string | null;
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
 */
export interface IntegrityResultsData {
  session_id: string;
  tampered: boolean;
  vm_signals: string[];
  vm_hash: string;
  signal_count: number;
  device: Record<string, unknown>;
  meta: Record<string, unknown>;
  sigint: Record<string, string>;
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
      };
      checks: {
        probesConsistent: boolean;
        webrtcMatchesProbes: boolean | null;
      };
      signals: Array<{ code: string; severity: number; evidence: string }>;
    };
  };
  client_ip: string;
  user_agent: string;
  created_at: number;
}
