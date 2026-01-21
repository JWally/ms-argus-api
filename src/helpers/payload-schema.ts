// src/helpers/payload-schema.ts
// V3 Payload Schema - Clean schema matching the current web payload structure
// Includes JSON Schema for middy validator middleware

/**
 * V3 Payload structure from ms-argus-web
 *
 * Top-level structure:
 * - identifiers: session_id, evercookie_id, public_key
 * - hashes: stable, fuzzy, and named component hashes
 * - device: detailed device fingerprint data (nested objects)
 * - sigint: network intelligence (tlsFingerprint, tcpProbe, stun, faviconCache)
 */

// ==================== TYPESCRIPT TYPES ====================

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

export interface SigintTcpProbe {
  rttMs?: number;
  proxyScore?: number;
  vpnScore?: number;
}

export interface SigintStun {
  localIps?: string[];
  publicIp?: string | null;
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

export interface PayloadSigint {
  tlsFingerprint?: SigintTlsFingerprint;
  tcpProbe?: SigintTcpProbe;
  stun?: SigintStun;
  faviconCache?: SigintFaviconCache;
  timing?: SigintTiming;
  errors?: unknown[];
}

export interface ArgusPayload {
  identifiers: PayloadIdentifiers;
  hashes: PayloadHashes;
  device: PayloadDevice;
  sigint?: PayloadSigint;
}

// ==================== JSON SCHEMA FOR MIDDY VALIDATOR ====================

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
        tlsFingerprint: {
          type: "object",
          additionalProperties: true,
          properties: {
            id: { type: ["string", "null"] },
            ip: { type: ["string", "null"] },
            ja3: { type: ["string", "null"] },
            ja4: { type: ["string", "null"] },
          },
        },
        tcpProbe: {
          type: "object",
          additionalProperties: true,
          properties: {
            rttMs: { type: "number" },
            proxyScore: { type: "number" },
            vpnScore: { type: "number" },
          },
        },
        stun: {
          type: "object",
          additionalProperties: true,
        },
        faviconCache: {
          type: "object",
          additionalProperties: true,
          properties: {
            id: { type: ["string", "null"] },
          },
        },
        timing: {
          type: "object",
          additionalProperties: true,
        },
        errors: {
          type: "array",
        },
      },
    },
  },
} as const;

// ==================== HELPER FUNCTIONS ====================

/**
 * Extract session_id from a validated payload
 */
export function getSessionId(payload: ArgusPayload): string {
  return payload.identifiers.session_id;
}

/**
 * Type guard for ArgusPayload (use after middy validation)
 */
export function isArgusPayload(input: unknown): input is ArgusPayload {
  if (!input || typeof input !== "object") return false;
  const obj = input as Record<string, unknown>;

  if (!obj.identifiers || typeof obj.identifiers !== "object") return false;
  const ids = obj.identifiers as Record<string, unknown>;
  if (typeof ids.session_id !== "string") return false;

  if (!obj.hashes || typeof obj.hashes !== "object") return false;
  const hashes = obj.hashes as Record<string, unknown>;
  if (typeof hashes.stable !== "string") return false;
  if (typeof hashes.fuzzy !== "string") return false;

  if (!obj.device || typeof obj.device !== "object") return false;

  return true;
}

// ==================== SESSION RESPONSE TYPES ====================

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
}

export interface SessionResponse {
  identifiers: SessionResponseIdentifiers;
  analysis: SessionResponseAnalysis;
  hashes: PayloadHashes;
  device: PayloadDevice;
  sigint?: PayloadSigint;
}

// ==================== SESSION RESPONSE JSON SCHEMA ====================

/**
 * JSON Schema for session-get response validation
 *
 * Validates that responses conform to expected structure.
 * Less strict than input validation since this is our own output,
 * but ensures consistency.
 */
export const sessionResponseJsonSchema = {
  type: "object",
  required: ["identifiers", "analysis", "hashes", "device"],
  additionalProperties: true,
  properties: {
    identifiers: {
      type: "object",
      required: ["session_id", "device_id"],
      additionalProperties: true,
      properties: {
        session_id: { type: "string", minLength: 1 },
        device_id: { type: "string", minLength: 1 },
        evercookie_id: { type: "string" },
        public_key: { type: "string" },
      },
    },
    analysis: {
      type: "object",
      required: [
        "status",
        "confidence",
        "match_tier",
        "is_new_device",
        "risk_score",
        "flags",
        "evidence_codes",
      ],
      additionalProperties: true,
      properties: {
        status: {
          type: "string",
          enum: ["pending", "complete", "degraded", "error"],
        },
        confidence: { type: "number", minimum: 0, maximum: 1 },
        match_tier: { type: "number" },
        is_new_device: { type: "boolean" },
        risk_score: { type: "number", minimum: 0 },
        flags: { type: "array", items: { type: "string" } },
        evidence_codes: { type: "array", items: { type: "string" } },
        anomalies: {
          type: "array",
          items: {
            type: "object",
            required: ["type", "code", "severity"],
            additionalProperties: true,
            properties: {
              type: { type: "string" },
              code: { type: "string" },
              severity: { type: "string" },
            },
          },
        },
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
    },
    sigint: {
      type: "object",
      additionalProperties: true,
    },
  },
} as const;

/**
 * Validate a session response object
 * Throws if invalid
 */
export function validateSessionResponse(response: unknown): SessionResponse {
  if (!response || typeof response !== "object") {
    throw new Error("Invalid response: not an object");
  }

  const obj = response as Record<string, unknown>;

  // Check identifiers
  if (!obj.identifiers || typeof obj.identifiers !== "object") {
    throw new Error("Invalid response: missing identifiers");
  }
  const ids = obj.identifiers as Record<string, unknown>;
  if (!ids.session_id || typeof ids.session_id !== "string") {
    throw new Error("Invalid response: missing session_id");
  }
  if (!ids.device_id || typeof ids.device_id !== "string") {
    throw new Error("Invalid response: missing device_id");
  }

  // Check analysis
  if (!obj.analysis || typeof obj.analysis !== "object") {
    throw new Error("Invalid response: missing analysis");
  }
  const analysis = obj.analysis as Record<string, unknown>;
  if (typeof analysis.status !== "string") {
    throw new Error("Invalid response: missing analysis.status");
  }
  if (typeof analysis.confidence !== "number") {
    throw new Error("Invalid response: missing analysis.confidence");
  }

  // Check hashes
  if (!obj.hashes || typeof obj.hashes !== "object") {
    throw new Error("Invalid response: missing hashes");
  }
  const hashes = obj.hashes as Record<string, unknown>;
  if (!hashes.stable || typeof hashes.stable !== "string") {
    throw new Error("Invalid response: missing hashes.stable");
  }
  if (!hashes.fuzzy || typeof hashes.fuzzy !== "string") {
    throw new Error("Invalid response: missing hashes.fuzzy");
  }

  // Check device
  if (!obj.device || typeof obj.device !== "object") {
    throw new Error("Invalid response: missing device");
  }

  return response as SessionResponse;
}
