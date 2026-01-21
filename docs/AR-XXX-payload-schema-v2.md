# AR-XXX: Payload Schema v2

## Overview

Restructure the fingerprint payload and API response into a clean, organized schema with clear separation of concerns.

## Current Problems

1. **Duplication**: `loose` and `stable` contain overlapping data
2. **Scattered identifiers**: `session_id`, `device_id`, `evercookie_id` spread across different levels
3. **Mixed concerns**: Fingerprint data, network signals, and analysis results intermingled
4. **Inconsistent naming**: `tcp_blob`, `tls_blob`, `sigint`, `fingerprint` at various levels

## Proposed Schema

```typescript
interface ArgusPayload {
  identifiers: Identifiers;
  device: DeviceFingerprint;
  sigint: SignalIntelligence;
  analysis?: Analysis; // Populated by backend
}
```

### Identifiers

All persistent and session-level identity signals.

```typescript
interface Identifiers {
  // Session
  session_id: string;

  // Device (assigned by backend)
  device_id?: string;

  // Client-side persistent identifiers
  evercookie_id?: string;
  public_key?: string; // ECDSA crypto identity
  favicon_cache_id?: string; // Favicon cache fingerprint
}
```

### Device

All browser/device fingerprint data collected by the web library.

```typescript
interface DeviceFingerprint {
  // Computed hashes (for matching)
  hashes: {
    stable: string; // Deterministic hash for exact matching
    fuzzy: string; // SimHash for similarity matching
    canvas: string;
    webgl: string;
    audio: string;
    fonts?: string;
  };

  // Navigator/Browser
  navigator: {
    user_agent: string;
    platform: string;
    language: string;
    languages: string[];
    hardware_concurrency: number;
    device_memory?: number;
    max_touch_points: number;
    vendor: string;
    do_not_track?: boolean;
    pdf_viewer_enabled?: boolean;
  };

  // Screen
  screen: {
    width: number;
    height: number;
    avail_width: number;
    avail_height: number;
    color_depth: number;
    pixel_ratio: number;
    orientation?: string;
  };

  // GPU/WebGL
  gpu: {
    renderer: string;
    vendor: string;
    webgl_version?: string;
    shading_language_version?: string;
    extensions?: string[];
    parameters?: Record<string, unknown>;
  };

  // Canvas fingerprint data
  canvas: {
    geometry?: string;
    text?: string;
    emoji?: string;
  };

  // Audio fingerprint
  audio: {
    context_hash?: string;
    oscillator_hash?: string;
    dynamics_compressor_hash?: string;
  };

  // Math fingerprint (browser-specific math quirks)
  maths?: Record<string, unknown>;

  // Fonts
  fonts?: {
    detected: string[];
    count: number;
  };

  // Timezone
  timezone: {
    offset: number;
    name: string; // e.g., "America/Chicago"
  };

  // Workers (scope consistency checks)
  workers?: {
    main: WorkerScope;
    web?: WorkerScope;
    shared?: WorkerScope;
    service?: WorkerScope | "unavailable";
  };

  // Feature detection
  features?: {
    webgl: boolean;
    webgl2: boolean;
    canvas: boolean;
    audio_context: boolean;
    web_rtc: boolean;
    service_worker: boolean;
    web_assembly: boolean;
  };

  // Bot detection signals
  bot_signals?: {
    is_headless: boolean;
    has_automation: boolean;
    webdriver: boolean;
    phantom: boolean;
    nightmare: boolean;
    selenium: boolean;
    puppeteer_extra?: boolean;
  };

  // Timing/Performance
  timing?: {
    collection_ms: number;
    canvas_ms?: number;
    audio_ms?: number;
    webgl_ms?: number;
  };

  // Raw data (optional, for debugging/analysis)
  raw?: Record<string, unknown>;
}

interface WorkerScope {
  hardware_concurrency: number;
  device_memory?: number;
  language: string;
  languages: string;
  platform: string;
  user_agent: string;
  timezone: string;
}
```

### SignalIntelligence (sigint)

Server-side collected network signals.

```typescript
interface SignalIntelligence {
  // IP information
  ip: {
    address: string;
    version: 4 | 6;
    asn?: number;
    org?: string;
    country?: string;
    city?: string;
    is_proxy?: boolean;
    is_vpn?: boolean;
    is_tor?: boolean;
    is_datacenter?: boolean;
  };

  // TLS fingerprint
  tls: {
    ja3?: string;
    ja4?: string;
    version?: string;
    cipher_suites?: string[];
    extensions?: string[];
  };

  // TCP fingerprint
  tcp: {
    ttl?: number;
    window_size?: number;
    mss?: number;
    os_guess?: string;
  };

  // HTTP headers
  headers: {
    user_agent?: string;
    accept_language?: string;
    accept_encoding?: string;
    accept?: string;
    connection?: string;
    sec_ch_ua?: string;
    sec_ch_ua_platform?: string;
    sec_ch_ua_mobile?: string;
  };

  // WebRTC (if collected via STUN)
  webrtc?: {
    local_ip?: string;
    public_ip?: string;
    nat_detected?: boolean;
  };
}
```

### Analysis

Backend-computed analysis results.

```typescript
interface Analysis {
  // Match status
  status: "pending" | "complete" | "degraded";

  // Confidence and matching
  confidence: number; // 0-1
  match_tier: number; // 0.5, 1, 1.5, 2
  risk_score: number; // 0-1

  // Evidence
  evidence_codes: EvidenceCode[];
  flags: string[];

  // Anomaly detection
  anomalies?: Anomaly[];

  // Match details (for debugging/transparency)
  match_details?: {
    fuzzy_match_info?: {
      incoming_hash: string;
      stored_hash: string;
      hamming_distance: number;
      similarity: number;
    };
    simhash_details?: {
      incoming_hash: string;
      matched_hash: string;
      hamming_distance: number;
      similarity: number;
      bands_matched: number;
    };
  };

  // Timing
  processing_ms?: number;
}

type EvidenceCode =
  | "EVERCOOKIE_MATCH"
  | "PUBLIC_KEY_MATCH"
  | "STABLE_HASH_MATCH"
  | "FUZZY_HASH_MATCH"
  | "SIMHASH_MATCH"
  | "IP_JA4_BUCKET"
  | "GPU_SCREEN_TZ_BUCKET"
  | "AUDIO_CANVAS_BUCKET"
  | "NEW_DEVICE";

interface Anomaly {
  type: "CROSS_FIELD" | "NETWORK" | "HARDWARE" | "IDENTITY";
  code: string;
  severity: number;
  evidence: {
    expected: string;
    actual: string;
    fields?: string[];
  };
}
```

## API Endpoints

### POST /v1/collect

**Request** (from web library):

```json
{
  "identifiers": {
    "session_id": "sess_abc123",
    "evercookie_id": "ec_xyz",
    "public_key": "-----BEGIN PUBLIC KEY-----..."
  },
  "device": {
    "hashes": { ... },
    "navigator": { ... },
    "screen": { ... },
    ...
  }
}
```

**Response**: `204 No Content`

Server adds `sigint` from request context (IP, headers, TLS).

### GET /v1/session/{session_id}

**Response**:

```json
{
  "identifiers": {
    "session_id": "sess_abc123",
    "device_id": "dev_01KFEPB3T8SS10FQF0B818HDS4",
    "evercookie_id": "ec_xyz",
    "public_key": "-----BEGIN PUBLIC KEY-----..."
  },
  "device": {
    "hashes": { ... },
    "navigator": { ... },
    ...
  },
  "sigint": {
    "ip": { ... },
    "tls": { ... },
    "headers": { ... }
  },
  "analysis": {
    "status": "complete",
    "confidence": 0.95,
    "match_tier": 1,
    "risk_score": 0.3,
    "flags": ["returning_user"],
    "evidence_codes": ["STABLE_HASH_MATCH"],
    "anomalies": []
  }
}
```

## Migration Strategy

### Phase 1: Backend Support (ms-argus-api)

1. Add v2 schema types
2. Update ingestion to accept both v1 and v2 formats
3. Normalize v1 → v2 internally
4. Update session-get to return v2 format
5. Update matching logic to use v2 paths

### Phase 2: Web Library (ms-argus-web)

1. Refactor fingerprint collection to v2 structure
2. Add `hashes` computation
3. Update API client to send v2 format
4. Deprecate v1 format

### Phase 3: Demo & Clients

1. Update demo site to display v2 structure
2. Update any external integrations
3. Remove v1 support after migration period

## File Changes

### ms-argus-api

- `src/types/payload-v2.ts` - New schema types
- `src/helpers/normalize-payload.ts` - v1 → v2 normalizer
- `src/handlers/ingestion.ts` - Accept v2, normalize v1
- `src/handlers/session-get.ts` - Return v2 format
- `src/services/matching/` - Use v2 internally

### ms-argus-web

- `src/types/` - v2 schema types
- `src/collectors/` - Refactor to v2 structure
- `src/api/` - Send v2 format

### ms-argus-bots

- Update result parsing for v2 format

### ms-argus-automation

- Update test factories and assertions for v2

## Open Questions

1. Should we version the API (`/v2/collect`) or handle via content negotiation?
2. How long to support v1 format during migration?
3. Should `device.raw` include the full CreepJS output for debugging, or omit entirely?

## Appendix: Field Mapping (v1 → v2)

| v1 Path                         | v2 Path                     |
| ------------------------------- | --------------------------- |
| `session_id`                    | `identifiers.session_id`    |
| `fingerprint.evercookie_id`     | `identifiers.evercookie_id` |
| `fingerprint.public_key`        | `identifiers.public_key`    |
| `fingerprint.stable_hash`       | `device.hashes.stable`      |
| `fingerprint.fuzzy_hash`        | `device.hashes.fuzzy`       |
| `fingerprint.canvas_hash`       | `device.hashes.canvas`      |
| `fingerprint.loose.navigator.*` | `device.navigator.*`        |
| `fingerprint.loose.screen.*`    | `device.screen.*`           |
| `tcp_blob`                      | `sigint.tcp`                |
| `tls_blob`                      | `sigint.tls`                |
| `headers`                       | `sigint.headers`            |
| `device_id`                     | `identifiers.device_id`     |
| `confidence`                    | `analysis.confidence`       |
| `match_tier`                    | `analysis.match_tier`       |
| `risk_score`                    | `analysis.risk_score`       |
| `flags`                         | `analysis.flags`            |
| `evidence_codes`                | `analysis.evidence_codes`   |
| `anomalies`                     | `analysis.anomalies`        |
