// src/helpers/constants.ts
import { Options } from "@middy/http-cors";
import * as glue from "aws-cdk-lib/aws-glue";

export const SECURITY_KEY_NAME = "argus-keys";

// Cache duration: 15 minutes
export const KEY_CACHE_DURATION: number = 1000 * 60 * 15;

export const DEFAULT_HEADERS = {
  "Content-Security-Policy": "default-src 'self'",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Download-Options": "noopen",
  "X-Frame-Options": "DENY",
  "X-Permitted-Cross-Domain-Policies": "none",
  "Referrer-Policy": "no-referrer",
  "X-XSS-Protection": "1; mode=block",
} as const;

export const ALLOWED_HEADERS = [
  "Content-Type",
  "X-Amz-Date",
  "Authorization",
  "X-Api-Key",
  "X-Amz-Security-Token",
  "X-Amz-User-Agent",
  "Accept",
  "Accept-Language",
  "Content-Language",
  "Origin",
  "X-Requested-With",
];

const HARDENED_ORIGIN = "*";

export const MIDDY_CORS_CONFIG: Options = {
  origin: HARDENED_ORIGIN,
  credentials: true,
  methods: ["POST", "OPTIONS"].join(","),
  headers: ALLOWED_HEADERS.join(","),
};

export const WARMUP_EVENT = {
  source: "serverless-plugin-warmup",
  event: {
    source: "warmup",
    type: "keepalive",
  },
};

export const AWS_SECRETS_REQUIRED_KEYS: string[] = [
  "ENCRYPTION_KEY", // AES-GCM key for TCP blob decryption
  "HMAC_KEY", // HMAC key for signature validation
];

export const ERROR_STRINGS = {
  SECRETS_MANAGER_FAILED: "Failed to retrieve secrets from Secrets Manager",
  KEY_ARN_NOT_SET: "Environment variables SECRET_KEY_ARN must be set",
  CANNOT_PARSE_JSON: "Cannot Parse JSON Data",
  CANNOT_DECRYPT: "Cannot Decrypt Payload",
  CANNOT_VERIFY_SIGNATURE: "Cannot Verify Signature",
};

export const SECRET_KEY_ARN: string | undefined = process.env.SECRET_KEY_ARN;
export const POWERTOOLS_METRICS_NAMESPACE: string | undefined =
  process.env.POWERTOOLS_METRICS_NAMESPACE;
export const POWERTOOLS_SERVICE_NAME: string | undefined =
  process.env.POWERTOOLS_SERVICE_NAME;

/**
 * Argus fingerprint data columns for Glue/Parquet schema
 * Includes: JS fingerprint, TCP fingerprint, TLS fingerprint, IP enrichment, analysis results
 */
export const ARGUS_COLUMNS: glue.CfnTable.ColumnProperty[] = [
  // ==================== CORE IDENTITY ====================
  { name: "session_id", type: "string" },
  { name: "ipAddress", type: "string" },

  // ==================== TCP FINGERPRINT (from tcp-probe) ====================
  { name: "tcp.rtt_us", type: "int" },
  { name: "tcp.rttvar", type: "int" },
  { name: "tcp.snd_mss", type: "int" },
  { name: "tcp.rcv_mss", type: "int" },
  { name: "tcp.pmtu", type: "int" },
  { name: "tcp.snd_cwnd", type: "int" },
  { name: "tcp.total_retrans", type: "int" },
  { name: "tcp.tls_handshake_us", type: "bigint" },
  { name: "tcp.http_first_byte_us", type: "bigint" },
  { name: "tcp.total_connection_us", type: "bigint" },
  { name: "tcp.tls_to_tcp_ratio", type: "double" },
  { name: "tcp.total_to_tcp_ratio", type: "double" },
  { name: "tcp.proxy_score", type: "double" },
  { name: "tcp.vpn_score", type: "double" },
  { name: "tcp.proxy_signals", type: "string" }, // JSON array

  // ==================== TLS/HTTP2 FINGERPRINT ====================
  { name: "tls.ja3", type: "string" },
  { name: "tls.ja4", type: "string" },
  { name: "http2.protocol", type: "string" },
  { name: "http2.header_order", type: "string" },
  { name: "http2.fingerprint", type: "string" },

  // ==================== CLIENT HINTS ====================
  { name: "client_hints.ua", type: "string" },
  { name: "client_hints.ua_mobile", type: "string" },
  { name: "client_hints.ua_platform", type: "string" },
  { name: "client_hints.ua_platform_version", type: "string" },
  { name: "client_hints.ua_arch", type: "string" },
  { name: "client_hints.ua_bitness", type: "string" },
  { name: "client_hints.device_memory", type: "string" },
  { name: "client_hints.network_rtt", type: "string" },

  // ==================== IP ENRICHMENT ====================
  { name: "ip.asn", type: "int" },
  { name: "ip.org", type: "string" },
  { name: "ip.country", type: "string" },
  { name: "ip.city", type: "string" },
  { name: "ip.is_proxy", type: "boolean" },
  { name: "ip.is_vpn", type: "boolean" },
  { name: "ip.is_datacenter", type: "boolean" },
  { name: "ip.is_tor", type: "boolean" },

  // ==================== JS FINGERPRINT HASHES ====================
  { name: "js.canvas_hash", type: "string" },
  { name: "js.webgl_hash", type: "string" },
  { name: "js.audio_hash", type: "string" },
  { name: "js.fonts_hash", type: "string" },
  { name: "js.screen_hash", type: "string" },
  { name: "js.timezone_hash", type: "string" },
  { name: "js.navigator_hash", type: "string" },
  { name: "js.intl_hash", type: "string" },
  { name: "js.math_hash", type: "string" },
  { name: "js.wasm_hash", type: "string" },

  // ==================== JS FINGERPRINT RAW DATA ====================
  { name: "js.user_agent", type: "string" },
  { name: "js.platform", type: "string" },
  { name: "js.hardware_concurrency", type: "int" },
  { name: "js.device_memory", type: "double" },
  { name: "js.screen_width", type: "int" },
  { name: "js.screen_height", type: "int" },
  { name: "js.color_depth", type: "int" },
  { name: "js.timezone_offset", type: "int" },
  { name: "js.timezone_location", type: "string" },
  { name: "js.language", type: "string" },
  { name: "js.languages", type: "string" },
  { name: "js.webdriver", type: "boolean" },
  { name: "js.gpu_vendor", type: "string" },
  { name: "js.gpu_renderer", type: "string" },

  // ==================== BOT SIGNALS ====================
  { name: "bot.is_headless", type: "boolean" },
  { name: "bot.has_lies", type: "boolean" },
  { name: "bot.lie_count", type: "int" },
  { name: "bot.engine_mismatch", type: "boolean" },
  { name: "bot.likely_residential_proxy", type: "boolean" },
  { name: "bot.stealth_signals", type: "string" }, // JSON object
  { name: "bot.bot_hash", type: "string" },

  // ==================== INCONSISTENCIES ====================
  { name: "inconsistencies.count_critical", type: "int" },
  { name: "inconsistencies.count_high", type: "int" },
  { name: "inconsistencies.count_medium", type: "int" },
  { name: "inconsistencies.count_low", type: "int" },
  { name: "inconsistencies.risk_score", type: "double" },
  { name: "inconsistencies.details", type: "string" }, // JSON array

  // ==================== ANALYSIS RESULTS ====================
  { name: "analysis.device_id", type: "string" },
  { name: "analysis.device_id_confidence", type: "double" },
  { name: "analysis.risk_score", type: "double" },
  { name: "analysis.anomaly_flags", type: "string" }, // JSON array
  { name: "analysis.verdict", type: "string" }, // human, bot, suspicious
  { name: "analysis.processing_time_ms", type: "int" },

  // ==================== TIMING FINGERPRINT ====================
  { name: "timing.perf_elapsed", type: "double" },
  { name: "timing.date_elapsed", type: "double" },
  { name: "timing.drift", type: "double" },
  { name: "timing.resolution", type: "double" },
  { name: "timing.time_origin", type: "double" },

  // ==================== HTTP HEADERS ====================
  { name: "headers.user_agent", type: "string" },
  { name: "headers.accept", type: "string" },
  { name: "headers.accept_language", type: "string" },
  { name: "headers.accept_encoding", type: "string" },
  { name: "headers.referer", type: "string" },
  { name: "headers.origin", type: "string" },
  { name: "headers.x_forwarded_for", type: "string" },

  // ==================== METADATA ====================
  { name: "meta.timestamp", type: "bigint" },
  { name: "meta.collection_duration_ms", type: "int" },
  { name: "meta.argus_version", type: "string" },

  // ==================== DATE PARTITIONS ====================
  { name: "DATE_INFO.year", type: "int" },
  { name: "DATE_INFO.month", type: "int" },
  { name: "DATE_INFO.day", type: "int" },
  { name: "DATE_INFO.hour", type: "int" },
  { name: "DATE_INFO.minute", type: "int" },
  { name: "DATE_INFO.second", type: "int" },
  { name: "DATE_INFO.unix_timestamp", type: "bigint" },
  { name: "DATE_INFO.iso_string", type: "string" },
];
