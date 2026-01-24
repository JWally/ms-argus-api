// tests/utils/fingerprint.factory.ts
// AR-60: Test factories for generating fingerprints with various signal combinations

import { Fingerprint } from "../../src/types/fingerprint";

/**
 * Options for generating a fingerprint
 */
export interface FingerprintOptions {
  // Tier 0.5 signals
  includeEvercookie?: boolean;

  // Tier 1 signals
  includeStableHash?: boolean;
  includeFuzzyHash?: boolean;

  // Tier 2 signals
  includeIpJa4?: boolean;
  includeGpuScreenTz?: boolean;
  includeAudioCanvas?: boolean;

  // Bot detection signals
  includeBotSignals?: boolean;

  // Custom values (optional overrides)
  stableHash?: string;
  fuzzyHash?: string;
  evercookieId?: string;
  ipAddress?: string;
  ja4?: string;
  gpuRenderer?: string;
  screenDims?: string;
  timezone?: string;
  audioHash?: string;
  canvasHash?: string;
  userAgent?: string;
  hardwareConcurrency?: number;
  deviceMemory?: number;
}

/**
 * Preset configurations for common test scenarios
 */
export const FingerprintPresets = {
  /** Full fingerprint with all signals */
  FULL: {
    includeEvercookie: true,
    includeStableHash: true,
    includeFuzzyHash: true,
    includeIpJa4: true,
    includeGpuScreenTz: true,
    includeAudioCanvas: true,
    includeBotSignals: true,
  },

  /** Minimal fingerprint - only stable hash */
  MINIMAL: {
    includeStableHash: true,
  },

  /** Tier 1 only - hash-based matching */
  TIER1_ONLY: {
    includeStableHash: true,
    includeFuzzyHash: true,
  },

  /** Tier 2 only - bucket-based matching */
  TIER2_ONLY: {
    includeIpJa4: true,
    includeGpuScreenTz: true,
    includeAudioCanvas: true,
  },

  /** Evercookie only - persistent tracking */
  EVERCOOKIE_ONLY: {
    includeEvercookie: true,
  },

  /** Bot-like fingerprint - minimal signals, suspicious values */
  BOT_LIKE: {
    includeStableHash: true,
    includeBotSignals: true,
    hardwareConcurrency: 1,
    deviceMemory: 0,
    userAgent: "HeadlessChrome",
  },

  /** Privacy browser - limited signals (Brave/Firefox strict) */
  PRIVACY_BROWSER: {
    includeStableHash: true,
    includeIpJa4: true,
    // Canvas/audio typically blocked, GPU often randomized
  },

  /** Mobile device */
  MOBILE: {
    includeStableHash: true,
    includeFuzzyHash: true,
    includeIpJa4: true,
    includeGpuScreenTz: true,
    includeBotSignals: true,
    screenDims: "390x844",
    deviceMemory: 4,
    hardwareConcurrency: 6,
  },
} as const;

/**
 * Counter for generating unique values
 */
let counter = 0;

/**
 * Generate a unique ID suffix
 */
function uniqueId(): string {
  return `${Date.now()}-${++counter}`;
}

/**
 * Generate a random hex string of specified length
 */
function randomHex(length: number): string {
  const chars = "0123456789abcdef";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

const DEFAULT_SCREEN_DIMS = "1920x1080";
const DEFAULT_TIMEZONE = "America/New_York";

function applyEvercookie(fp: Fingerprint, options: FingerprintOptions): void {
  if (!options.includeEvercookie) return;
  fp.evercookie_id = options.evercookieId ?? `ev-${uniqueId()}`;
}

function applyTier1Hashes(fp: Fingerprint, options: FingerprintOptions): void {
  if (options.includeStableHash) {
    fp.stable_hash = options.stableHash ?? `stable-${randomHex(32)}`;
  }
  if (options.includeFuzzyHash) {
    fp.fuzzy_hash = options.fuzzyHash ?? `fuzzy-${randomHex(32)}`;
  }
}

function applyIpJa4(fp: Fingerprint, options: FingerprintOptions): void {
  if (!options.includeIpJa4) return;
  fp.ip_address =
    options.ipAddress ??
    `10.0.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
  fp.ja4 = options.ja4 ?? `t13d1516h2_${randomHex(12)}_${randomHex(12)}`;
}

function applyGpuScreenTz(fp: Fingerprint, options: FingerprintOptions): void {
  if (!options.includeGpuScreenTz) return;
  fp.gpu_renderer = options.gpuRenderer ?? "ANGLE (NVIDIA GeForce RTX 3080)";
  fp.screen_dims = options.screenDims ?? DEFAULT_SCREEN_DIMS;
  fp.timezone = options.timezone ?? DEFAULT_TIMEZONE;
}

function applyAudioCanvas(fp: Fingerprint, options: FingerprintOptions): void {
  if (!options.includeAudioCanvas) return;
  fp.audio_hash = options.audioHash ?? `audio-${randomHex(32)}`;
  fp.canvas_hash = options.canvasHash ?? `canvas-${randomHex(32)}`;
}

function applyBotSignals(fp: Fingerprint, options: FingerprintOptions): void {
  if (!options.includeBotSignals) return;
  fp.user_agent =
    options.userAgent ??
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
  fp.hardware_concurrency = options.hardwareConcurrency ?? 8;
  fp.device_memory = options.deviceMemory ?? 16;
}

/**
 * Generate a fingerprint with specified signals
 */
export function createFingerprint(
  options: FingerprintOptions = {},
): Fingerprint {
  const fingerprint: Fingerprint = {};
  applyEvercookie(fingerprint, options);
  applyTier1Hashes(fingerprint, options);
  applyIpJa4(fingerprint, options);
  applyGpuScreenTz(fingerprint, options);
  applyAudioCanvas(fingerprint, options);
  applyBotSignals(fingerprint, options);
  return fingerprint;
}

/**
 * Create a fingerprint from a preset
 */
export function createFingerprintFromPreset(
  preset: keyof typeof FingerprintPresets,
  overrides?: Partial<FingerprintOptions>,
): Fingerprint {
  const presetOptions = FingerprintPresets[preset];
  return createFingerprint({ ...presetOptions, ...overrides });
}

export interface DriftOptions {
  changeIp?: boolean;
  changeGpu?: boolean;
  changeScreen?: boolean;
  changeTimezone?: boolean;
  changeUserAgent?: boolean;
}

function driftIp(fp: Fingerprint): void {
  if (!fp.ip_address) return;
  const parts = fp.ip_address.split(".");
  parts[3] = String(Math.floor(Math.random() * 256));
  fp.ip_address = parts.join(".");
}

function driftGpu(fp: Fingerprint): void {
  if (!fp.gpu_renderer) return;
  fp.gpu_renderer = fp.gpu_renderer.replace("RTX 3080", "RTX 3080 Ti");
}

function driftScreen(fp: Fingerprint): void {
  if (!fp.screen_dims) return;
  fp.screen_dims =
    fp.screen_dims === DEFAULT_SCREEN_DIMS ? "2560x1440" : DEFAULT_SCREEN_DIMS;
}

function driftTimezone(fp: Fingerprint): void {
  if (!fp.timezone) return;
  fp.timezone =
    fp.timezone === DEFAULT_TIMEZONE ? "America/Los_Angeles" : DEFAULT_TIMEZONE;
}

function driftUserAgent(fp: Fingerprint): void {
  if (!fp.user_agent) return;
  fp.user_agent = fp.user_agent.replace("537.36", "538.00");
}

/**
 * Create a "drifted" version of a fingerprint
 * Simulates the same device with some signals changed
 */
export function createDriftedFingerprint(
  original: Fingerprint,
  driftOptions: DriftOptions = {},
): Fingerprint {
  const drifted = { ...original };
  if (driftOptions.changeIp) driftIp(drifted);
  if (driftOptions.changeGpu) driftGpu(drifted);
  if (driftOptions.changeScreen) driftScreen(drifted);
  if (driftOptions.changeTimezone) driftTimezone(drifted);
  if (driftOptions.changeUserAgent) driftUserAgent(drifted);
  return drifted;
}

/**
 * Create multiple unique fingerprints
 */
export function createMultipleFingerprints(
  count: number,
  options: FingerprintOptions = FingerprintPresets.FULL,
): Fingerprint[] {
  return Array.from({ length: count }, () => createFingerprint(options));
}

/**
 * Create fingerprints that should all match to the same device
 * (same stable_hash, different Tier 2 signals)
 */
export function createMatchingFingerprints(
  count: number,
  baseOptions: FingerprintOptions = {},
): Fingerprint[] {
  const stableHash = baseOptions.stableHash ?? `stable-${randomHex(32)}`;
  const evercookieId = baseOptions.evercookieId ?? `ev-${uniqueId()}`;

  return Array.from({ length: count }, () =>
    createFingerprint({
      ...FingerprintPresets.FULL,
      ...baseOptions,
      stableHash,
      evercookieId,
      // Randomize Tier 2 signals to simulate slight variations
      ipAddress: `10.0.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
    }),
  );
}
