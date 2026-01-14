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

/**
 * Generate a fingerprint with specified signals
 */
export function createFingerprint(
  options: FingerprintOptions = {},
): Fingerprint {
  const fingerprint: Fingerprint = {};
  const id = uniqueId();

  // Tier 0.5: Evercookie
  if (options.includeEvercookie) {
    fingerprint.evercookie_id = options.evercookieId ?? `ev-${id}`;
  }

  // Tier 1: Hash-based
  if (options.includeStableHash) {
    fingerprint.stable_hash = options.stableHash ?? `stable-${randomHex(32)}`;
  }
  if (options.includeFuzzyHash) {
    fingerprint.fuzzy_hash = options.fuzzyHash ?? `fuzzy-${randomHex(32)}`;
  }

  // Tier 2: IP + JA4
  if (options.includeIpJa4) {
    fingerprint.ip_address =
      options.ipAddress ??
      `10.0.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
    fingerprint.ja4 =
      options.ja4 ?? `t13d1516h2_${randomHex(12)}_${randomHex(12)}`;
  }

  // Tier 2: GPU + Screen + Timezone
  if (options.includeGpuScreenTz) {
    fingerprint.gpu_renderer =
      options.gpuRenderer ?? "ANGLE (NVIDIA GeForce RTX 3080)";
    fingerprint.screen_dims = options.screenDims ?? "1920x1080";
    fingerprint.timezone = options.timezone ?? "America/New_York";
  }

  // Tier 2: Audio + Canvas
  if (options.includeAudioCanvas) {
    fingerprint.audio_hash = options.audioHash ?? `audio-${randomHex(32)}`;
    fingerprint.canvas_hash = options.canvasHash ?? `canvas-${randomHex(32)}`;
  }

  // Bot detection signals
  if (options.includeBotSignals) {
    fingerprint.user_agent =
      options.userAgent ??
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    fingerprint.hardware_concurrency = options.hardwareConcurrency ?? 8;
    fingerprint.device_memory = options.deviceMemory ?? 16;
  }

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

/**
 * Create a "drifted" version of a fingerprint
 * Simulates the same device with some signals changed
 */
export function createDriftedFingerprint(
  original: Fingerprint,
  driftOptions: {
    changeIp?: boolean;
    changeGpu?: boolean;
    changeScreen?: boolean;
    changeTimezone?: boolean;
    changeUserAgent?: boolean;
  } = {},
): Fingerprint {
  const drifted = { ...original };

  if (driftOptions.changeIp && drifted.ip_address) {
    // Change last octet (same subnet, different IP)
    const parts = drifted.ip_address.split(".");
    parts[3] = String(Math.floor(Math.random() * 256));
    drifted.ip_address = parts.join(".");
  }

  if (driftOptions.changeGpu && drifted.gpu_renderer) {
    // Simulate driver update
    drifted.gpu_renderer = drifted.gpu_renderer.replace(
      "RTX 3080",
      "RTX 3080 Ti",
    );
  }

  if (driftOptions.changeScreen && drifted.screen_dims) {
    // Simulate resolution change
    drifted.screen_dims =
      drifted.screen_dims === "1920x1080" ? "2560x1440" : "1920x1080";
  }

  if (driftOptions.changeTimezone && drifted.timezone) {
    // Simulate travel
    drifted.timezone =
      drifted.timezone === "America/New_York"
        ? "America/Los_Angeles"
        : "America/New_York";
  }

  if (driftOptions.changeUserAgent && drifted.user_agent) {
    // Simulate browser update
    drifted.user_agent = drifted.user_agent.replace("537.36", "538.00");
  }

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
