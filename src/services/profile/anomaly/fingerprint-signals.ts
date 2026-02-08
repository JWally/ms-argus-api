import { Fingerprint } from "../../../types";
import {
  AnomalySignal,
  AnomalyType,
  AnomalyCodes,
  createSignal,
} from "./types";

/**
 * Configuration for a score threshold check
 */
interface ScoreCheck {
  /** Score value to check (undefined treated as 0) */
  score: number | undefined;
  /** Type of anomaly to create */
  type: AnomalyType;
  /** Anomaly code to use */
  code: (typeof AnomalyCodes)[keyof typeof AnomalyCodes];
  /** Field name for reporting */
  field: string;
  /** Optional multiplier for severity (default 1) */
  severityMultiplier?: number;
}

/**
 * Check if a score exceeds threshold and create anomaly signal
 * @param check - Score check configuration
 * @returns Anomaly signal if score > 0.7, null otherwise
 */
function checkScoreThreshold(check: ScoreCheck): AnomalySignal | null {
  const { score, type, code, field, severityMultiplier = 1 } = check;
  if (score === undefined || score <= 0.7) return null;
  return createSignal(type, code, score * severityMultiplier, {
    expected: `${field} <= 0.7`,
    actual: `${field}: ${score.toFixed(2)}`,
    fields: [field],
  });
}

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object";
}

/** Check screen dimensions vs CSS media screen query. */
function checkScreenCssMismatch(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const screen = device.screen;
  const cssMedia = device.cssMedia;
  if (!isObj(screen) || !isObj(cssMedia)) return null;
  const screenQuery = cssMedia.screenQuery;
  if (!isObj(screenQuery)) return null;

  const sw = screen.width;
  const sh = screen.height;
  const cw = screenQuery.width;
  const ch = screenQuery.height;
  if (typeof sw !== "number" || typeof sh !== "number") return null;
  if (typeof cw !== "number" || typeof ch !== "number") return null;

  if (sw !== cw || sh !== ch) {
    return createSignal("CROSS_FIELD", AnomalyCodes.SCREEN_CSS_MISMATCH, 0.9, {
      expected: `screen ${sw}x${sh} matches CSS screenQuery`,
      actual: `screen ${sw}x${sh} vs CSS ${cw}x${ch}`,
      fields: [
        "screen.width",
        "screen.height",
        "cssMedia.screenQuery.width",
        "cssMedia.screenQuery.height",
      ],
    });
  }
  return null;
}

/** Check for audio fingerprint noise (anti-fingerprint extension indicator). */
function checkAudioNoise(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const audio = device.offlineAudioContext;
  if (!isObj(audio)) return null;
  const noise = audio.noise;
  if (typeof noise !== "number") return null;
  if (noise > 0) {
    return createSignal(
      "CROSS_FIELD",
      AnomalyCodes.AUDIO_NOISE_DETECTED,
      0.85,
      {
        expected: "audio noise: 0",
        actual: `audio noise: ${noise}`,
        fields: ["offlineAudioContext.noise"],
      },
    );
  }
  return null;
}

/** Check timezone offset consistency between main thread and worker scope. */
function checkTimezoneOffsetMismatch(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const tz = device.timezone;
  const ws = device.workerScope;
  if (!isObj(tz) || !isObj(ws)) return null;

  const mainOffset = tz.offset;
  const workerOffset = ws.timezoneOffset;
  if (typeof mainOffset !== "number" || typeof workerOffset !== "number")
    return null;

  if (mainOffset !== workerOffset) {
    return createSignal(
      "CROSS_FIELD",
      AnomalyCodes.TIMEZONE_OFFSET_MISMATCH,
      0.9,
      {
        expected: `timezone offset consistent (${mainOffset})`,
        actual: `main: ${mainOffset} vs worker: ${workerOffset}`,
        fields: ["timezone.offset", "workerScope.timezoneOffset"],
      },
    );
  }
  return null;
}

/** Collect touch-related contradictions from screen and CSS media signals. */
function collectTouchMismatches(
  screen: Record<string, unknown> | null,
  cssMedia: Record<string, unknown> | null,
): string[] {
  const mismatches: string[] = [];
  const touchFalse = screen !== null && screen.touch === false;

  if (touchFalse) {
    mismatches.push("screen.touch=false");
  }

  if (cssMedia !== null && touchFalse) {
    const { anyPointer, anyHover } = cssMedia;
    if (anyPointer === "fine" && anyHover === "hover") {
      mismatches.push(`pointer=${anyPointer},hover=${anyHover}`);
    }
  }

  return mismatches;
}

/** Check touch capability coherence (maxTouchPoints vs touch/pointer signals). */
function checkTouchMismatch(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const nav = device.navigator;
  if (!isObj(nav)) return null;

  const maxTouch = nav.maxTouchPoints;
  if (typeof maxTouch !== "number" || maxTouch <= 0) return null;

  const screen = isObj(device.screen) ? device.screen : null;
  const cssMedia = isObj(device.cssMedia) ? device.cssMedia : null;
  const mismatches = collectTouchMismatches(screen, cssMedia);

  if (mismatches.length === 0) return null;

  return createSignal("CROSS_FIELD", AnomalyCodes.TOUCH_MISMATCH, 0.7, {
    expected: `maxTouchPoints=${maxTouch} consistent with touch signals`,
    actual: `maxTouchPoints=${maxTouch} but ${mismatches.join(", ")}`,
    fields: [
      "navigator.maxTouchPoints",
      "screen.touch",
      "cssMedia.anyPointer",
      "cssMedia.anyHover",
    ],
  });
}

/** Check WebGL renderer consistency between main context and worker scope. */
function checkWebglRendererMismatch(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const webgl = device.canvasWebgl;
  const ws = device.workerScope;
  if (!isObj(webgl) || !isObj(ws)) return null;
  const params = webgl.parameters;
  if (!isObj(params)) return null;

  const mainRenderer = params.UNMASKED_RENDERER_WEBGL;
  const workerRenderer = ws.webglRenderer;
  if (typeof mainRenderer !== "string" || typeof workerRenderer !== "string")
    return null;

  if (mainRenderer !== workerRenderer) {
    return createSignal(
      "CROSS_FIELD",
      AnomalyCodes.WEBGL_RENDERER_MISMATCH,
      0.85,
      {
        expected: "WebGL renderer consistent across contexts",
        actual: `main: ${mainRenderer.substring(0, 60)} vs worker: ${workerRenderer.substring(0, 60)}`,
        fields: [
          "canvasWebgl.parameters.UNMASKED_RENDERER_WEBGL",
          "workerScope.webglRenderer",
        ],
      },
    );
  }
  return null;
}

/**
 * Detect anomalies from pre-computed fingerprint signals (headless, proxy, VPN)
 * and within-payload consistency checks.
 */
export function detectFingerprintSignals(
  fingerprint: Fingerprint,
  raw?: unknown,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];

  if (fingerprint.is_headless === true) {
    signals.push(
      createSignal("CROSS_FIELD", AnomalyCodes.HEADLESS_DETECTED, 0.9, {
        expected: "is_headless: false",
        actual: "is_headless: true",
        fields: ["is_headless"],
      }),
    );
  }

  const proxySignal = checkScoreThreshold({
    score: fingerprint.proxy_score,
    type: "NETWORK",
    code: AnomalyCodes.HIGH_PROXY_SCORE,
    field: "proxy_score",
  });
  if (proxySignal) signals.push(proxySignal);

  const vpnSignal = checkScoreThreshold({
    score: fingerprint.vpn_score,
    type: "NETWORK",
    code: AnomalyCodes.HIGH_VPN_SCORE,
    field: "vpn_score",
    severityMultiplier: 0.8,
  });
  if (vpnSignal) signals.push(vpnSignal);

  // Within-payload consistency checks (require raw device object)
  if (isObj(raw)) {
    const consistencyChecks = [
      checkScreenCssMismatch,
      checkAudioNoise,
      checkTimezoneOffsetMismatch,
      checkTouchMismatch,
      checkWebglRendererMismatch,
    ];
    for (const check of consistencyChecks) {
      const signal = check(raw);
      if (signal) signals.push(signal);
    }
  }

  return signals;
}
