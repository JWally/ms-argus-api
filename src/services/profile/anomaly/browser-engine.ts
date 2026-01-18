// src/services/profile/anomaly/browser-engine.ts
// AR-143: Browser engine anomaly detection (math fingerprint validation)

import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";

/**
 * Browser family extracted from User-Agent
 */
type BrowserFamily = "chrome" | "firefox" | "safari" | "unknown";

/**
 * Math result entry with browser engine markers
 */
interface MathEntry {
  value?: number;
  chrome?: boolean;
  firefox?: boolean;
  safari?: boolean;
}

/**
 * Raw payload structure for math data
 */
interface RawMathsPayload {
  loose?: {
    maths?: {
      data?: Record<string, MathEntry | unknown>;
    };
  };
}

/**
 * Engine name for evidence display
 */
const ENGINE_NAMES: Record<BrowserFamily, string> = {
  chrome: "Chrome/V8",
  firefox: "Firefox/SpiderMonkey",
  safari: "Safari/JSCore",
  unknown: "Unknown",
};

/**
 * Extract browser family from User-Agent string
 * Prioritizes specific browser identifiers over generic ones
 */
function extractBrowserFamily(userAgent: string | undefined): BrowserFamily {
  if (!userAgent) return "unknown";

  const ua = userAgent.toLowerCase();

  // Firefox is distinctive - check first
  if (ua.includes("firefox/") || ua.includes("gecko/")) {
    // But exclude Chrome/Edge that may have Gecko in compat strings
    if (!ua.includes("chrome/") && !ua.includes("edg/")) {
      return "firefox";
    }
  }

  // Safari check - must have Safari but NOT Chrome/Chromium
  // Safari UA: "Safari/605.1.15" without "Chrome/"
  if (
    ua.includes("safari/") &&
    !ua.includes("chrome/") &&
    !ua.includes("chromium/")
  ) {
    return "safari";
  }

  // Chrome-based browsers (Chrome, Edge, Brave, Opera use Chrome engine)
  if (
    ua.includes("chrome/") ||
    ua.includes("chromium/") ||
    ua.includes("edg/") ||
    ua.includes("opr/")
  ) {
    return "chrome";
  }

  return "unknown";
}

/**
 * Count math engine markers from raw payload
 * Returns counts for each engine type
 */
function countEngineMarkers(data: Record<string, MathEntry | unknown>): {
  chrome: number;
  firefox: number;
  safari: number;
  total: number;
} {
  const counts = { chrome: 0, firefox: 0, safari: 0, total: 0 };

  for (const [, entry] of Object.entries(data)) {
    // Skip non-object entries
    if (!entry || typeof entry !== "object") continue;

    const mathEntry = entry as MathEntry;

    // Count engine markers
    if (mathEntry.chrome === true) counts.chrome++;
    if (mathEntry.firefox === true) counts.firefox++;
    if (mathEntry.safari === true) counts.safari++;
    counts.total++;
  }

  return counts;
}

/**
 * Determine dominant engine from math results
 * Uses majority vote when results are mixed
 */
function getDominantEngine(counts: {
  chrome: number;
  firefox: number;
  safari: number;
  total: number;
}): BrowserFamily {
  if (counts.total === 0) return "unknown";

  // Find the engine with the most true markers
  const max = Math.max(counts.chrome, counts.firefox, counts.safari);
  if (max === 0) return "unknown";

  // Need clear majority (more than half the total that have any marker)
  const totalMarked = counts.chrome + counts.firefox + counts.safari;
  if (totalMarked === 0) return "unknown";

  // Return the dominant engine if it has majority
  if (counts.firefox > counts.chrome && counts.firefox > counts.safari) {
    return "firefox";
  }
  if (counts.chrome > counts.firefox && counts.chrome > counts.safari) {
    return "chrome";
  }
  if (counts.safari > counts.chrome && counts.safari > counts.firefox) {
    return "safari";
  }

  // Tie or no clear winner
  return "unknown";
}

/**
 * Check if claimed browser matches detected math engine
 */
function browserMatchesEngine(
  claimed: BrowserFamily,
  detected: BrowserFamily,
): boolean {
  if (claimed === "unknown" || detected === "unknown") return true;
  return claimed === detected;
}

/**
 * Detect browser engine anomalies by validating math fingerprint against claimed browser
 *
 * Different browser engines (V8/Chrome, SpiderMonkey/Firefox, JSCore/Safari) produce
 * different floating point results for edge-case math operations.
 *
 * @param fingerprint - Normalized fingerprint with user_agent
 * @param raw - Raw payload with loose.maths.data
 * @returns Array of anomaly signals for detected mismatches
 */
export function detectBrowserEngineAnomalies(
  fingerprint: Fingerprint,
  raw?: unknown,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];

  // Return empty if no raw payload
  if (!raw || typeof raw !== "object") {
    return signals;
  }

  const payload = raw as RawMathsPayload;

  // Check for loose.maths.data structure
  if (!payload.loose?.maths?.data) {
    return signals;
  }

  const mathData = payload.loose.maths.data;

  // Extract browser family from UA
  const claimedBrowser = extractBrowserFamily(fingerprint.user_agent);
  if (claimedBrowser === "unknown") {
    return signals; // Can't validate unknown browsers
  }

  // Count engine markers
  const counts = countEngineMarkers(mathData);
  if (counts.total === 0) {
    return signals; // No math data to analyze
  }

  // Determine dominant engine from math results
  const detectedEngine = getDominantEngine(counts);
  if (detectedEngine === "unknown") {
    return signals; // Can't determine engine
  }

  // Check for mismatch
  if (!browserMatchesEngine(claimedBrowser, detectedEngine)) {
    signals.push(
      createSignal(
        "CROSS_FIELD",
        AnomalyCodes.MATH_ENGINE_MISMATCH,
        0.85,
        `${ENGINE_NAMES[claimedBrowser]} (UA claims ${claimedBrowser.charAt(0).toUpperCase() + claimedBrowser.slice(1)})`,
        `${ENGINE_NAMES[detectedEngine]} (math results indicate ${detectedEngine.charAt(0).toUpperCase() + detectedEngine.slice(1)})`,
        ["user_agent", "loose.maths.data"],
      ),
    );
  }

  return signals;
}
