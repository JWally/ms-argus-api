/** Brave-on-iOS privacy-wrap attribution. */

import type { IntegrityResultsData } from "../helpers/payload-schema";
import { readUaIdentity } from "./identity";

const BRAVE_IOS_AUDIO_KEYS = [
  "AnalyserNode.getFloatFrequencyData",
  "AnalyserNode.getByteFrequencyData",
  "AnalyserNode.getFloatTimeDomainData",
  "AnalyserNode.getByteTimeDomainData",
  "AudioBuffer.getChannelData",
] as const;

const BRAVE_IOS_PLUGIN_KEYS = [
  "PluginArray.item",
  "PluginArray.namedItem",
  "Navigator.plugins",
] as const;

const BRAVE_IOS_ALL_KEYS = new Set<string>([
  ...BRAVE_IOS_AUDIO_KEYS,
  ...BRAVE_IOS_PLUGIN_KEYS,
  "Navigator.hardwareConcurrency",
]);

export interface BraveIosDetection {
  matched: boolean;
  attributedLies: number;
}

/** Attribute Brave iOS privacy API wraps without suppressing other evidence. */
export function detectBraveIos(
  integrity: IntegrityResultsData,
): BraveIosDetection {
  const identity = readUaIdentity(integrity);
  if (identity.browserFamily !== "safari" || identity.os !== "iOS") {
    return { matched: false, attributedLies: 0 };
  }

  const liesData =
    (
      integrity.device as
        | { lies?: { data?: Record<string, string[]> } }
        | undefined
    )?.lies?.data ?? {};
  const audioHits = BRAVE_IOS_AUDIO_KEYS.filter(
    (key) => liesData[key] !== undefined,
  ).length;
  const pluginHits = BRAVE_IOS_PLUGIN_KEYS.filter(
    (key) => liesData[key] !== undefined,
  ).length;
  if (audioHits < 4 || pluginHits < 1) {
    return { matched: false, attributedLies: 0 };
  }

  let attributedLies = 0;
  for (const [key, lies] of Object.entries(liesData)) {
    if (BRAVE_IOS_ALL_KEYS.has(key) && Array.isArray(lies)) {
      attributedLies += lies.length;
    }
  }
  return { matched: true, attributedLies };
}
