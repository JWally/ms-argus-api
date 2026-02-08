import { fnv1a } from "./hash";
import type { Fingerprint } from "../types/fingerprint";

/**
 * Build session anchor bucket key for ephemeral matching
 * Combines IP + User-Agent hash + Screen dimensions
 * Returns null if required signals are missing
 */
export function buildSessionAnchorKey(fingerprint: Fingerprint): string | null {
  if (
    !fingerprint.ip_address ||
    !fingerprint.user_agent ||
    !fingerprint.screen_dims
  ) {
    return null;
  }

  const uaHash = fnv1a(fingerprint.user_agent);
  return `session_anchor#${fingerprint.ip_address}#${uaHash}#${fingerprint.screen_dims}`;
}

/**
 * Build IP+UA-only anchor bucket key for ephemeral matching
 * Does NOT include screen_dims - catches dock/undock screen changes
 * Returns null if required signals are missing
 */
export function buildIpUaAnchorKey(fingerprint: Fingerprint): string | null {
  if (!fingerprint.ip_address || !fingerprint.user_agent) {
    return null;
  }

  const uaHash = fnv1a(fingerprint.user_agent);
  return `ip_ua_anchor#${fingerprint.ip_address}#${uaHash}`;
}
