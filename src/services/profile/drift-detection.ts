// src/services/profile/drift-detection.ts
// AR-120: Extracted drift detection logic from profile-service.ts
import { DeviceProfile, Fingerprint } from "./types";

/**
 * Check if incoming fingerprint has significant drift from existing profile
 * Returns true if we should update, false if fingerprint is essentially the same
 */
export function hasSignificantDrift(
  existing: DeviceProfile,
  incoming: Fingerprint,
): boolean {
  // Major drift: stable hash changed
  if (existing.stable_hash !== incoming.stable_hash) {
    return true;
  }

  // Count how many signals have changed
  let changedSignals = 0;

  if (existing.canvas_hash !== incoming.canvas_hash) changedSignals++;
  if (existing.webgl_hash !== incoming.webgl_hash) changedSignals++;
  if (existing.audio_hash !== incoming.audio_hash) changedSignals++;
  if (existing.gpu_renderer !== incoming.gpu_renderer) changedSignals++;
  if (existing.screen_dims !== incoming.screen_dims) changedSignals++;

  // Drift threshold: 2+ signals changed
  return changedSignals >= 2;
}
