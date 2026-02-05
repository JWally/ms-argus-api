/**
 * Profile drift detection.
 *
 * Determines whether an incoming fingerprint has changed enough from
 * the stored profile to warrant an update. Used to reduce unnecessary
 * writes when fingerprints are effectively identical.
 * @module
 */
import { DeviceProfile, Fingerprint } from "./types";

/**
 * Check if incoming fingerprint has significant drift from existing profile.
 *
 * Compares stable_hash for exact changes, then counts secondary signal
 * changes (canvas, webgl, audio, gpu, screen). Updates are triggered if
 * stable_hash differs OR 2+ secondary signals have changed.
 *
 * @param existing - Current device profile from storage
 * @param incoming - Incoming fingerprint from request
 * @returns True if profile should be updated, false if no significant drift
 */
export function hasSignificantDrift(
  existing: DeviceProfile,
  incoming: Fingerprint,
): boolean {
  if (existing.stable_hash !== incoming.stable_hash) {
    return true;
  }

  let changedSignals = 0;

  if (existing.canvas_hash !== incoming.canvas_hash) changedSignals++;
  if (existing.webgl_hash !== incoming.webgl_hash) changedSignals++;
  if (existing.audio_hash !== incoming.audio_hash) changedSignals++;
  if (existing.gpu_renderer !== incoming.gpu_renderer) changedSignals++;
  if (existing.screen_dims !== incoming.screen_dims) changedSignals++;

  // Drift threshold: 2+ signals changed
  return changedSignals >= 2;
}
