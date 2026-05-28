/**
 * Cross-axis shared primitives for the scoring/ modules.
 *
 * Anything two or more axis composers need to call (or the orchestrator in
 * helpers/merchant-projection.ts needs to call) goes here, so we never
 * import upward from scoring/ back into helpers/.
 *
 * Current contents are the absolute minimum needed by the network-tampering
 * extraction:
 *   - MerchantProjectionInput  (the projection input shape)
 *   - probabilityFromUnit      (unit [0,1] → percentage-of-5 mapper)
 *   - detectCellular           (cellular carve-out predicate)
 *   - detectCorporateShield    (Cisco-Umbrella-style carve-out)
 *   - detectNoWebrtc           (no-WebRTC-uplift predicate)
 *
 * Subsequent PRs (automation, device-tampering) move more of the cross-axis
 * helpers here as they come up: detectHyperscaler, isCorporateShieldedAsn,
 * isVerifiedAppleRelay, readHeadless, readJa4UaSignals, etc.
 */

import type { IntegrityResultsData } from "../helpers/payload-schema";

/** Input bundle for the projection. Accepts an integrity record only — the
 *  old session/payload shapes were tied to the fingerprint matching pipeline
 *  which was removed in remove-fingerprint. */
export interface MerchantProjectionInput {
  session_id: string;
  integrity?: IntegrityResultsData;
}

/** Round a [0,1] unit score up to a nearest-5 percentage in [0,100]. */
export function probabilityFromUnit(score: number): number {
  const clamped = Math.max(0, Math.min(1, score));
  return Math.round((clamped * 100) / 5) * 5;
}

/** Mobile-carrier or CGNAT path. Used by network-axis carve-outs and the
 *  `cellular` tag. */
export function detectCellular(input: MerchantProjectionInput): boolean {
  if (input.integrity?.analysis.ip.asn.category === "mobile") return true;
  const signals = input.integrity?.analysis.ip.signals ?? [];
  return signals.some((s) => s.code === "SAME_SUBNET_CGNAT");
}

/** Known corporate egress (e.g. Cisco Umbrella, Zscaler) — these
 *  re-originate TLS and look like VPNs structurally; the carve-out zeroes
 *  the network-axis components to avoid false-positive blocks. */
export function detectCorporateShield(input: MerchantProjectionInput): boolean {
  return input.integrity?.analysis.ip.asn.category === "corporate_proxy";
}

/** WebRTC not submitted and the ip-consistency analyzer is otherwise
 *  confident — feeds the "no-WebRTC" uplift floor in the network axis. */
export function detectNoWebrtc(input: MerchantProjectionInput): boolean {
  const ipAnalysis = input.integrity?.analysis.ip;
  if (!ipAnalysis) return false;
  if (ipAnalysis.integrity === 0) return false;
  return ipAnalysis.ips.webrtc === null;
}
