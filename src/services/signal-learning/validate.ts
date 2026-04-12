/**
 * Signal Learning Validation
 *
 * Runs deterministic checks on a device payload to determine whether
 * the observation is trustworthy for baseline learning. Poisoned
 * observations (engine/TLS mismatches) are rejected.
 *
 * @module services/signal-learning/validate
 */

import {
  ENGINE_FAMILY,
  VALID_ENGINE_COMBOS,
  VENDOR_FAMILY,
} from "../profile/anomaly/engine-coherence";
import {
  TLS_STACKS,
  STACK_H2_FAMILY,
  parseJa4,
} from "../profile/anomaly/tls-maps";

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object";
}

function str(obj: Record<string, unknown>, key: string): string | undefined {
  const v = obj[key];
  return typeof v === "string" ? v : undefined;
}

function resolveTlsFamily(sigint: Record<string, unknown>): string | null {
  // Try h2 probe JA4 first, then tcp probe JA4
  const h2 = sigint.h2 as Record<string, unknown> | undefined;
  const tcp = sigint.tcp_probe as Record<string, unknown> | undefined;
  const ja4 = (h2?.ja4 as string) ?? (tcp?.ja4 as string) ?? null;
  if (!ja4) return null;

  const parsed = parseJa4(ja4);
  if (!parsed) return null;

  const stack = TLS_STACKS[parsed.cipherHash];
  return stack ? (STACK_H2_FAMILY[stack.stack] ?? null) : null;
}

/** True iff jsEngine+layoutEngine pair is a known-valid combination. */
function engineComboValid(
  jsEngine: string | undefined,
  layoutEngine: string | undefined,
): boolean {
  if (!jsEngine || !layoutEngine) return true;
  if (jsEngine === "unknown" || layoutEngine === "unknown") return true;
  return VALID_ENGINE_COMBOS.has(`${jsEngine}:${layoutEngine}`);
}

/** True iff jsEngine's family aligns with the observed TLS family. */
function engineMatchesTls(
  jsEngine: string | undefined,
  tlsFamily: string,
): boolean {
  if (!jsEngine || jsEngine === "unknown") return true;
  const fam = ENGINE_FAMILY[jsEngine];
  return !fam || fam === tlsFamily;
}

/** True iff navigator.vendor's family aligns with the observed TLS family. */
function vendorMatchesTls(vendor: unknown, tlsFamily: string): boolean {
  if (typeof vendor !== "string") return true;
  const fam = VENDOR_FAMILY[vendor];
  return !fam || fam === tlsFamily;
}

/**
 * Check whether the device payload passes deterministic integrity checks.
 *
 * Returns true if the observation looks legitimate (safe to count for learning).
 * Returns true for inconclusive cases (missing data) — we only reject
 * observations with definite mismatches.
 */
export function passesDeterministicChecks(
  device: unknown,
  sigint?: unknown,
): boolean {
  const dev = isObj(device) ? device : {};
  const sig = isObj(sigint) ? sigint : {};
  const engine = isObj(dev.engine)
    ? (dev.engine as Record<string, unknown>)
    : {};
  const nav = isObj(dev.navigator)
    ? (dev.navigator as Record<string, unknown>)
    : {};

  const jsEngine = str(engine, "jsEngine");
  const layoutEngine = str(engine, "layoutEngine");

  if (!engineComboValid(jsEngine, layoutEngine)) return false;

  const tlsFamily = resolveTlsFamily(sig);
  if (!tlsFamily) return true; // No TLS data — inconclusive, allow.

  return (
    engineMatchesTls(jsEngine, tlsFamily) &&
    vendorMatchesTls(nav.vendor, tlsFamily)
  );
}
