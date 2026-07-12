/**
 * Timezone analysis for integrity ingestion.
 *
 * Cross-validates timezone data from four independent sources:
 * 1. Client device.timezone (offset, computed offset, IANA location)
 * 2. Worker scopes (timezoneOffset from dedicated/shared workers)
 * 3. CloudFront IP geolocation (sigint.aws_cf.tz)
 * 4. Client-side lie detection flag
 */

import {
  AnomalyCodes,
  createSignal,
  toResultSignals,
  type AnomalySignal,
} from "../../services/profile/anomaly/types";

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

export interface TimezoneAnalysisResult {
  lied: boolean;
  checks: {
    offsetMatchesComputed: boolean;
    locationMatchesCfTimezone: boolean | null;
    offsetMatchesWorker: boolean | null;
    clientReportedLie: boolean;
  };
  cfTimezone: string | null;
  clientTimezone: string | null;
  signals: Array<{ code: string; severity: number; evidence: string }>;
}

function checkOffsetVsComputed(
  tz: Record<string, unknown>,
): AnomalySignal | null {
  const offset = num(tz.offset);
  const computed = num(tz.offsetComputed);
  if (offset === null || computed === null) return null;
  if (offset === computed) return null;
  return createSignal(
    "CROSS_FIELD",
    AnomalyCodes.TZ_OFFSET_COMPUTED_MISMATCH,
    0.7,
    {
      expected: `offset (${offset}) matches offsetComputed`,
      actual: `offset=${offset}, offsetComputed=${computed}`,
      fields: ["timezone.offset", "timezone.offsetComputed"],
    },
  );
}

function checkCfTimezone(
  clientLocation: string | null,
  cfTz: string | null,
): AnomalySignal | null {
  if (!clientLocation || !cfTz) return null;
  if (clientLocation === cfTz) return null;
  return createSignal(
    "CROSS_FIELD",
    AnomalyCodes.TZ_GEOLOCATION_MISMATCH,
    0.6,
    {
      expected: `client timezone matches IP geolocation`,
      actual: `client=${clientLocation}, cloudfront=${cfTz}`,
      fields: ["timezone.location", "sigint.aws_cf.tz"],
    },
  );
}

function checkWorkerOffset(
  mainOffset: number | null,
  device: Record<string, unknown>,
): AnomalySignal | null {
  if (mainOffset === null) return null;
  const ws = device.workerScope;
  if (!isObj(ws) || !isObj(ws.scopes)) return null;

  for (const key of ["web", "shared"]) {
    const scope = ws.scopes[key];
    if (!isObj(scope)) continue;
    const workerOffset = num(scope.timezoneOffset);
    if (workerOffset === null) continue;
    if (workerOffset !== mainOffset) {
      return createSignal(
        "CROSS_FIELD",
        AnomalyCodes.TIMEZONE_OFFSET_MISMATCH,
        0.5,
        {
          expected: `main offset matches ${key} worker`,
          actual: `main=${mainOffset}, ${key}Worker=${workerOffset}`,
          fields: [
            "timezone.offset",
            `workerScope.scopes.${key}.timezoneOffset`,
          ],
        },
      );
    }
  }
  return null;
}

function formatSignals(
  signals: AnomalySignal[],
): TimezoneAnalysisResult["signals"] {
  return toResultSignals(signals);
}

const EMPTY: TimezoneAnalysisResult = {
  lied: false,
  checks: {
    offsetMatchesComputed: true,
    locationMatchesCfTimezone: null,
    offsetMatchesWorker: null,
    clientReportedLie: false,
  },
  cfTimezone: null,
  clientTimezone: null,
  signals: [],
};

function extractCfTimezone(sigint: unknown): string | null {
  if (!isObj(sigint) || !isObj(sigint.aws_cf)) return null;
  // Direct field (post-hydration via redeemSigintTokens)
  const direct = str(sigint.aws_cf.tz);
  if (direct) return direct;
  // Nested under .data (raw client fetch result: { data, error, durationMs })
  return isObj(sigint.aws_cf.data) ? str(sigint.aws_cf.data.tz) : null;
}

function collectSignals(
  tz: Record<string, unknown>,
  device: Record<string, unknown>,
  cfTz: string | null,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];

  const offsetSig = checkOffsetVsComputed(tz);
  if (offsetSig) signals.push(offsetSig);

  const cfSig = checkCfTimezone(str(tz.location), cfTz);
  if (cfSig) signals.push(cfSig);

  const workerSig = checkWorkerOffset(num(tz.offset), device);
  if (workerSig) signals.push(workerSig);

  if (tz.lied) {
    signals.push(
      createSignal("CROSS_FIELD", AnomalyCodes.TIMEZONE_OFFSET_MISMATCH, 0.4, {
        expected: "no timezone API tampering",
        actual: "client lie scanner flagged timezone APIs",
        fields: ["timezone.lied"],
      }),
    );
  }

  return signals;
}

function buildChecks(
  signals: AnomalySignal[],
  tz: Record<string, unknown>,
  cfTz: string | null,
): TimezoneAnalysisResult["checks"] {
  const hasCfMismatch = signals.some(
    (s) => s.code === AnomalyCodes.TZ_GEOLOCATION_MISMATCH,
  );
  const hasWorkerMismatch = signals.some(
    (s) => s.code === AnomalyCodes.TIMEZONE_OFFSET_MISMATCH && s.severity > 0.4,
  );
  const hasOffsetMismatch = signals.some(
    (s) => s.code === AnomalyCodes.TZ_OFFSET_COMPUTED_MISMATCH,
  );
  return {
    offsetMatchesComputed: !hasOffsetMismatch,
    locationMatchesCfTimezone: cfTz ? !hasCfMismatch : null,
    offsetMatchesWorker: num(tz.offset) !== null ? !hasWorkerMismatch : null,
    clientReportedLie: !!tz.lied,
  };
}

/**
 * Analyze timezone consistency across client, worker, and server sources.
 */
export function analyzeTimezone(
  device: unknown,
  sigint: unknown,
): TimezoneAnalysisResult {
  if (!isObj(device)) return EMPTY;
  const tz = device.timezone;
  if (!isObj(tz)) return EMPTY;

  const cfTz = extractCfTimezone(sigint);
  const signals = collectSignals(tz, device, cfTz);

  return {
    lied: signals.length > 0,
    checks: buildChecks(signals, tz, cfTz),
    cfTimezone: cfTz,
    clientTimezone: str(tz.location),
    signals: formatSignals(signals),
  };
}
