/**
 * Automation verdict axis.
 *
 * Owns the stored headless/CDP payload shape, CDP evidence tiers, mobile
 * carve-outs, and iframe-liveness checks. The merchant projection consumes
 * only the final score and two categorical predicates.
 */

import type { IntegrityResultsData } from "../helpers/payload-schema";
import {
  CDP_SUSPECT_TIER,
  desktopCdpTimingScore,
  hasErrorStackBurstSignal,
  type ConsoleTimingFields,
} from "./cdp-timing";
import type { MerchantProjectionInput } from "./shared";

const UA_HEADER_KEY = "user-agent";

interface HeadlessSignals {
  headlessRating?: number;
  likeHeadlessRating?: number;
  stealthRating?: number;
  likeHeadless?: Record<string, unknown>;
  cdp?: {
    consoleTiming?: ConsoleTimingFields;
    consoleTimingWorker?: ConsoleTimingFields;
    cdcGlobals?: boolean;
    pwBindings?: boolean;
    phantomMismatch?: boolean;
    clientLitter?: string[];
    automationGlobals?: string[];
    crossRealmTampered?: string[];
    ownPropsNative?: boolean;
    workerModuleImportChain?: { cdp_shaped?: boolean };
  };
}

function roundProbability(pct: number): number {
  const clamped = Math.max(0, Math.min(100, pct));
  return Math.round(clamped / 5) * 5;
}

function readHeadless(
  integrity: IntegrityResultsData,
): HeadlessSignals | undefined {
  return (integrity.device as { headless?: HeadlessSignals } | undefined)
    ?.headless;
}

export function detectDeveloperTools(input: MerchantProjectionInput): boolean {
  if (!input.integrity) return false;
  return readHeadless(input.integrity)?.likeHeadless?.devToolsOpen === true;
}

/** Mobile UAs make desktop-calibrated weak and timing signals unreliable. */
function isMobileBrowser(integrity: IntegrityResultsData | undefined): boolean {
  if (!integrity) return false;
  const headers = integrity.request_headers?.headers ?? {};
  const candidates: string[] = [
    integrity.user_agent ?? "",
    headers[UA_HEADER_KEY] ?? "",
  ];
  const device = integrity.device as
    | { workerScope?: { scopes?: Record<string, { userAgent?: unknown }> } }
    | undefined;
  for (const scope of Object.values(device?.workerScope?.scopes ?? {})) {
    if (typeof scope?.userAgent === "string") candidates.push(scope.userAgent);
  }
  return candidates.some((ua) => /iPhone|iPad|iPod|Android|Mobile/i.test(ua));
}

function weakHeadlessScore(headless: HeadlessSignals | undefined): number {
  const likeHeadless = headless?.likeHeadless;
  if (!likeHeadless) return headless?.likeHeadlessRating ?? 0;

  const values = Object.entries(likeHeadless).filter(
    ([key, value]) => key !== "noTaskbar" && typeof value === "boolean",
  );
  if (values.length === 0) return headless?.likeHeadlessRating ?? 0;

  const trueCount = values.filter(([, value]) => value === true).length;
  return +((trueCount / values.length) * 100).toFixed(0);
}

function hasCdpProtoProxyTrap(headless: HeadlessSignals | undefined): boolean {
  const cdp = headless?.cdp;
  return (
    cdp?.consoleTiming?.cdp_proto_proxy_trap === true ||
    cdp?.consoleTimingWorker?.cdp_proto_proxy_trap === true
  );
}

function hasHardCdpResidue(headless: HeadlessSignals | undefined): boolean {
  const cdp = headless?.cdp;
  if (!cdp) return false;
  if ((cdp.consoleTimingWorker?.console_lies ?? 0) > 0) return true;
  return (
    cdp.cdcGlobals === true ||
    cdp.pwBindings === true ||
    (cdp.automationGlobals?.length ?? 0) > 0 ||
    (cdp.clientLitter?.length ?? 0) > 0 ||
    cdp.ownPropsNative === false
  );
}

function hasSoftCdpResidue(headless: HeadlessSignals | undefined): boolean {
  const cdp = headless?.cdp;
  return (
    cdp?.phantomMismatch === true || (cdp?.crossRealmTampered?.length ?? 0) > 0
  );
}

/**
 * The iframe was created but nested WebCrypto never responded. This is the
 * Marionette/Camoufox liveness signature; creation failure alone is ignored.
 */
export function hasIframeCryptoStuck(
  integrity: IntegrityResultsData | undefined,
): boolean {
  const iframeCrypto = (
    integrity?.device as
      | {
          status?: {
            iframeCrypto?: {
              responsive?: boolean;
              iframe_created?: boolean;
            };
          };
        }
      | undefined
  )?.status?.iframeCrypto;
  return (
    iframeCrypto?.iframe_created === true && iframeCrypto.responsive === false
  );
}

function hasPristineLiftCompromised(
  integrity: IntegrityResultsData | undefined,
): boolean {
  const pristine = (
    integrity?.device as
      | {
          status?: {
            pristine?: {
              lifted?: boolean;
              getRandomValuesNativeSource?: string | null;
            };
          };
        }
      | undefined
  )?.status?.pristine;
  if (!pristine) return false;
  if (pristine.lifted === false) return true;
  return (
    pristine.lifted === true && pristine.getRandomValuesNativeSource === null
  );
}

/** Max-composed strict, CDP, iframe-liveness, and pristine-lift evidence. */
function cdpAutomationScore(
  input: MerchantProjectionInput,
  headless: HeadlessSignals | undefined,
): number {
  const isMobile = isMobileBrowser(input.integrity);
  const timingScore = desktopCdpTimingScore(headless, isMobile);
  if (hasIframeCryptoStuck(input.integrity)) return 100;
  if (hasHardCdpResidue(headless)) return 100;
  if (hasErrorStackBurstSignal(headless?.cdp?.consoleTimingWorker)) return 75;
  if (timingScore === 75) return 75;
  if (hasSoftCdpResidue(headless)) return 75;
  if (hasPristineLiftCompromised(input.integrity)) return 75;
  if (hasCdpProtoProxyTrap(headless)) return CDP_SUSPECT_TIER;
  return timingScore;
}

/** Return the raw automation-axis percentage before PAT trust adjustment. */
export function automationProbability(input: MerchantProjectionInput): number {
  const headless = readHeadless(
    input.integrity ?? ({} as IntegrityResultsData),
  );
  const strictScore = (headless?.headlessRating ?? 0) > 0 ? 100 : 0;
  const hardScore = Math.max(strictScore, cdpAutomationScore(input, headless));
  if (hardScore > 0) return hardScore;

  const isMobile = isMobileBrowser(input.integrity);
  const stealth = isMobile ? 0 : (headless?.stealthRating ?? 0);
  const weak = isMobile ? 0 : weakHeadlessScore(headless);
  return roundProbability(weak + (stealth > 0 ? 20 : 0));
}
