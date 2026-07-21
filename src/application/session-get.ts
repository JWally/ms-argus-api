import type { DecrementResult } from "../helpers/credits";
import type { MerchantSafeResponse } from "../helpers/merchant-projection";
import type { IntegrityResultsData } from "../helpers/payload-schema";
import type {
  SdkAttestation,
  SdkAttestationVerifyResult,
} from "../helpers/sdk-attestation";
import type { VerifiedClaims } from "../helpers/token-verifier";

type VerifiedAttestation = Extract<SdkAttestationVerifyResult, { ok: true }>;

interface VerifyMerchantOptions {
  ssmPubkeyPath: string;
  expectedCpi: string;
}

interface VerifyAttestationOptions {
  expectedPurpose: string;
  expectedCpi: string;
  expectedSessionId: string;
}

export interface SessionGetPorts {
  verifyMerchant: (
    apiKey: string | undefined,
    merchantToken: string | undefined,
    options: VerifyMerchantOptions,
  ) => Promise<VerifiedClaims | null>;
  verifyAttestation: (
    attestation: SdkAttestation,
    options: VerifyAttestationOptions,
  ) => SdkAttestationVerifyResult;
  debitCredit: (merchantId: string) => Promise<DecrementResult>;
  fetchIntegrity: (
    cpi: string,
    sessionId: string,
  ) => Promise<IntegrityResultsData | undefined>;
  buildProjection: (input: {
    session_id: string;
    integrity: IntegrityResultsData;
  }) => MerchantSafeResponse;
  now: () => number;
  recordMetric: (name: string) => void;
  logTiming: (timing: SessionGetTiming) => void;
}

export interface SessionGetRequest {
  cpi: string;
  sessionId: string;
  apiKey?: string;
  merchantToken?: string;
  attestation?: SdkAttestation;
}

interface SessionGetTiming {
  authMs: number;
  attestMs: number;
  debitMs: number;
  fetchMs: number;
  projectMs: number;
  totalMs: number;
}

export type SessionGetResult =
  | { kind: "verifier_misconfigured" }
  | { kind: "unauthorized" }
  | { kind: "invalid_attestation"; reason: string }
  | { kind: "insufficient_credits" }
  | { kind: "not_found" }
  | {
      kind: "ok";
      projection: MerchantSafeResponse;
      creditsRemaining: number;
      attestation?: VerifiedAttestation;
    };

interface SessionGetConfig {
  ssmPubkeyPath?: string;
  ports: SessionGetPorts;
}

async function authorize(
  request: SessionGetRequest,
  config: SessionGetConfig,
): Promise<VerifiedClaims | SessionGetResult> {
  if (!config.ssmPubkeyPath) return { kind: "verifier_misconfigured" };
  const claims = await config.ports.verifyMerchant(
    request.apiKey,
    request.merchantToken,
    {
      ssmPubkeyPath: config.ssmPubkeyPath,
      expectedCpi: request.cpi,
    },
  );
  if (!claims) {
    config.ports.recordMetric("MerchantTokenRejected");
    return { kind: "unauthorized" };
  }
  config.ports.recordMetric("MerchantTokenAccepted");
  return claims;
}

function verifyOptionalAttestation(
  request: SessionGetRequest,
  ports: SessionGetPorts,
): VerifiedAttestation | SessionGetResult | undefined {
  if (!request.attestation) return undefined;
  const result = ports.verifyAttestation(request.attestation, {
    expectedPurpose: "argus-session-get-v1",
    expectedCpi: request.cpi,
    expectedSessionId: request.sessionId,
  });
  if (!result.ok) {
    ports.recordMetric("SdkAttestationRejected");
    return { kind: "invalid_attestation", reason: result.reason };
  }
  ports.recordMetric("SdkAttestationAccepted");
  return result;
}

function isSessionGetResult(
  value: VerifiedClaims | VerifiedAttestation | SessionGetResult | undefined,
): value is SessionGetResult {
  return !!value && "kind" in value;
}

function bindAttestationToScan(
  attestation: VerifiedAttestation | undefined,
  integrity: IntegrityResultsData,
): SessionGetResult | undefined {
  if (!attestation) return undefined;
  const storedPublicKey = integrity.identification?.pubkey;
  if (!storedPublicKey) {
    return {
      kind: "invalid_attestation",
      reason: "stored_public_key_missing",
    };
  }
  if (storedPublicKey !== attestation.publicKey) {
    return { kind: "invalid_attestation", reason: "public_key_mismatch" };
  }
  return undefined;
}

function buildTiming(marks: number[]): SessionGetTiming {
  const [start, auth, attest, debit, fetch, project] = marks;
  return {
    authMs: Math.round(auth - start),
    attestMs: Math.round(attest - auth),
    debitMs: Math.round(debit - attest),
    fetchMs: Math.round(fetch - debit),
    projectMs: Math.round(project - fetch),
    totalMs: Math.round(project - start),
  };
}

export function createSessionGet(config: SessionGetConfig) {
  return async (request: SessionGetRequest): Promise<SessionGetResult> => {
    const marks = [config.ports.now()];
    const claims = await authorize(request, config);
    if (isSessionGetResult(claims)) return claims;
    marks.push(config.ports.now());
    const attestation = verifyOptionalAttestation(request, config.ports);
    if (isSessionGetResult(attestation)) return attestation;
    marks.push(config.ports.now());
    const debit = await config.ports.debitCredit(claims.merchantId);
    if (!debit.ok) {
      config.ports.recordMetric("InsufficientCredits");
      return { kind: "insufficient_credits" };
    }
    config.ports.recordMetric("CreditBurned");
    marks.push(config.ports.now());
    const integrity = await config.ports.fetchIntegrity(
      request.cpi,
      request.sessionId,
    );
    marks.push(config.ports.now());
    if (!integrity) return { kind: "not_found" };
    const bindingFailure = bindAttestationToScan(attestation, integrity);
    if (bindingFailure) return bindingFailure;
    config.ports.recordMetric("IntegritySessionRetrieved");
    const projection = config.ports.buildProjection({
      session_id: request.sessionId,
      integrity,
    });
    marks.push(config.ports.now());
    config.ports.logTiming(buildTiming(marks));
    return {
      kind: "ok",
      projection,
      creditsRemaining: debit.remaining,
      ...(attestation ? { attestation } : {}),
    };
  };
}
