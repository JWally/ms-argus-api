import { createHash, createPublicKey, createVerify } from "node:crypto";

const CLOCK_SKEW_SECONDS = 30;
const MAX_ENVELOPE_BYTES = 8 * 1024;

export interface SdkAttestation {
  envelope: string;
  signature: string;
  publicKey: string;
  keyId: string;
}

interface VerifyOptions {
  expectedPurpose: string;
  expectedCpi: string;
  expectedSessionId: string;
}

interface SdkEnvelope {
  v: number;
  purpose: string;
  payload: Record<string, unknown>;
  iat: number;
  exp: number;
  keyId: string;
}

type VerifyOk = {
  ok: true;
  keyId: string;
  publicKey: string;
  payload: Record<string, unknown>;
};

type VerifyFail = {
  ok: false;
  reason: string;
};

export type SdkAttestationVerifyResult = VerifyOk | VerifyFail;

export function parseSdkAttestationHeaders(
  headers: Record<string, string | undefined> | undefined,
): SdkAttestation | null {
  const envelope = getHeader(headers, "x-argus-attest-envelope");
  const signature = getHeader(headers, "x-argus-attest-signature");
  const publicKey = getHeader(headers, "x-argus-attest-public-key");
  const keyId = getHeader(headers, "x-argus-attest-key-id");
  if (!envelope && !signature && !publicKey && !keyId) return null;
  return {
    envelope: envelope ?? "",
    signature: signature ?? "",
    publicKey: publicKey ?? "",
    keyId: keyId ?? "",
  };
}

export function verifySdkAttestation(
  attestation: SdkAttestation,
  options: VerifyOptions,
): SdkAttestationVerifyResult {
  const decoded = decodeEnvelope(attestation.envelope);
  if (!decoded.ok) return decoded;
  const shape = validateEnvelope(decoded.envelope, options);
  if (!shape.ok) return shape;
  const keyCheck = validateKey(attestation, decoded.envelope);
  if (!keyCheck.ok) return keyCheck;
  const sigCheck = verifySignature(attestation);
  if (!sigCheck.ok) return sigCheck;
  return {
    ok: true,
    keyId: attestation.keyId,
    publicKey: attestation.publicKey,
    payload: decoded.envelope.payload,
  };
}

function getHeader(
  headers: Record<string, string | undefined> | undefined,
  name: string,
): string | undefined {
  if (!headers) return undefined;
  return headers[name] ?? headers[name.toLowerCase()] ?? headers[toTitle(name)];
}

function toTitle(name: string): string {
  return name
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("-");
}

function decodeEnvelope(
  envelope: string,
): { ok: true; envelope: SdkEnvelope } | VerifyFail {
  if (!envelope) return { ok: false, reason: "missing_envelope" };
  let json: string;
  try {
    const bytes = base64urlToBuffer(envelope);
    if (bytes.length > MAX_ENVELOPE_BYTES) {
      return { ok: false, reason: "envelope_too_large" };
    }
    json = bytes.toString("utf8");
  } catch {
    return { ok: false, reason: "envelope_not_base64url" };
  }
  try {
    const parsed = JSON.parse(json) as unknown;
    if (!isEnvelope(parsed)) return { ok: false, reason: "envelope_shape" };
    return { ok: true, envelope: parsed };
  } catch {
    return { ok: false, reason: "envelope_not_json" };
  }
}

function validateEnvelope(
  envelope: SdkEnvelope,
  options: VerifyOptions,
): VerifyFail | { ok: true } {
  if (envelope.v !== 1) return { ok: false, reason: "envelope_version" };
  if (envelope.purpose !== options.expectedPurpose) {
    return { ok: false, reason: "purpose_mismatch" };
  }
  const now = Math.floor(Date.now() / 1000);
  if (now < envelope.iat - CLOCK_SKEW_SECONDS) {
    return { ok: false, reason: "not_yet_valid" };
  }
  if (now > envelope.exp + CLOCK_SKEW_SECONDS) {
    return { ok: false, reason: "expired" };
  }
  if (envelope.payload.cpi !== options.expectedCpi) {
    return { ok: false, reason: "cpi_mismatch" };
  }
  if (envelope.payload.sessionId !== options.expectedSessionId) {
    return { ok: false, reason: "session_mismatch" };
  }
  return { ok: true };
}

function validateKey(
  attestation: SdkAttestation,
  envelope: SdkEnvelope,
): VerifyFail | { ok: true } {
  if (!attestation.publicKey)
    return { ok: false, reason: "missing_public_key" };
  if (!attestation.keyId) return { ok: false, reason: "missing_key_id" };
  const publicKeyBytes = Buffer.from(attestation.publicKey, "base64");
  const derivedKeyId = createHash("sha256")
    .update(publicKeyBytes)
    .digest("hex")
    .slice(0, 16);
  if (derivedKeyId !== attestation.keyId || derivedKeyId !== envelope.keyId) {
    return { ok: false, reason: "key_id_mismatch" };
  }
  return { ok: true };
}

function verifySignature(
  attestation: SdkAttestation,
): VerifyFail | { ok: true } {
  if (!attestation.signature) return { ok: false, reason: "missing_signature" };
  let signature: Buffer;
  try {
    signature = p1363ToDer(Buffer.from(attestation.signature, "base64"));
  } catch {
    return { ok: false, reason: "bad_signature" };
  }
  try {
    const publicKey = createPublicKey({
      key: Buffer.from(attestation.publicKey, "base64"),
      format: "der",
      type: "spki",
    });
    const verifier = createVerify("SHA256");
    verifier.update(attestation.envelope, "utf8");
    verifier.end();
    return verifier.verify(publicKey, signature)
      ? { ok: true }
      : { ok: false, reason: "bad_signature" };
  } catch {
    return { ok: false, reason: "bad_signature" };
  }
}

function isEnvelope(value: unknown): value is SdkEnvelope {
  if (!value || typeof value !== "object") return false;
  const o = value as Record<string, unknown>;
  return (
    typeof o.v === "number" &&
    typeof o.purpose === "string" &&
    !!o.payload &&
    typeof o.payload === "object" &&
    typeof o.iat === "number" &&
    typeof o.exp === "number" &&
    typeof o.keyId === "string"
  );
}

function base64urlToBuffer(input: string): Buffer {
  const pad = "=".repeat((4 - (input.length % 4)) % 4);
  return Buffer.from(
    input.replace(/-/g, "+").replace(/_/g, "/") + pad,
    "base64",
  );
}

function p1363ToDer(sig: Buffer): Buffer {
  if (sig.length !== 64) throw new Error("signature_shape");
  const r = derInt(sig.subarray(0, 32));
  const s = derInt(sig.subarray(32, 64));
  const seq = Buffer.concat([r, s]);
  return Buffer.concat([Buffer.from([0x30, seq.length]), seq]);
}

function derInt(bytes: Buffer): Buffer {
  let offset = 0;
  while (offset < bytes.length - 1 && bytes[offset] === 0) offset++;
  const trimmed = bytes.subarray(offset);
  const normalized =
    trimmed[0] & 0x80 ? Buffer.concat([Buffer.from([0]), trimmed]) : trimmed;
  return Buffer.concat([Buffer.from([0x02, normalized.length]), normalized]);
}
