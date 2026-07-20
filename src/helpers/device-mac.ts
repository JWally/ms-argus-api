/**
 * Server companion for the SDK's device.mac chain (see
 * ms-argus-web-integrity scripts/vm-src/main.ts on the
 * defense/hmac-chain branch).
 *
 * The SDK computes:
 *
 *   material = sessionToken \0 sigintTls \0 sigintTcpToken \0 sigintH2Token
 *              \0 devicePubkey               (empty parts omitted)
 *   key      = HMAC-MD5(BUILD_SALT, material)
 *   absorb   = for each of 23 slices in fixed order:
 *                buf += BE32(sliceId) || stringify(device[name])
 *   mac      = HMAC-MD5(key, absorb)   → 32-hex string in device.mac
 *
 * HMAC-MD5 chosen over HMAC-SHA-256 for bytecode tractability (4 state
 * words + no message schedule vs 8 + 64-word expansion). MD5's collision
 * attacks don't apply: attacker has no chosen-message oracle and no key,
 * so RFC 6151 §2 "still suitable for HMAC" applies.
 *
 * This module replays the same chain over a received payload and returns
 * 'absent' | 'ok' | 'mismatch'. The caller rejects both missing and invalid
 * MACs; only the current 23-slice chain is accepted.
 *
 * BUILD_SALT, slice order, key material order, and skip-empty rule MUST
 * stay in lockstep with the SDK. Rotate them per release.
 */

import { createHmac } from "crypto";

/** Must match BUILD_SALT in ms-argus-web-integrity scripts/vm-src/main.ts. */
const BUILD_SALT = Buffer.from([
  0x9c, 0x2f, 0xa1, 0x7b, 0x4e, 0xd3, 0x68, 0x05,
]);

/**
 * Slice absorb order — must match computeDeviceMac in the SDK's bytecode.
 * The ID is what the SDK absorbs as the 4-byte BE prefix; the `name` is
 * the device.* property name we read on the server.
 */
const SLICE_ORDER: ReadonlyArray<{ id: number; name: string }> = [
  { id: 0x50, name: "css" },
  { id: 0x51, name: "engine" },
  { id: 0x52, name: "math" },
  { id: 0x53, name: "headless" },
  { id: 0x54, name: "lies" },
  { id: 0x55, name: "trash" },
  { id: 0x56, name: "shielding" },
  { id: 0x57, name: "incognito" },
  { id: 0x58, name: "intl" },
  { id: 0x59, name: "navigator" },
  { id: 0x5a, name: "screen" },
  { id: 0x5b, name: "status" },
  { id: 0x5c, name: "timezone" },
  { id: 0x5d, name: "timing" },
  { id: 0x5e, name: "cssMedia" },
  { id: 0x5f, name: "webrtc" },
  { id: 0x60, name: "windowPrefixes" },
  { id: 0x61, name: "workerScope" },
  { id: 0x62, name: "errors" },
  { id: 0x63, name: "canvas" },
  { id: 0x64, name: "audio" },
  { id: 0x65, name: "fonts" },
  // Worker-collected self-attestation. SDK (ms-argus-web-integrity
  // defense/worker-isolation) populates this inside the dedicated VM
  // worker by reading self.navigator + self.performance + the toString
  // of self.crypto.getRandomValues. Anchors the iframe-supplied
  // device.navigator slice against the worker's own observation:
  // analyzer can compare device.navigator.userAgent vs
  // device.worker_attest.ua to surface postMessage-substitution.
  { id: 0x66, name: "worker_attest" },
];

/**
 * Reimplementation of the SDK's bytecode-native JSON walker. Node's
 * built-in JSON.stringify is byte-equivalent for the content the SDK
 * collects (no surrogates, no 0x2028/0x2029, no functions, no symbols),
 * so we delegate. If the walker drifts in a future revision, this is
 * the one place to mirror the change.
 *
 * Order of keys: V8's Object.keys gives insertion order for non-numeric
 * string keys. JSON.parse on the wire preserves insertion order. So
 * stringify(parsedSlice) replays the same order the SDK serialized.
 */
// Deliberate seam, not indirection: the documented one-place hook where the
// server's replay of the SDK's slice serialization gets mirrored if the SDK
// walker ever drifts.
// nosemgrep: semgrep.no-wrapper-function
function canonicalStringify(value: unknown): string {
  return JSON.stringify(value);
}

/**
 * Build the absorb buffer that the SDK HMACs.
 *
 * Returns the concatenation of [BE32(sliceId) || utf8(stringify(slice))]
 * for each slice in SLICE_ORDER. Missing slices are stringified as
 * "undefined" → walker emits "null", same as the SDK side.
 */
/**
 * Convert a JS string to bytes by truncating each UTF-16 code unit to its
 * low 8 bits. Mirrors the bytecode's `s.charCodeAt(i) & 0xff` per-char
 * loop in macAbsorb. This is LOSSY for non-ASCII (BMP chars > 0xFF or
 * surrogates lose their high bits) but MUST match exactly because the
 * MAC is computed over these bytes.
 *
 * Trade-off: an attacker substituting non-ASCII content with same-low-byte
 * unicode (e.g., "中" 0x4E2D → "-" 0x002D, both low-byte 0x2D) bypasses
 * the MAC. Mitigation: device payload is overwhelmingly ASCII; substituting
 * fields to be useful as an exploit requires injecting non-collision bytes
 * (UA strings, JSON keys). Acceptable for current attack model. Fix path
 * if needed later: ship a UTF-8 encoder in the bytecode (raises register
 * pressure ~10 regs).
 */
function strToLowByteBuffer(s: string): Buffer {
  const out = Buffer.alloc(s.length);
  for (let i = 0; i < s.length; i++) {
    out[i] = s.charCodeAt(i) & 0xff;
  }
  return out;
}

/**
 * Build the MAC-key material in the fixed (bytecode-private) order:
 *   sessionToken, sigintTls, sigintTcpToken, sigintH2Token, devicePubkey
 * Empty/missing parts are omitted (SDK applies same skip rule). The
 * separator is 0x00 — none of these values can contain a raw null.
 */
function buildKeyMaterial(opts: {
  sessionToken: string;
  sigintTls: string;
  sigintTcpToken: string;
  sigintH2Token: string;
  devicePubkey: string;
}): Buffer {
  const parts: string[] = [opts.sessionToken];
  if (opts.sigintTls.length > 0) parts.push(opts.sigintTls);
  if (opts.sigintTcpToken.length > 0) parts.push(opts.sigintTcpToken);
  if (opts.sigintH2Token.length > 0) parts.push(opts.sigintH2Token);
  if (opts.devicePubkey.length > 0) parts.push(opts.devicePubkey);
  return strToLowByteBuffer(parts.join(String.fromCharCode(0)));
}

export type DeviceMacOutcome =
  | { kind: "absent" }
  | { kind: "ok" }
  | { kind: "mismatch"; expected: string; received: string };

export type DeviceMacRejectionReason =
  | "device_mac_required"
  | "device_mac_mismatch";

/** Map verification into the ingestion boundary's fail-closed policy. */
export function deviceMacRejectionReason(
  outcome: DeviceMacOutcome,
): DeviceMacRejectionReason | null {
  if (outcome.kind === "absent") return "device_mac_required";
  if (outcome.kind === "mismatch") return "device_mac_mismatch";
  return null;
}

/**
 * Verify the device.mac field on a received integrity payload.
 *
 * Three outcomes:
 *  - 'absent'   — device, worker attestation, or device.mac not present.
 *                 Caller rejects.
 *  - 'ok'       — MAC matches expected. Payload integrity confirmed.
 *  - 'mismatch' — MAC present but doesn't match. Tampering. Caller
 *                 should reject hard (tier-100 device_tampering).
 *
 * Comparison is case-insensitive hex. We don't use timingSafeEqual
 * because the MAC isn't a secret on the wire — both sides can derive
 * it from publicly-observable inputs once they know the bytecode-private
 * salt + order. Constant-time compare is unnecessary.
 */
/**
 * Extract the parts of the payload that feed the MAC computation. Split
 * out of verifyDeviceMac to keep that function under the complexity cap.
 * Returns null when the payload shape disqualifies it from verification
 * (no current worker attestation or device.mac field) — caller maps to
 * 'absent'.
 */
interface MacInputs {
  device: Record<string, unknown>;
  received: string;
  sigintTls: string;
  sigintTcpToken: string;
  sigintH2Token: string;
  devicePubkey: string;
}

function optStr(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function extractMacInputs(payload: unknown): MacInputs | null {
  if (!payload || typeof payload !== "object") return null;
  const p = payload as Record<string, unknown>;
  const device = p.device as Record<string, unknown> | undefined;
  if (!device || typeof device !== "object") return null;
  if (!device.worker_attest || typeof device.worker_attest !== "object") {
    return null;
  }
  const received = device.mac;
  if (typeof received !== "string" || received.length === 0) return null;
  const deviceIdentity = p.device_identity as { pubkey?: unknown } | undefined;
  return {
    device,
    received,
    sigintTls: optStr(p.sigintTls),
    sigintTcpToken: optStr(p.sigintTcpToken),
    sigintH2Token: optStr(p.sigintH2Token),
    devicePubkey: optStr(deviceIdentity?.pubkey),
  };
}

function computeMac(device: Record<string, unknown>, key: Buffer): string {
  const chunks: Buffer[] = [];
  for (const { id, name } of SLICE_ORDER) {
    const idBuf = Buffer.alloc(4);
    idBuf.writeUInt32BE(id, 0);
    chunks.push(idBuf);
    const v = device[name];
    const serialized = v === undefined ? "null" : canonicalStringify(v);
    chunks.push(strToLowByteBuffer(serialized ?? "null"));
  }
  const absorb = Buffer.concat(chunks);
  return createHmac("md5", key).update(absorb).digest("hex").toLowerCase();
}

export function verifyDeviceMac(
  payload: unknown,
  opts: { sessionToken: string },
): DeviceMacOutcome {
  const inputs = extractMacInputs(payload);
  if (!inputs) return { kind: "absent" };

  const material = buildKeyMaterial({
    sessionToken: opts.sessionToken,
    sigintTls: inputs.sigintTls,
    sigintTcpToken: inputs.sigintTcpToken,
    sigintH2Token: inputs.sigintH2Token,
    devicePubkey: inputs.devicePubkey,
  });
  const key = createHmac("md5", BUILD_SALT).update(material).digest();
  const received = inputs.received.toLowerCase();

  const expected = computeMac(inputs.device, key);
  if (expected === received) return { kind: "ok" };

  return { kind: "mismatch", expected, received };
}
