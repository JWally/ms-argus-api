import { createDecipheriv } from "crypto";

/**
 * Encrypted probe response format produced by ms-argus-sigint probes
 * when SIGINT_AES_KEY is set. The `data` field is base64(nonce||ciphertext||tag).
 */
export interface EncryptedResponse {
  v: number;
  data: string;
}

export function isEncryptedResponse(
  value: unknown,
): value is EncryptedResponse {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as Record<string, unknown>).v === "number" &&
    typeof (value as Record<string, unknown>).data === "string"
  );
}

/**
 * AES-256-GCM decrypt a probe response.
 * Format: base64(nonce[12] || ciphertext || tag[16])
 */
export function decryptProbeResponse<T>(
  encrypted: EncryptedResponse,
  keyHex: string,
): T {
  const key = Buffer.from(keyHex, "hex");
  const buf = Buffer.from(encrypted.data, "base64");
  const nonce = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const ciphertext = buf.subarray(12, buf.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  return JSON.parse(decrypted.toString("utf8")) as T;
}
