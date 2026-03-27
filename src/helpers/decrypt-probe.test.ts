import { describe, it, expect } from "vitest";
import { createCipheriv, randomBytes } from "crypto";
import {
  isEncryptedResponse,
  decryptProbeResponse,
  type EncryptedResponse,
} from "./decrypt-probe";

const TEST_KEY_HEX = "a".repeat(64); // 32 bytes of 0xaa

function encrypt(data: unknown, keyHex: string): EncryptedResponse {
  const key = Buffer.from(keyHex, "hex");
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const plaintext = Buffer.from(JSON.stringify(data), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const combined = Buffer.concat([nonce, ciphertext, tag]);
  return { v: 1, data: combined.toString("base64") };
}

describe("isEncryptedResponse", () => {
  it("returns true for valid encrypted response shape", () => {
    expect(isEncryptedResponse({ v: 1, data: "abc123" })).toBe(true);
  });

  it("returns false for plain probe response", () => {
    expect(isEncryptedResponse({ tcp_info: null, rtt_fingerprint: null })).toBe(
      false,
    );
  });

  it("returns false for null", () => {
    expect(isEncryptedResponse(null)).toBe(false);
  });

  it("returns false for missing data field", () => {
    expect(isEncryptedResponse({ v: 1 })).toBe(false);
  });

  it("returns false for wrong data type", () => {
    expect(isEncryptedResponse({ v: 1, data: 123 })).toBe(false);
  });

  it("returns false for missing v field", () => {
    expect(isEncryptedResponse({ data: "abc" })).toBe(false);
  });

  it("returns false for non-number v", () => {
    expect(isEncryptedResponse({ v: "1", data: "abc" })).toBe(false);
  });
});

describe("decryptProbeResponse", () => {
  it("decrypts and parses a tcp probe response", () => {
    const original = {
      tcp_info: { rtt: 12000 },
      rtt_fingerprint: { tcp_rtt_us: 12000, snd_mss: 1460 },
      client_ip: "1.2.3.4",
      domain: "test.io",
    };
    const encrypted = encrypt(original, TEST_KEY_HEX);
    const result = decryptProbeResponse(encrypted, TEST_KEY_HEX);
    expect(result).toEqual(original);
  });

  it("decrypts and parses an h2 probe response", () => {
    const original = {
      h2_fingerprint: {
        fingerprint: "1:65536;3:1000;4:6291456|15663105|0|m,p,a,s",
      },
      client_ip: "5.6.7.8",
      domain: "test.io",
    };
    const encrypted = encrypt(original, TEST_KEY_HEX);
    const result = decryptProbeResponse(encrypted, TEST_KEY_HEX);
    expect(result).toEqual(original);
  });

  it("throws on wrong key", () => {
    const original = { foo: "bar" };
    const encrypted = encrypt(original, TEST_KEY_HEX);
    const wrongKey = "b".repeat(64);
    expect(() => decryptProbeResponse(encrypted, wrongKey)).toThrow();
  });

  it("throws on tampered ciphertext", () => {
    const encrypted = encrypt({ foo: "bar" }, TEST_KEY_HEX);
    const buf = Buffer.from(encrypted.data, "base64");
    // Flip a byte in the ciphertext region
    buf[15] ^= 0xff;
    const tampered: EncryptedResponse = {
      v: 1,
      data: buf.toString("base64"),
    };
    expect(() => decryptProbeResponse(tampered, TEST_KEY_HEX)).toThrow();
  });
});
