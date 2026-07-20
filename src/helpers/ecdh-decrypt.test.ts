import { describe, it, expect, beforeAll } from "vitest";
import { deflateRawSync } from "node:zlib";
import { webcrypto } from "node:crypto";
import { deriveAndUnscramble, decryptArgusPayload } from "./ecdh-decrypt";
import type { EcdhKeys } from "./get-ecdh-keys";

const subtle = webcrypto.subtle;
const HKDF_INFO = new TextEncoder().encode("argus-web-v1");

describe("deriveAndUnscramble (v3 Fibonacci)", () => {
  /**
   * Mirror of the client VM's Fibonacci-modulated XOR scramble.
   * Client XORs at the string character level, then TextEncoder.encode produces UTF-8.
   * Server receives UTF-8 after inflate, must reverse at string level too.
   */
  function scramble(plaintext: string, sessionToken: string): Buffer {
    let scrambled = "";
    let fib0 = 1;
    let fib1 = 1;
    for (let i = 0; i < plaintext.length; i++) {
      const t = sessionToken.charCodeAt(i % sessionToken.length);
      const f = fib1 % 256;
      scrambled += String.fromCharCode(plaintext.charCodeAt(i) ^ (t ^ f));
      const fib2 = fib0 + fib1;
      fib0 = fib1;
      fib1 = fib2;
      if (fib1 > 1000000) {
        fib0 = 1;
        fib1 = 1;
      }
    }
    return Buffer.from(scrambled, "utf-8");
  }

  it("round-trips a simple payload", () => {
    const token = "abc123def456";
    const plaintext = '{"hello":"world"}';
    const scrambled = scramble(plaintext, token);
    const result = deriveAndUnscramble(scrambled, token);
    expect(result.toString("utf-8")).toBe(plaintext);
  });

  it("round-trips a payload longer than the token", () => {
    const token = "short";
    const plaintext = "a]".repeat(500);
    const scrambled = scramble(plaintext, token);
    const result = deriveAndUnscramble(scrambled, token);
    expect(result.toString("utf-8")).toBe(plaintext);
  });

  it("handles Fibonacci reset at 1M boundary", () => {
    // Generate a payload long enough that Fibonacci exceeds 1M
    // Fibonacci reaches 1M around index 30 (fib(30) = 1346269 > 1M)
    // After reset, the sequence restarts — verify consistency
    const token = "test-token";
    const plaintext = "x".repeat(100);
    const scrambled = scramble(plaintext, token);
    const result = deriveAndUnscramble(scrambled, token);
    expect(result.toString("utf-8")).toBe(plaintext);
  });

  it("uses different key bytes for each position (not just repeating token)", () => {
    const token = "A"; // Single char token
    const plaintext = "AAAA";
    const scrambled = scramble(plaintext, token);

    // If it were simple XOR with just the token char, all bytes would be identical
    // Fibonacci modulation means each byte is XOR'd with a different value
    const bytes = [...scrambled];
    const allSame = bytes.every((b) => b === bytes[0]);
    expect(allSame).toBe(false);
  });
});

/**
 * End-to-end decrypt with a real ephemeral P-256 keypair, exercising the
 * shared decryptEcdh core and the zip-bomb bound (maxOutputLength on inflate).
 * The client-side encryption here mirrors deriveAesKey exactly: ECDH shared
 * secret → HKDF-SHA256(salt=UTCdate, info="argus-web-v1") → AES-256-GCM.
 */
describe("decryptArgusPayload — bounded inflate (zip-bomb defense)", () => {
  let serverKeys: EcdhKeys;
  let clientPrivateKey: CryptoKey;
  let serverPublicKey: CryptoKey;
  let clientRawPubB64: string;

  const b64 = (b: ArrayBuffer | Uint8Array) =>
    Buffer.from(b as ArrayBuffer).toString("base64");
  const todaySalt = () => new Date().toISOString().slice(0, 10);

  /** Reproduce deriveAesKey's client half: ECDH(clientPriv, serverPub) → HKDF → AES-GCM. */
  async function deriveClientAesKey(dateSalt: string): Promise<CryptoKey> {
    const sharedBits = await subtle.deriveBits(
      { name: "ECDH", public: serverPublicKey },
      clientPrivateKey,
      256,
    );
    const hkdfKey = await subtle.importKey("raw", sharedBits, "HKDF", false, [
      "deriveKey",
    ]);
    return subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new TextEncoder().encode(dateSalt),
        info: HKDF_INFO,
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"],
    );
  }

  /** Pack a generic collect payload: deflateRaw → AES-GCM → base64. */
  async function seal(plaintext: string): Promise<string> {
    const aesKey = await deriveClientAesKey(todaySalt());
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      deflateRawSync(Buffer.from(plaintext, "utf-8")),
    );
    return Buffer.concat([Buffer.from(iv), Buffer.from(ct)]).toString("base64");
  }

  beforeAll(async () => {
    const server = await subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    );
    const client = await subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    );
    clientPrivateKey = client.privateKey;
    serverPublicKey = server.publicKey;
    clientRawPubB64 = b64(await subtle.exportKey("raw", client.publicKey));
    serverKeys = {
      current: {
        privateKey: b64(await subtle.exportKey("pkcs8", server.privateKey)),
        publicKey: b64(await subtle.exportKey("spki", server.publicKey)),
        rawPublicKey: b64(await subtle.exportKey("raw", server.publicKey)),
        createdAt: 0,
      },
    };
  });

  it("decrypts a normal payload that inflates under the cap", async () => {
    const body = await seal(JSON.stringify({ hello: "world", n: 42 }));
    const result = await decryptArgusPayload(
      body,
      true,
      clientRawPubB64,
      serverKeys,
    );
    expect(result).toEqual({ hello: "world", n: 42 });
  });

  it("returns null for a deflate bomb that inflates past the cap", async () => {
    // 8MB of highly-compressible input → tiny ciphertext, but inflates well
    // past MAX_INFLATED_BYTES (2MB default). inflateRawSync throws RangeError,
    // which the per-key try/catch swallows → decrypt returns null → HTTP 400.
    const bomb = "A".repeat(8 * 1024 * 1024);
    const body = await seal(bomb);
    const result = await decryptArgusPayload(
      body,
      true,
      clientRawPubB64,
      serverKeys,
    );
    expect(result).toBeNull();
  });

  it("returns null on a wrong client pubkey (auth-tag failure)", async () => {
    const body = await seal(JSON.stringify({ ok: true }));
    // A different, unrelated raw pubkey → ECDH yields a different secret →
    // AES-GCM tag fails → null.
    const other = await subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    );
    const otherRawPub = b64(await subtle.exportKey("raw", other.publicKey));
    const result = await decryptArgusPayload(
      body,
      true,
      otherRawPub,
      serverKeys,
    );
    expect(result).toBeNull();
  });
});
