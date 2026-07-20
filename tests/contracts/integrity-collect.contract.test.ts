import { webcrypto } from "node:crypto";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import type { Metrics } from "@aws-lambda-powertools/metrics";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import contract from "../../contracts/integrity-collect/v1/transport.json";

const keyBoundary = vi.hoisted(() => ({ getEcdhKeys: vi.fn() }));

vi.mock("../../src/helpers/get-ecdh-keys", () => ({
  getEcdhKeys: (...args: unknown[]) => keyBoundary.getEcdhKeys(...args),
}));

import { binaryGzipBodyParser } from "../../src/handlers/ingestion/middleware";

const subtle = webcrypto.subtle;
const SESSION_TOKEN = "contract-session-token";
const HKDF_INFO = new TextEncoder().encode("argus-web-v1");
const config = {
  maxBodyBytes: 256 * 1024,
  maxDecompressedBytes: 2 * 1024 * 1024,
};
const payload = {
  identifiers: {
    session_id: "integrity-contract-session",
    cpi: "argus_cpi_test_contract12345",
  },
  hashes: { stable: "stable-contract", fuzzy: "fuzzy-contract" },
  device: { navigator: { userAgent: "Argus contract client" } },
};

const metrics = {
  addMetric: vi.fn(),
} as unknown as Metrics;

let clientPrivateKey: CryptoKey;
let clientPublicKeyB64: string;
let serverPublicKey: CryptoKey;

function fibonacciScramble(plaintext: string, sessionToken: string): Buffer {
  let scrambled = "";
  let fib0 = 1;
  let fib1 = 1;
  for (let index = 0; index < plaintext.length; index++) {
    const tokenCode = sessionToken.charCodeAt(index % sessionToken.length);
    scrambled += String.fromCharCode(
      plaintext.charCodeAt(index) ^ (tokenCode ^ (fib1 % 256)),
    );
    const next = fib0 + fib1;
    fib0 = fib1;
    fib1 = next;
    if (fib1 > 1_000_000) {
      fib0 = 1;
      fib1 = 1;
    }
  }
  return Buffer.from(scrambled, "utf8");
}

async function deriveClientAesKey(): Promise<CryptoKey> {
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
      salt: new TextEncoder().encode(new Date().toISOString().slice(0, 10)),
      info: HKDF_INFO,
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
}

async function seal(): Promise<string> {
  const plaintext = fibonacciScramble(JSON.stringify(payload), SESSION_TOKEN);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv },
    await deriveClientAesKey(),
    plaintext,
  );
  return Buffer.concat([Buffer.from(iv), Buffer.from(ciphertext)]).toString(
    "base64",
  );
}

async function requestFor(): Promise<APIGatewayProxyEventV2> {
  return {
    version: "2.0",
    routeKey: `${contract.method} ${contract.path}`,
    rawPath: contract.path,
    rawQueryString: "",
    headers: {
      "content-type": contract.content_type,
      "x-argus-origin": clientPublicKeyB64,
      "x-argus-session": SESSION_TOKEN,
      "x-argus-v": contract.current_client_version,
    },
    requestContext: {
      accountId: "000000000000",
      apiId: "contract",
      domainName: "contract.invalid",
      domainPrefix: "contract",
      http: {
        method: contract.method,
        path: contract.path,
        protocol: "HTTP/1.1",
        sourceIp: "203.0.113.20",
        userAgent: "Argus contract client",
      },
      requestId: "contract-request",
      routeKey: `${contract.method} ${contract.path}`,
      stage: "$default",
      time: "01/Jan/2026:00:00:00 +0000",
      timeEpoch: Date.now(),
    },
    body: await seal(),
    isBase64Encoded: true,
  };
}

async function replay(event: APIGatewayProxyEventV2): Promise<void> {
  const middleware = binaryGzipBodyParser(config, metrics);
  await middleware.before?.({ event } as never);
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
  serverPublicKey = server.publicKey;
  clientPrivateKey = client.privateKey;
  clientPublicKeyB64 = Buffer.from(
    await subtle.exportKey("raw", client.publicKey),
  ).toString("base64");
  keyBoundary.getEcdhKeys.mockResolvedValue({
    current: {
      privateKey: Buffer.from(
        await subtle.exportKey("pkcs8", server.privateKey),
      ).toString("base64"),
      publicKey: Buffer.from(
        await subtle.exportKey("spki", server.publicKey),
      ).toString("base64"),
      rawPublicKey: Buffer.from(
        await subtle.exportKey("raw", server.publicKey),
      ).toString("base64"),
      createdAt: Date.now(),
    },
  });
});

beforeEach(() => {
  vi.mocked(metrics.addMetric).mockClear();
});

describe("integrity collect provider contract", () => {
  it(`decrypts current wire version ${contract.current_client_version}`, async () => {
    const event = await requestFor();

    await replay(event);

    expect(JSON.parse(event.body ?? "{}")).toEqual(payload);
    expect(event.isBase64Encoded).toBe(false);
  });

  for (const negative of contract.negative_cases) {
    it(`rejects ${negative.name}`, async () => {
      const event = await requestFor();
      if (negative.mutation === "content-type") {
        event.headers["content-type"] = negative.value;
      } else if (negative.mutation === "remove-origin") {
        delete event.headers["x-argus-origin"];
      } else if (negative.mutation === "remove-session") {
        delete event.headers["x-argus-session"];
      } else if (negative.mutation === "remove-version") {
        delete event.headers["x-argus-v"];
      } else if (negative.mutation === "version") {
        event.headers["x-argus-v"] = negative.value;
      }

      await expect(replay(event)).rejects.toMatchObject({
        statusCode: negative.expected_status,
      });
    });
  }
});
