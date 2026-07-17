/**
 * Service-level end-to-end coverage for the public Argus request path.
 *
 * Both Lambda entry points and their real Middy stacks run here. The test
 * encrypts the collect request exactly like a v3 browser client, persists the
 * resulting row through DynamoDB commands, then retrieves and projects that
 * row through session-get. AWS and the two independently-tested trust issuers
 * (probe-token redemption and merchant-token verification) are replaced by
 * deterministic in-memory adapters; the application pipeline is not mocked.
 */
import { webcrypto } from "node:crypto";
import type { Context } from "aws-lambda";
import {
  ConditionalCheckFailedException,
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
  type AttributeValue,
} from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { mockClient } from "aws-sdk-client-mock";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const boundaryMocks = vi.hoisted(() => ({
  getEcdhKeys: vi.fn(),
  redeemSigintTokens: vi.fn(),
  verifyMerchantToken: vi.fn(),
}));

vi.mock("../../src/helpers/get-ecdh-keys", () => ({
  getEcdhKeys: (...args: unknown[]) => boundaryMocks.getEcdhKeys(...args),
}));

vi.mock("../../src/helpers/redeem-sigint-tokens", () => ({
  redeemSigintTokens: (...args: unknown[]) =>
    boundaryMocks.redeemSigintTokens(...args),
  isAwsCfAuthenticallyHydrated: () => false,
}));

vi.mock("../../src/helpers/token-verifier", () => ({
  verifyMerchantToken: (...args: unknown[]) =>
    boundaryMocks.verifyMerchantToken(...args),
}));

import { handler as collectHandler } from "../../src/handlers/ingestion";
import { handler as sessionGetHandler } from "../../src/handlers/session-get";
import type { ArgusPayload } from "../../src/helpers/payload-schema";

const subtle = webcrypto.subtle;
const ddbMock = mockClient(DynamoDBClient);
const rows = new Map<string, Record<string, AttributeValue>>();
const credits = new Map<string, number>();

const CPI = "argus_cpi_test_e2eflow12345";
const SESSION_ID = "e2e-session-1";
const SESSION_TOKEN = "e2e-transport-session-token";
const MERCHANT_ID = "merchant-e2e";
const HKDF_INFO = new TextEncoder().encode("argus-web-v1");

let clientPrivateKey: CryptoKey;
let clientPublicKeyB64: string;
let serverPublicKey: CryptoKey;

function rowKey(cpi: string, sessionId: string): string {
  return `${cpi}\u0000${sessionId}`;
}

function lambdaContext(): Context {
  return {
    callbackWaitsForEmptyEventLoop: false,
    functionName: "argus-e2e",
    functionVersion: "1",
    invokedFunctionArn:
      "arn:aws:lambda:us-east-1:000000000000:function:argus-e2e",
    memoryLimitInMB: "256",
    awsRequestId: "e2e-request",
    logGroupName: "/aws/lambda/argus-e2e",
    logStreamName: "e2e",
    getRemainingTimeInMillis: () => 30_000,
    done: () => undefined,
    fail: () => undefined,
    succeed: () => undefined,
  };
}

function scrambleV3(plaintext: string, sessionToken: string): Buffer {
  let scrambled = "";
  let fib0 = 1;
  let fib1 = 1;
  for (let i = 0; i < plaintext.length; i++) {
    const tokenCode = sessionToken.charCodeAt(i % sessionToken.length);
    scrambled += String.fromCharCode(
      plaintext.charCodeAt(i) ^ (tokenCode ^ (fib1 % 256)),
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

async function sealV3(payload: ArgusPayload): Promise<string> {
  const key = await deriveClientAesKey();
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    scrambleV3(JSON.stringify(payload), SESSION_TOKEN),
  );
  return Buffer.concat([Buffer.from(iv), Buffer.from(ciphertext)]).toString(
    "base64",
  );
}

function payload(sessionId = SESSION_ID): ArgusPayload {
  return {
    identifiers: { session_id: sessionId, cpi: CPI },
    hashes: { stable: "stable-e2e", fuzzy: "fuzzy-e2e" },
    device: {
      navigator: {
        userAgent: "Mozilla/5.0 Chrome/140.0.0.0",
        userAgentParsed: "Chrome 140",
        system: "Windows 11",
      },
    },
    sigintTcpToken: "tcp-token-e2e",
    sigintH2Token: "h2-token-e2e",
    sigintTls: "tls-token-e2e",
  };
}

async function collectEvent(sessionId = SESSION_ID) {
  return {
    version: "2.0",
    routeKey: "POST /v1/integrity-collect",
    rawPath: "/v1/integrity-collect",
    rawQueryString: "",
    headers: {
      "content-type": "application/octet-stream",
      "x-argus-origin": clientPublicKeyB64,
      "x-argus-session": SESSION_TOKEN,
      "x-argus-v": "3",
      "x-argus-cpi": CPI,
      "x-forwarded-for": "203.0.113.10",
      "user-agent": "Mozilla/5.0 Chrome/140.0.0.0",
      "accept-language": "en-US,en;q=0.9",
    },
    requestContext: {
      accountId: "000000000000",
      apiId: "e2e",
      domainName: "api.e2e.invalid",
      domainPrefix: "api",
      http: {
        method: "POST",
        path: "/v1/integrity-collect",
        protocol: "HTTP/1.1",
        sourceIp: "203.0.113.10",
        userAgent: "Mozilla/5.0 Chrome/140.0.0.0",
      },
      requestId: "collect-e2e",
      routeKey: "POST /v1/integrity-collect",
      stage: "$default",
      time: "01/Jan/2026:00:00:00 +0000",
      timeEpoch: Date.now(),
    },
    body: await sealV3(payload(sessionId)),
    isBase64Encoded: true,
  };
}

function sessionEvent(
  options: { cpi?: string; token?: string } = {},
): Parameters<typeof sessionGetHandler>[0] {
  return {
    resource: "/v1/session/{cpi}/{session_id}",
    path: `/v1/session/${options.cpi ?? CPI}/${SESSION_ID}`,
    httpMethod: "GET",
    headers: {
      "x-api-key": "e2e-key-id",
      "x-argus-token": options.token ?? "valid-merchant-token",
    },
    multiValueHeaders: {},
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    pathParameters: {
      cpi: options.cpi ?? CPI,
      session_id: SESSION_ID,
    },
    stageVariables: null,
    requestContext: {},
    body: null,
    isBase64Encoded: false,
  } as unknown as Parameters<typeof sessionGetHandler>[0];
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
  boundaryMocks.getEcdhKeys.mockResolvedValue({
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
  rows.clear();
  credits.clear();
  credits.set(MERCHANT_ID, 10);
  ddbMock.reset();
  boundaryMocks.redeemSigintTokens.mockReset();
  boundaryMocks.verifyMerchantToken.mockReset();

  boundaryMocks.redeemSigintTokens.mockImplementation(
    async (raw: ArgusPayload) => ({
      ...raw,
      sigint: {
        tcp_probe: {
          client_ip: "203.0.113.10",
          rtt_fingerprint: {
            tcp_rtt_us: 15_000,
            rcv_mss: 1460,
            snd_mss: 1460,
          },
        },
        h2: { protocol: "h2", fingerprint: "e2e-h2" },
      },
    }),
  );
  boundaryMocks.verifyMerchantToken.mockImplementation(
    async (_keyId: string, token: string, opts: { expectedCpi?: string }) =>
      token === "valid-merchant-token"
        ? {
            merchantId: MERCHANT_ID,
            cpi: opts.expectedCpi ?? CPI,
            keyId: "e2e-key-id",
            plan: "test",
            iat: Date.now(),
          }
        : null,
  );

  ddbMock.on(PutItemCommand).callsFake(async (input) => {
    const cpi = input.Item?.cpi?.S ?? "";
    const sessionId = input.Item?.session_id?.S ?? "";
    const key = rowKey(cpi, sessionId);
    if (rows.has(key)) {
      throw new ConditionalCheckFailedException({
        $metadata: {},
        message: "duplicate e2e row",
      });
    }
    rows.set(key, input.Item ?? {});
    return {};
  });
  ddbMock.on(GetItemCommand).callsFake(async (input) => ({
    Item: rows.get(
      rowKey(input.Key?.cpi?.S ?? "", input.Key?.session_id?.S ?? ""),
    ),
  }));
  ddbMock.on(UpdateItemCommand).callsFake(async (input) => {
    const merchantId = input.Key?.merchantId?.S ?? "";
    const remaining = (credits.get(merchantId) ?? 0) - 1;
    if (remaining < 0) {
      throw new ConditionalCheckFailedException({
        $metadata: {},
        message: "out of credits",
      });
    }
    credits.set(merchantId, remaining);
    return { Attributes: { credits: { N: String(remaining) } } };
  });
});

describe("integrity collect -> session-get", () => {
  it("rejects an unencrypted collect before persistence", async () => {
    const event = await collectEvent();
    event.headers["content-type"] = "application/json";
    Reflect.deleteProperty(event.headers, "x-argus-origin");
    event.body = JSON.stringify(payload());
    event.isBase64Encoded = false;

    const collected = await collectHandler(event, lambdaContext());
    expect(collected).toMatchObject({ statusCode: 415 });
    expect(ddbMock.commandCalls(PutItemCommand)).toHaveLength(0);
  });

  it("decrypts, analyzes, stores, retrieves, and projects one scan", async () => {
    const collected = await collectHandler(
      await collectEvent(),
      lambdaContext(),
    );
    expect(collected).toMatchObject({ statusCode: 200 });
    expect(JSON.parse((collected as { body: string }).body)).toMatchObject({
      session_id: SESSION_ID,
    });

    const stored = rows.get(rowKey(CPI, SESSION_ID));
    expect(stored).toBeDefined();
    expect(unmarshall(stored ?? {})).toMatchObject({
      cpi: CPI,
      session_id: SESSION_ID,
      merchant_projection: { session_id: SESSION_ID },
      projection_version: "v2",
    });

    const retrieved = await sessionGetHandler(sessionEvent(), lambdaContext());
    expect(retrieved).toMatchObject({ statusCode: 200 });
    expect(JSON.parse((retrieved as { body: string }).body)).toMatchObject({
      session_id: SESSION_ID,
      creditsRemaining: 9,
      automation: expect.any(Number),
      device_tampering: expect.any(Number),
      network_tampering: expect.any(Number),
      verdict: expect.stringMatching(/^(clean|suspect|block)$/),
    });
  });

  it("treats a same-session collect retry as idempotent", async () => {
    const first = await collectHandler(await collectEvent(), lambdaContext());
    const firstRow = rows.get(rowKey(CPI, SESSION_ID));
    const retry = await collectHandler(await collectEvent(), lambdaContext());

    expect(first).toMatchObject({ statusCode: 200 });
    expect(retry).toMatchObject({ statusCode: 200 });
    expect(rows.get(rowKey(CPI, SESSION_ID))).toEqual(firstRow);
  });

  it("keeps the composite CPI boundary when retrieving a session", async () => {
    await collectHandler(await collectEvent(), lambdaContext());

    const retrieved = await sessionGetHandler(
      sessionEvent({ cpi: "argus_cpi_test_othermerchant1" }),
      lambdaContext(),
    );
    expect(retrieved).toMatchObject({ statusCode: 404 });
    expect(JSON.parse((retrieved as { body: string }).body)).toEqual({
      error: "Session not found",
    });
  });

  it("rejects an invalid merchant token before debit or retrieval", async () => {
    await collectHandler(await collectEvent(), lambdaContext());
    ddbMock.resetHistory();

    const retrieved = await sessionGetHandler(
      sessionEvent({ token: "invalid-token" }),
      lambdaContext(),
    );
    expect(retrieved).toMatchObject({ statusCode: 401 });
    expect(ddbMock.commandCalls(UpdateItemCommand)).toHaveLength(0);
    expect(ddbMock.commandCalls(GetItemCommand)).toHaveLength(0);
  });

  it("rejects exhausted credit before reading the stored verdict", async () => {
    await collectHandler(await collectEvent(), lambdaContext());
    credits.set(MERCHANT_ID, 0);
    ddbMock.resetHistory();

    const retrieved = await sessionGetHandler(sessionEvent(), lambdaContext());
    expect(retrieved).toMatchObject({ statusCode: 402 });
    expect(JSON.parse((retrieved as { body: string }).body)).toEqual({
      error: "insufficient_credits",
    });
    expect(ddbMock.commandCalls(GetItemCommand)).toHaveLength(0);
  });
});
