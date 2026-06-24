import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import {
  createHash,
  generateKeyPairSync,
  sign as signRaw,
  constants,
  type KeyObject,
} from "crypto";

import { encodeTokenChallenge } from "./challenge";

/** Build a real RSA-PSS-signed synthetic PAT (same shape as verify.test.ts). */
function buildSyntheticToken(
  privateKey: KeyObject,
  spkiDer: Buffer,
  challenge: Buffer,
): Buffer {
  const tokenType = Buffer.alloc(2);
  tokenType.writeUInt16BE(0x0002);
  const nonce = Buffer.alloc(32, 0x11);
  const challengeDigest = createHash("sha256").update(challenge).digest();
  const tokenKeyId = createHash("sha256").update(spkiDer).digest();
  const signedMessage = Buffer.concat([
    tokenType,
    nonce,
    challengeDigest,
    tokenKeyId,
  ]);
  const authenticator = signRaw("sha384", signedMessage, {
    key: privateKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 48,
  });
  return Buffer.concat([signedMessage, authenticator]);
}

const b64url = (b: Buffer) =>
  b
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

let privateKey: KeyObject;
let spkiDer: Buffer;

beforeAll(() => {
  const gen = generateKeyPairSync as unknown as (
    type: string,
    opts: Record<string, unknown>,
  ) => { privateKey: KeyObject; publicKey: KeyObject };
  const kp = gen("rsa-pss", {
    modulusLength: 2048,
    hashAlgorithm: "sha384",
    mgf1HashAlgorithm: "sha384",
    saltLength: 48,
  });
  privateKey = kp.privateKey;
  spkiDer = kp.publicKey.export({ type: "spki", format: "der" }) as Buffer;
});

// Controllable store mock shared across the suite.
const store = {
  bindingEnabled: vi.fn((): boolean => true),
  newRedemptionContext: vi.fn((): Buffer => Buffer.alloc(32, 0x22)),
  storeChallenge: vi.fn(async (_challenge: Buffer): Promise<boolean> => true),
  consumeChallenge: vi.fn(
    async (_digest: Buffer): Promise<Buffer | null> => null,
  ),
};

function event(
  headers: Record<string, string> = {},
  path = "/v1/pat-attestation",
) {
  return {
    requestContext: { http: { path, sourceIp: "203.0.113.7" } },
    headers,
  } as never;
}

async function loadHandler() {
  vi.doMock("./challenge-store", () => store);
  vi.doMock("./issuer-directory", () => ({
    getActiveTokenKey: vi.fn(async () => ({ spkiDer })),
  }));
  vi.doMock("../../helpers/pat-signed-token", () => ({
    signPatAttestation: vi.fn(() => "signed-attestation-blob"),
    CLIENT_REFRESH_SECONDS: 45,
  }));
  vi.doMock("@aws-sdk/client-secrets-manager", () => ({
    SecretsManagerClient: class {
      async send() {
        return { SecretString: "00".repeat(32) };
      }
    },
    GetSecretValueCommand: class {},
  }));
  process.env.SIGINT_AES_KEY_SECRET_ARN = "arn:aws:secretsmanager:test";
  return (await import("./handler")).baseHandler;
}

beforeEach(() => {
  store.bindingEnabled.mockReturnValue(true);
  store.storeChallenge.mockResolvedValue(true);
  store.consumeChallenge.mockResolvedValue(null);
});
afterEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
  vi.doUnmock("./challenge-store");
  vi.doUnmock("./issuer-directory");
  vi.doUnmock("../../helpers/pat-signed-token");
  vi.doUnmock("@aws-sdk/client-secrets-manager");
});

describe("PAT handler — bound challenge + single-use (#13)", () => {
  it("issues a BOUND challenge and stores it (no Authorization)", async () => {
    const baseHandler = await loadHandler();
    const res = (await baseHandler(event())) as {
      statusCode: number;
      body: string;
    };
    expect(res.statusCode).toBe(401);
    expect(store.storeChallenge).toHaveBeenCalledTimes(1);
    // The stored challenge carries our 32-byte redemption context (bound mode).
    const storedChallenge = store.storeChallenge.mock.calls[0][0] as Buffer;
    expect(storedChallenge.includes(Buffer.alloc(32, 0x22))).toBe(true);
    expect(typeof JSON.parse(res.body).challenge).toBe("string");
  });

  it("redeems a token bound to a stored challenge → 200 signed blob (consumes once)", async () => {
    const boundChallenge = encodeTokenChallenge({
      issuerName: "demo-issuer.example",
      redemptionContext: Buffer.alloc(32, 0x22),
    });
    store.consumeChallenge.mockResolvedValueOnce(boundChallenge);
    const token = buildSyntheticToken(privateKey, spkiDer, boundChallenge);

    const baseHandler = await loadHandler();
    const res = (await baseHandler(
      event({ authorization: `PrivateToken token=${b64url(token)}` }),
    )) as { statusCode: number; body: string };

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).token).toBe("signed-attestation-blob");
    expect(store.consumeChallenge).toHaveBeenCalledTimes(1);
  });

  it("rejects a REPLAYED bound token (consume returns null) → 401", async () => {
    const boundChallenge = encodeTokenChallenge({
      issuerName: "demo-issuer.example",
      redemptionContext: Buffer.alloc(32, 0x22),
    });
    const token = buildSyntheticToken(privateKey, spkiDer, boundChallenge);
    store.consumeChallenge.mockResolvedValue(null); // already consumed

    const baseHandler = await loadHandler();
    const res = (await baseHandler(
      event({ authorization: `PrivateToken token=${b64url(token)}` }),
    )) as { statusCode: number; body: string };

    // Falls back to the unbound challenge, whose digest differs → verify fails.
    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body).error).toBe("invalid_token");
  });

  it("rejects a malformed Authorization token → 401", async () => {
    const baseHandler = await loadHandler();
    const res = (await baseHandler(
      event({ authorization: "PrivateToken token=AAAA" }),
    )) as { statusCode: number; body: string };
    expect(res.statusCode).toBe(401);
  });
});
