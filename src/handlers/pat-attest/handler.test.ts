import {
  constants,
  createHash,
  generateKeyPairSync,
  sign as signRaw,
  type KeyObject,
} from "crypto";
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { encodeTokenChallenge } from "./challenge";

const ISSUER = "demo-issuer.example";
const CPI = "argus_cpi_test_abc1234567";
const SESSION_ID = "11111111-2222-4333-8444-555555555555";
let privateKey: KeyObject;
let spkiDer: Buffer;

beforeAll(() => {
  const generate = generateKeyPairSync as unknown as (
    type: string,
    options: Record<string, unknown>,
  ) => { privateKey: KeyObject; publicKey: KeyObject };
  const pair = generate("rsa-pss", {
    modulusLength: 2048,
    hashAlgorithm: "sha384",
    mgf1HashAlgorithm: "sha384",
    saltLength: 48,
  });
  privateKey = pair.privateKey;
  spkiDer = pair.publicKey.export({ type: "spki", format: "der" }) as Buffer;
});

const replayStore = {
  claimPatTokenHash: vi.fn<
    () => Promise<"claimed" | "replayed" | "unavailable">
  >(async () => "claimed"),
};
const signPatAttestation = vi.fn(() => "signed-attestation-blob");

function syntheticToken(): Buffer {
  const challenge = encodeTokenChallenge({ issuerName: ISSUER });
  const type = Buffer.alloc(2);
  type.writeUInt16BE(2);
  const message = Buffer.concat([
    type,
    Buffer.alloc(32, 0x11),
    createHash("sha256").update(challenge).digest(),
    createHash("sha256").update(spkiDer).digest(),
  ]);
  const signature = signRaw("sha384", message, {
    key: privateKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 48,
  });
  return Buffer.concat([message, signature]);
}

function b64url(value: Buffer): string {
  return value.toString("base64url");
}

function event(authorization?: string) {
  return {
    requestContext: {
      http: { path: "/v1/pat-attestation", sourceIp: "203.0.113.7" },
    },
    headers: authorization ? { authorization } : {},
    queryStringParameters: { cpi: CPI, sessionId: SESSION_ID },
  } as never;
}

async function loadHandler() {
  vi.doMock("./issuer-config", () => ({
    ISSUER_CONFIG: {
      host: ISSUER,
      disabled: false,
      directoryCacheSeconds: 3600,
    },
  }));
  vi.doMock("./issuer-directory", () => ({
    getActiveTokenKey: vi.fn(async () => ({ spkiDer })),
  }));
  vi.doMock("./token-replay-store", () => replayStore);
  vi.doMock("../../helpers/pat-signed-token", () => ({
    signPatAttestation,
    CLIENT_REFRESH_SECONDS: 45,
  }));
  vi.doMock("@aws-sdk/client-secrets-manager", () => ({
    SecretsManagerClient: class {
      send() {
        return { SecretString: "00".repeat(32) };
      }
    },
    GetSecretValueCommand: class {},
  }));
  process.env.SIGINT_AES_KEY_SECRET_ARN = "arn:test";
  return (await import("./handler")).baseHandler;
}

beforeEach(() => {
  replayStore.claimPatTokenHash.mockResolvedValue("claimed");
});

afterEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
});

describe("PAT handler single-use binding", () => {
  it("issues the Apple-compatible unbound challenge", async () => {
    const handler = await loadHandler();
    const response = (await handler(event())) as { body: string };
    const challenge = Buffer.from(
      JSON.parse(response.body ?? "{}").challenge,
      "base64url",
    );
    expect(challenge.equals(encodeTokenChallenge({ issuerName: ISSUER }))).toBe(
      true,
    );
  });

  it("claims the raw token once and binds the wrapper", async () => {
    const token = syntheticToken();
    const handler = await loadHandler();
    const response = (await handler(
      event(`PrivateToken token=${b64url(token)}`),
    )) as { statusCode: number };
    expect(response.statusCode).toBe(200);
    expect(replayStore.claimPatTokenHash).toHaveBeenCalledWith(
      createHash("sha256").update(token).digest("hex"),
    );
    expect(signPatAttestation).toHaveBeenCalledWith(
      expect.objectContaining({
        cpi: CPI,
        sessionId: SESSION_ID,
        srcIp: "203.0.113.7",
      }),
    );
  });

  it("rejects replay before issuing another wrapper", async () => {
    replayStore.claimPatTokenHash.mockResolvedValue("replayed");
    const handler = await loadHandler();
    const response = (await handler(
      event(`PrivateToken token=${b64url(syntheticToken())}`),
    )) as { statusCode: number };
    expect(response.statusCode).toBe(401);
    expect(signPatAttestation).not.toHaveBeenCalled();
  });
});
