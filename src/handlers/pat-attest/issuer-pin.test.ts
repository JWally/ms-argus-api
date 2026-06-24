import { afterEach, describe, expect, it, vi } from "vitest";
import { createHash } from "crypto";

// A token-key (base64url SPKI). Content is irrelevant to pin logic — only its
// SHA-256 (the token_key_id) matters. getActiveTokenKey never signature-checks.
const TOKEN_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMA";
const b64urlDecode = (s: string) =>
  Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
const KEY_ID = createHash("sha256")
  .update(b64urlDecode(TOKEN_KEY))
  .digest("hex");

const DIRECTORY = {
  "issuer-request-uri": "https://issuer.example/token-request",
  "token-keys": [
    { "token-type": 2, "token-key": TOKEN_KEY, "not-before": 1_700_000_000 },
  ],
};

function baseConfig(overrides: Record<string, unknown>) {
  return {
    ISSUER_CONFIG: {
      host: "issuer.example",
      directoryPath: "/.well-known/token-issuer-directory",
      expectedTokenType: 0x0002,
      directoryCacheSeconds: 3600,
      disabled: false,
      knownTokenKeyIds: [],
      enforceKeyPin: false,
      ...overrides,
    },
  };
}

async function load(overrides: Record<string, unknown>) {
  vi.doMock("./issuer-config", () => baseConfig(overrides));
  vi.stubGlobal(
    "fetch",
    vi.fn(() => new Response(JSON.stringify(DIRECTORY))),
  );
  const mod = await import("./issuer-directory");
  mod.__resetCacheForTesting();
  return mod;
}

afterEach(() => {
  vi.resetModules();
  vi.doUnmock("./issuer-config");
  vi.unstubAllGlobals();
});

describe("PAT issuer key pinning (#13)", () => {
  it("accepts a recognized (pinned) key", async () => {
    const { getActiveTokenKey } = await load({
      knownTokenKeyIds: [KEY_ID],
      enforceKeyPin: true,
    });
    const key = await getActiveTokenKey();
    expect(key?.keyId).toBe(KEY_ID);
  });

  it("accepts an UNRECOGNIZED key when not enforcing (alert-only)", async () => {
    const { getActiveTokenKey } = await load({
      knownTokenKeyIds: ["00".repeat(32)],
      enforceKeyPin: false,
    });
    const key = await getActiveTokenKey();
    expect(key).not.toBeNull();
    expect(key?.keyId).toBe(KEY_ID);
  });

  it("REJECTS an unrecognized key when enforcing (fail-closed → no PAT)", async () => {
    const { getActiveTokenKey } = await load({
      knownTokenKeyIds: ["00".repeat(32)],
      enforceKeyPin: true,
    });
    expect(await getActiveTokenKey()).toBeNull();
  });

  it("treats an empty allowlist as no pinning (accepts anything)", async () => {
    const { getActiveTokenKey } = await load({
      knownTokenKeyIds: [],
      enforceKeyPin: true,
    });
    expect(await getActiveTokenKey()).not.toBeNull();
  });
});
