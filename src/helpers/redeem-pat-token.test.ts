import { describe, expect, it } from "vitest";
import { redeemPatToken } from "./redeem-pat-token";
import { signPatAttestation } from "./pat-signed-token";
import type { ArgusPayload } from "./payload-schema";

const KEY = "a".repeat(64);
const SRC_IP = "203.0.113.42";
const CPI = "argus_cpi_test_abc1234567";
const SESSION_ID = "11111111-2222-4333-8444-555555555555";

function payload(patToken?: string): ArgusPayload {
  return {
    identifiers: { session_id: SESSION_ID },
    hashes: { stable: "x", fuzzy: "y" },
    device: {} as ArgusPayload["device"],
    ...(patToken ? { patToken } : {}),
  };
}

function token(): string {
  return signPatAttestation({
    issuer: "demo-issuer.private-access-tokens.fastly.com",
    srcIp: SRC_IP,
    cpi: CPI,
    sessionId: SESSION_ID,
    tokenHash: "deadbeef".repeat(8),
    sigintAesKeyHex: KEY,
  });
}

function context(overrides: Record<string, string> = {}) {
  return {
    expectedSrcIp: SRC_IP,
    expectedCpi: CPI,
    expectedSessionId: SESSION_ID,
    sigintAesKeyHex: KEY,
    ...overrides,
  };
}

describe("redeemPatToken", () => {
  it("attaches PAT only when every binding matches", () => {
    const out = redeemPatToken(payload(token()), context());
    expect(out.pat).toMatchObject({
      attested: true,
      tokenHash: "deadbeef".repeat(8),
    });
    expect(out.patAttempt).toEqual({ attempted: true, verified: true });
  });

  it.each([
    ["IP", { expectedSrcIp: "198.51.100.1" }, "WRONG_IP"],
    ["CPI", { expectedCpi: "argus_cpi_test_other12345" }, "WRONG_CPI"],
    [
      "session",
      { expectedSessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" },
      "WRONG_SESSION",
    ],
  ])("rejects a mismatched %s binding", (_label, override, reason) => {
    const out = redeemPatToken(payload(token()), context(override));
    expect(out.pat).toBeUndefined();
    expect(out.patAttempt).toEqual({
      attempted: true,
      verified: false,
      reason,
    });
  });

  it("records a missing PAT as neutral not-attempted telemetry", () => {
    const out = redeemPatToken(payload(), context());
    expect(out.pat).toBeUndefined();
    expect(out.patAttempt).toEqual({ attempted: false, verified: false });
  });
});
