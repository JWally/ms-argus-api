import { describe, it, expect, vi } from "vitest";
import type { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { redeemSigintTokens } from "./redeem-sigint-tokens";
import { sipHash24 } from "./verify-cf-token";
import type { ArgusPayload } from "./payload-schema";

// Use a well-defined key so we can forge legitimate sigs in the tests
const KEY = "f5caa84bfeaf811c".repeat(4);
const UUID = "abcdef12-3456-7890-abcd-ef1234567890";
const ISSUED_AT = 1_700_000_000;

function ctx() {
  return {
    sigintAesKeyHex: KEY,
    probeTokensTableName: "test-table",
    dynamo: { send: vi.fn() } as unknown as DynamoDBClient,
  };
}

function makeTlsPayload(ts: number, overrides: Record<string, unknown> = {}) {
  const payload = {
    id: UUID,
    issuedAt: ISSUED_AT,
    ip: "1.2.3.4",
    asn: "13335",
    ts,
    ...overrides,
  };
  const canonical = `${payload.id}|${payload.issuedAt}|${payload.ip}|${payload.asn}|${payload.ts}`;
  return { ...payload, sig: sipHash24(KEY, canonical) };
}

function makeFpidCookie(id = UUID, issuedAt = ISSUED_AT): string {
  const sig = sipHash24(KEY, `fpid|${id}|${issuedAt}`);
  return `${id}_${issuedAt}.${sig}`;
}

describe("redeemSigintTokens (applyTlsJson cookie flags)", () => {
  it("stamps tampered=false and expired=false on a valid token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const tls = makeTlsPayload(now);
    const payload: ArgusPayload = {
      identifiers: { session_id: "s1" },
      sigintTls: JSON.stringify(tls),
    } as ArgusPayload;

    const result = await redeemSigintTokens(payload, {
      ...ctx(),
      fpidCookie: makeFpidCookie(),
    });
    const awsCf = result.sigint?.aws_cf as Record<string, unknown>;
    expect(awsCf.tampered).toBe(false);
    expect(awsCf.expired).toBe(false);
    expect(awsCf.cookieTampered).toBe(false);
    expect(awsCf.cookieMatchesToken).toBe(true);
  });

  it("flags cookieTampered when cookie sig is forged", async () => {
    const now = Math.floor(Date.now() / 1000);
    const tls = makeTlsPayload(now);
    const payload: ArgusPayload = {
      identifiers: { session_id: "s2" },
      sigintTls: JSON.stringify(tls),
    } as ArgusPayload;

    const forgedCookie = `${UUID}_${ISSUED_AT}.deadbeefdeadbeef`;
    const result = await redeemSigintTokens(payload, {
      ...ctx(),
      fpidCookie: forgedCookie,
    });
    const awsCf = result.sigint?.aws_cf as Record<string, unknown>;
    expect(awsCf.cookieTampered).toBe(true);
    expect(awsCf.cookieMatchesToken).toBeUndefined();
  });

  it("flags cookieTampered=true when no cookie is presented", async () => {
    const now = Math.floor(Date.now() / 1000);
    const tls = makeTlsPayload(now);
    const payload: ArgusPayload = {
      identifiers: { session_id: "s3" },
      sigintTls: JSON.stringify(tls),
    } as ArgusPayload;

    const result = await redeemSigintTokens(payload, ctx());
    const awsCf = result.sigint?.aws_cf as Record<string, unknown>;
    expect(awsCf.cookieTampered).toBe(true);
  });

  it("flags cookieMatchesToken=false when cookie id differs from token id", async () => {
    const now = Math.floor(Date.now() / 1000);
    const tls = makeTlsPayload(now);
    const otherUuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const otherCookie = makeFpidCookie(otherUuid, ISSUED_AT);
    const payload: ArgusPayload = {
      identifiers: { session_id: "s4" },
      sigintTls: JSON.stringify(tls),
    } as ArgusPayload;

    const result = await redeemSigintTokens(payload, {
      ...ctx(),
      fpidCookie: otherCookie,
    });
    const awsCf = result.sigint?.aws_cf as Record<string, unknown>;
    expect(awsCf.cookieTampered).toBe(false);
    expect(awsCf.cookieMatchesToken).toBe(false);
  });

  it("unwraps SigintResult envelope from sigintTls", async () => {
    const now = Math.floor(Date.now() / 1000);
    const tls = makeTlsPayload(now);
    const envelope = { data: tls, error: null, durationMs: 50 };
    const payload: ArgusPayload = {
      identifiers: { session_id: "s5" },
      sigintTls: JSON.stringify(envelope),
    } as ArgusPayload;

    const result = await redeemSigintTokens(payload, {
      ...ctx(),
      fpidCookie: makeFpidCookie(),
    });
    const awsCf = result.sigint?.aws_cf as Record<string, unknown>;
    expect(awsCf.id).toBe(UUID);
    expect(awsCf.tampered).toBe(false);
  });

  it("does not re-apply aws_cf when sigint.aws_cf is already set", async () => {
    const now = Math.floor(Date.now() / 1000);
    const tls = makeTlsPayload(now);
    const existing = { id: "pre-existing" };
    const payload: ArgusPayload = {
      identifiers: { session_id: "s6" },
      sigintTls: JSON.stringify(tls),
      sigint: { aws_cf: existing } as ArgusPayload["sigint"],
    } as ArgusPayload;

    const result = await redeemSigintTokens(payload, ctx());
    const awsCf = result.sigint?.aws_cf as Record<string, unknown>;
    expect(awsCf.id).toBe("pre-existing");
  });

  it("ignores malformed TLS JSON silently", async () => {
    const payload: ArgusPayload = {
      identifiers: { session_id: "s7" },
      sigintTls: "{not-valid-json",
    } as ArgusPayload;

    const result = await redeemSigintTokens(payload, ctx());
    expect(result.sigint?.aws_cf).toBeUndefined();
  });
});
