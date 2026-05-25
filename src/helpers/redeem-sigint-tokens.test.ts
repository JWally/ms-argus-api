import { describe, it, expect, vi } from "vitest";
import type { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  redeemSigintTokens,
  isAwsCfAuthenticallyHydrated,
} from "./redeem-sigint-tokens";
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
    requestSourceIp: "1.2.3.4",
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

  it("replaces inline aws_cf with the real CF-token decode (inline data is untrusted)", async () => {
    // Layer 1: server-authoritative fields are populated only by the real
    // CF probe decode. An attacker-supplied inline `sigint.aws_cf` MUST NOT
    // survive — otherwise crafted ASN/IP/geo lands as if it came from CF.
    // Pre-fix this test asserted the opposite (inline wins) which was the
    // bug. Flipped here to assert the post-fix behavior.
    const now = Math.floor(Date.now() / 1000);
    const tls = makeTlsPayload(now);
    const existing = { id: "pre-existing-and-untrusted" };
    const payload: ArgusPayload = {
      identifiers: { session_id: "s6" },
      sigintTls: JSON.stringify(tls),
      sigint: { aws_cf: existing } as ArgusPayload["sigint"],
    } as ArgusPayload;

    const result = await redeemSigintTokens(payload, ctx());
    const awsCf = result.sigint?.aws_cf as Record<string, unknown>;
    expect(awsCf.id).toBe(UUID); // real CF data wins
    expect(awsCf.id).not.toBe("pre-existing-and-untrusted");
  });

  it("strips inline aws_cf when no CF token is present (forged aws_cf cannot survive)", async () => {
    // Layer 1 negative case: attacker submits inline aws_cf with no
    // sigintTls. Pre-fix this would land as if real. Post-fix: cleared.
    const payload: ArgusPayload = {
      identifiers: { session_id: "s6b" },
      sigint: {
        aws_cf: { ip: "8.8.8.8", asn: "15169", organization: "FAKE" },
      } as ArgusPayload["sigint"],
    } as ArgusPayload;

    const result = await redeemSigintTokens(payload, ctx());
    expect(result.sigint?.aws_cf).toBeUndefined();
  });

  it("strips inline tcp_probe when the top-level token cannot be redeemed (junk token)", async () => {
    // Layer 1: with a junk top-level token AND inline tcp_probe payload,
    // the inline value MUST be discarded. Pre-fix it would survive
    // unredeemed and analyze as if from a real probe.
    const payload: ArgusPayload = {
      identifiers: { session_id: "s_tcp_inline" },
      sigintTcpToken: "junk.token.value",
      sigint: {
        tcp_probe: {
          rtt_fingerprint: { rtt_refreshed: 18, rcv_rtt_refreshed: 18 },
          snd_mss: 1460,
        },
      } as ArgusPayload["sigint"],
    } as ArgusPayload;

    const result = await redeemSigintTokens(payload, ctx());
    expect(result.sigint?.tcp_probe).toBeUndefined();
  });

  it("strips inline h2 when the top-level token cannot be redeemed (junk token)", async () => {
    // Layer 1: same as above for h2.
    const payload: ArgusPayload = {
      identifiers: { session_id: "s_h2_inline" },
      sigintH2Token: "junk.token.value",
      sigint: {
        h2: { ja4_h2: "fake_ja4_h2" },
      } as ArgusPayload["sigint"],
    } as ArgusPayload;

    const result = await redeemSigintTokens(payload, ctx());
    expect(result.sigint?.h2).toBeUndefined();
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

describe("isAwsCfAuthenticallyHydrated", () => {
  // Layer-2 gate consults this helper to decide whether aws_cf counts as
  // "a probe hydrated". A forged sigintTls produces an aws_cf record with
  // tampered=true; the original `!!sigint?.aws_cf` truthiness check let
  // that record satisfy the gate and the analyzer scored SAFE via the
  // proxy_waterfall rule-8 clean fallback. See bots/inline-probe-bypass.mjs
  // in ms-argus-attack-bots for the PoC.

  it("returns false when aws_cf is absent", () => {
    expect(isAwsCfAuthenticallyHydrated(undefined)).toBe(false);
    expect(isAwsCfAuthenticallyHydrated({})).toBe(false);
  });

  it("returns false when tampered=true (forged SipHash sig)", () => {
    expect(
      isAwsCfAuthenticallyHydrated({
        aws_cf: { tampered: true, expired: false },
      }),
    ).toBe(false);
  });

  it("returns false when expired=true (ts outside ±90s)", () => {
    expect(
      isAwsCfAuthenticallyHydrated({
        aws_cf: { tampered: false, expired: true },
      }),
    ).toBe(false);
  });

  it("returns false when flags are missing (fail-closed default)", () => {
    // verifyCfToken defaults both to true when it can't verify; if either
    // flag is anything other than an explicit `false` we treat aws_cf as
    // not authentically hydrated.
    expect(isAwsCfAuthenticallyHydrated({ aws_cf: {} })).toBe(false);
    expect(isAwsCfAuthenticallyHydrated({ aws_cf: { tampered: false } })).toBe(
      false,
    );
    expect(isAwsCfAuthenticallyHydrated({ aws_cf: { expired: false } })).toBe(
      false,
    );
  });

  it("returns true when both flags are explicitly false", () => {
    expect(
      isAwsCfAuthenticallyHydrated({
        aws_cf: { tampered: false, expired: false },
      }),
    ).toBe(true);
  });

  it("end-to-end: forged sigintTls hydrates aws_cf but is NOT authentic", async () => {
    // Concrete reproduction of the residual bypass. A real CF probe
    // hydration round-trip through redeemSigintTokens leaves aws_cf
    // stamped tampered=true; isAwsCfAuthenticallyHydrated returns false
    // and Layer-2 will reject.
    const now = Math.floor(Date.now() / 1000);
    const forged = {
      ...makeTlsPayload(now),
      sig: "deadbeefdeadbeef", // overwrite the real sig
    };
    const payload: ArgusPayload = {
      identifiers: { session_id: "s_forged" },
      sigintTls: JSON.stringify(forged),
    } as ArgusPayload;

    const result = await redeemSigintTokens(payload, ctx());
    // aws_cf IS hydrated (applyTlsJson runs unconditionally)
    expect(result.sigint?.aws_cf).toBeDefined();
    expect((result.sigint?.aws_cf as Record<string, unknown>).tampered).toBe(
      true,
    );
    // …but the Layer-2 helper says it doesn't count
    expect(isAwsCfAuthenticallyHydrated(result.sigint)).toBe(false);
  });

  it("end-to-end: valid sigintTls IS authentic", async () => {
    const now = Math.floor(Date.now() / 1000);
    const valid = makeTlsPayload(now);
    const payload: ArgusPayload = {
      identifiers: { session_id: "s_valid" },
      sigintTls: JSON.stringify(valid),
    } as ArgusPayload;

    const result = await redeemSigintTokens(payload, ctx());
    expect(isAwsCfAuthenticallyHydrated(result.sigint)).toBe(true);
  });
});
