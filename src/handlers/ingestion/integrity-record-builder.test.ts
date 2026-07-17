import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MetricUnit, type Metrics } from "@aws-lambda-powertools/metrics";
import type { Logger } from "@aws-lambda-powertools/logger";
import type { DeviceHistoryAnalysis } from "../../analysis/device-history";
import type { IdentityOutcome } from "../../helpers/device-identity";
import type { ArgusPayload } from "../../helpers/payload-schema";

const stunMocks = vi.hoisted(() => ({ claim: vi.fn() }));
const sigintMocks = vi.hoisted(() => ({
  decode: vi.fn(),
  buildField: vi.fn(),
}));
const analysisMocks = vi.hoisted(() => ({
  buildBlock: vi.fn(),
  buildIdentification: vi.fn(),
  buildPat: vi.fn(),
  captureHeaders: vi.fn(),
  summarizeSigint: vi.fn(),
}));
const relayMocks = vi.hoisted(() => ({ lookup: vi.fn() }));

vi.mock("../../helpers/stun-nonce-tracker", () => ({
  claimStunNonce: stunMocks.claim,
}));
vi.mock("../../helpers/sigint-v6-decode", () => ({
  decodeWebrtcSigintCandidates: sigintMocks.decode,
  buildWebrtcSigintField: sigintMocks.buildField,
}));
vi.mock("./integrity-analysis", () => ({
  buildAnalysisBlock: analysisMocks.buildBlock,
  buildIdentificationField: analysisMocks.buildIdentification,
  buildPatFields: analysisMocks.buildPat,
  captureRequestHeaders: analysisMocks.captureHeaders,
  sigintSummary: analysisMocks.summarizeSigint,
}));
vi.mock("../../services/network/apple-relay", () => ({
  lookupAppleRelaySync: relayMocks.lookup,
}));

import { buildIntegrityRecord } from "./integrity-record-builder";

const logger = { warn: vi.fn() } as unknown as Logger;
const metrics = { addMetric: vi.fn() } as unknown as Metrics;

const history: DeviceHistoryAnalysis = {
  tampered: false,
  identityMismatch: false,
  freshDevice: true,
  scanCount: 0,
  ageSeconds: 0,
  distinctIpCount: 0,
  distinctCountryCount: 0,
  distinctNetClassCount: 0,
  distinctCpiCount: 0,
  distinctUaCount: 0,
  recent5MinCount: 0,
  recent1HourCount: 0,
  recent24HourCount: 0,
};

const identity: IdentityOutcome = {
  present: true,
  verified: true,
  pubkey: "public-key",
  sig_present: true,
};

function makePayload(overrides: Partial<ArgusPayload> = {}): ArgusPayload {
  return {
    identifiers: { session_id: "session-1", cpi: "argus_cpi_test" },
    hashes: { stable: "stable", fuzzy: "fuzzy" },
    device: { browser: "fixture" },
    meta: { version: "test" },
    ...overrides,
  } as ArgusPayload;
}

type BuildArgs = Parameters<typeof buildIntegrityRecord>[0];

function makeArgs(overrides: Partial<BuildArgs> = {}): BuildArgs {
  return {
    ctx: {
      payload: makePayload(),
      sessionId: "session-1",
      cpi: "argus_cpi_test",
      event: {
        headers: {
          "x-forwarded-for": "203.0.113.7, 10.0.0.1",
          "user-agent": "Argus Browser",
          "accept-language": "en-US",
        },
        cookies: ["fpid=secret"],
      },
      deps: { logger, metrics },
    },
    hydratedPayload: makePayload({ sigint: {} }),
    identity,
    merchantId: "merchant-1",
    deviceHistory: history,
    sigintAesKey: "sigint-key",
    ttlSeconds: 2_592_000,
    now: 1_700_000_000_500,
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  sigintMocks.decode.mockReturnValue({
    decoded: null,
    candidateCount: 0,
    reason: "no_candidates",
  });
  sigintMocks.buildField.mockReturnValue(undefined);
  analysisMocks.buildIdentification.mockReturnValue({ verified: true });
  analysisMocks.buildPat.mockReturnValue({ pat: { attested: true } });
  analysisMocks.captureHeaders.mockReturnValue({
    headers: { "user-agent": "Argus Browser" },
    cookie_names: ["fpid"],
  });
  analysisMocks.buildBlock.mockReturnValue({ risk: "analysis" });
  analysisMocks.summarizeSigint.mockReturnValue({ tcp_token: "absent" });
  relayMocks.lookup.mockReturnValue({ network: "apple-private-relay" });
  stunMocks.claim.mockReturnValue({ accepted: true, firstClaim: true });
});

afterEach(() => vi.restoreAllMocks());

describe("buildIntegrityRecord", () => {
  it("assembles the durable record from trusted and request-owned evidence", () => {
    const args = makeArgs();
    const record = buildIntegrityRecord(args);

    expect(record).toEqual({
      cpi: "argus_cpi_test",
      session_id: "session-1",
      merchant_id: "merchant-1",
      device: { browser: "fixture" },
      meta: { version: "test" },
      sigint: {},
      identification: { verified: true },
      pat: { attested: true },
      analysis: { risk: "analysis" },
      client_ip: "203.0.113.7",
      user_agent: "Argus Browser",
      request_headers: {
        headers: { "user-agent": "Argus Browser" },
        cookie_names: ["fpid"],
      },
      apple_relay_egress: { network: "apple-private-relay" },
      created_at: 1_700_000_000_500,
      ttl: 1_702_592_000,
    });
    expect(sigintMocks.decode).toHaveBeenCalledWith(
      { browser: "fixture" },
      "sigint-key",
    );
    expect(analysisMocks.buildBlock).toHaveBeenCalledWith(
      expect.objectContaining({
        raw: args.ctx.payload,
        hydratedPayload: args.hydratedPayload,
        clientIp: "203.0.113.7",
        ua: "Argus Browser",
        acceptLanguage: "en-US",
        requestHeaders: { "user-agent": "Argus Browser" },
        deviceHistory: history,
      }),
    );
    expect(stunMocks.claim).not.toHaveBeenCalled();
  });

  it("keeps sparse fields absent and summarizes sigint when hydration has none", () => {
    analysisMocks.buildIdentification.mockReturnValue(undefined);
    relayMocks.lookup.mockReturnValue(null);
    const ctx = makeArgs().ctx;
    ctx.payload = makePayload({ device: undefined });
    delete (ctx.payload as ArgusPayload & { meta?: unknown }).meta;
    ctx.event.headers = {};
    sigintMocks.decode.mockReturnValue({
      decoded: null,
      candidateCount: 1,
      reason: "ok",
    });
    vi.spyOn(Date, "now").mockReturnValueOnce(1_700_000_001_500);
    const record = buildIntegrityRecord(
      makeArgs({
        ctx,
        hydratedPayload: makePayload(),
        merchantId: null,
        now: undefined,
      }),
    );

    expect(record).not.toHaveProperty("merchant_id");
    expect(record).not.toHaveProperty("identification");
    expect(record).not.toHaveProperty("apple_relay_egress");
    expect(record).toMatchObject({
      device: {},
      meta: {},
      client_ip: "",
      user_agent: "",
      created_at: 1_700_000_001_500,
    });
    expect(record.sigint).toEqual({ tcp_token: "absent" });
    expect(analysisMocks.summarizeSigint).toHaveBeenCalledWith(ctx.payload);
    expect(stunMocks.claim).not.toHaveBeenCalled();
  });

  it("claims a decoded STUN candidate using its canonical ciphertext", () => {
    sigintMocks.decode.mockReturnValue({
      decoded: {
        ip: "198.51.100.9",
        cipherB64: "ciphertext",
      },
      candidateCount: 1,
      reason: "ok",
    });

    expect(() => buildIntegrityRecord(makeArgs())).not.toThrow();
    expect(stunMocks.claim).toHaveBeenCalledWith(
      "ciphertext",
      "session-1",
      "argus_cpi_test",
      "198.51.100.9",
    );
  });

  it("rejects cross-session STUN replay before a record is assembled", () => {
    sigintMocks.decode.mockReturnValue({
      decoded: {
        ip: "198.51.100.9",
        cipherB64: "ciphertext",
      },
      candidateCount: 1,
      reason: "ok",
    });
    stunMocks.claim.mockReturnValue({
      accepted: false,
      reason: "cross_session_replay",
      firstClaimedBy: {
        sessionId: "original-session",
        cpi: "argus_cpi_test",
        ip: "198.51.100.9",
        claimedAt: 1_700_000_000_000,
      },
    });

    expect(() => buildIntegrityRecord(makeArgs())).toThrowError(
      expect.objectContaining({
        statusCode: 409,
        message: "webrtc attestation already redeemed",
      }),
    );
    expect(metrics.addMetric).toHaveBeenCalledWith(
      "WebrtcStunReplay",
      MetricUnit.Count,
      1,
    );
    expect(logger.warn).toHaveBeenCalledWith(
      "WebRTC STUN candidate replay rejected",
      {
        session_id: "session-1",
        cpi: "argus_cpi_test",
        attested_ip: "198.51.100.9",
        first_claimed_by: "original-session",
        first_claimed_at: 1_700_000_000_000,
      },
    );
    expect(analysisMocks.buildBlock).not.toHaveBeenCalled();
  });
});
