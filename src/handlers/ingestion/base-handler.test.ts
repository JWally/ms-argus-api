/**
 * Targeted coverage for the hydrateSigint catch arm — the structural
 * fix from commit `da1ed56`. Pre-fix, any throw out of redeemSigintTokens
 * caused the function to return the ORIGINAL payload (with attacker-
 * controlled inline `sigint.tcp_probe` / `sigint.h2` / `sigint.aws_cf`
 * blobs intact, because Layer-1 strip runs INSIDE redeemSigintTokens and
 * never executed). Post-fix it throws HttpError(503).
 *
 * The realistic production trigger is DDB throttling on PROBE_TOKENS_TABLE;
 * here we mock the helper itself so the test exercises just the catch arm
 * behavior, independent of which AWS subsystem caused the throw.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../helpers/redeem-sigint-tokens", () => ({
  redeemSigintTokens: vi.fn(),
  // Re-export the unrelated function untouched so base-handler.ts imports
  // resolve without further mocking.
  isAwsCfAuthenticallyHydrated: () => false,
}));

import { hydrateSigint } from "./base-handler";
import { redeemSigintTokens } from "../../helpers/redeem-sigint-tokens";
import { HttpError } from "../../helpers/http-error";
import type { ArgusPayload } from "../../helpers/payload-schema";
import type { Logger } from "@aws-lambda-powertools/logger";
import type { Metrics } from "@aws-lambda-powertools/metrics";

const mockLogger = {
  warn: vi.fn(),
  info: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
} as unknown as Logger;

const mockMetrics = {
  addMetric: vi.fn(),
} as unknown as Metrics;

function makeEvent(): {
  headers: Record<string, string>;
  cookies: string[];
  requestContext: { http: { sourceIp: string } };
} {
  return {
    headers: {},
    cookies: [],
    requestContext: { http: { sourceIp: "203.0.113.7" } },
  };
}

function makePayload(): ArgusPayload {
  return {
    identifiers: { session_id: "test-session", cpi: "argus_cpi_test_abc" },
    hashes: { stable: "x", fuzzy: "y" },
    device: {},
    // Inline sigint blob present — pre-fix this would survive the
    // pre-Layer-1 catch and pass Layer-2's truthiness check. The test
    // proves the catch no longer enables that bypass.
    sigint: {
      tcp_probe: {
        rtt_fingerprint: { rtt_refreshed: 8000, rcv_rtt_refreshed: 8000 },
      } as ArgusPayload["sigint"] extends infer S
        ? S extends { tcp_probe?: infer T }
          ? T
          : never
        : never,
    } as ArgusPayload["sigint"],
    sigintTcpToken: "junk",
    sigintH2Token: "junk",
    sigintTls: "{}",
  } as ArgusPayload;
}

describe("hydrateSigint catch arm — ARGUS_URGENT_FIXES #4 layer-1-bypass", () => {
  beforeEach(() => {
    vi.mocked(redeemSigintTokens).mockReset();
    vi.mocked(mockMetrics.addMetric).mockReset();
    vi.mocked(mockLogger.warn).mockReset();
    // Hydration only runs when both env vars are set; mirror prod config.
    process.env.SIGINT_AES_KEY = "a".repeat(64);
    process.env.PROBE_TOKENS_TABLE_NAME = "test-table";
  });

  it("throws HttpError(503) when redeemSigintTokens throws (DDB-throttle shape)", async () => {
    vi.mocked(redeemSigintTokens).mockRejectedValueOnce(
      Object.assign(new Error("ProvisionedThroughputExceededException"), {
        name: "ProvisionedThroughputExceededException",
      }),
    );

    const deps = { logger: mockLogger, metrics: mockMetrics };
    await expect(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      hydrateSigint(makePayload(), deps, makeEvent() as any),
    ).rejects.toThrow(HttpError);
  });

  it("503 carries the expected message — server transient, not client error", async () => {
    vi.mocked(redeemSigintTokens).mockRejectedValueOnce(new Error("boom"));

    const deps = { logger: mockLogger, metrics: mockMetrics };
    let caught: unknown;
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await hydrateSigint(makePayload(), deps, makeEvent() as any);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(HttpError);
    expect((caught as HttpError).statusCode).toBe(503);
    expect((caught as HttpError).message).toBe(
      "sigint verification temporarily unavailable",
    );
  });

  it("emits SigintHydrationError metric on catch", async () => {
    vi.mocked(redeemSigintTokens).mockRejectedValueOnce(new Error("boom"));

    const deps = { logger: mockLogger, metrics: mockMetrics };
    await expect(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      hydrateSigint(makePayload(), deps, makeEvent() as any),
    ).rejects.toThrow();

    const calls = vi.mocked(mockMetrics.addMetric).mock.calls;
    const metricNames = calls.map((c) => c[0]);
    expect(metricNames).toContain("SigintHydrationError");
  });

  it("does NOT return the original payload on catch (the structural fix)", async () => {
    // Regression assertion: pre-fix, the catch returned `payload`, so an
    // attacker's inline sigint blob survived end-to-end. Today, we throw
    // instead — so no caller can observe the original payload from this
    // path. If anyone ever changes the catch back to `return payload`,
    // this test fails.
    vi.mocked(redeemSigintTokens).mockRejectedValueOnce(new Error("boom"));

    const deps = { logger: mockLogger, metrics: mockMetrics };
    const payload = makePayload();
    let returned: ArgusPayload | null = null;
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      returned = await hydrateSigint(payload, deps, makeEvent() as any);
    } catch {
      // expected
    }
    expect(returned).toBeNull(); // never assigned because we threw
  });

  it("logs a WARN with the error for ops visibility (no silent failure)", async () => {
    vi.mocked(redeemSigintTokens).mockRejectedValueOnce(new Error("simulated"));

    const deps = { logger: mockLogger, metrics: mockMetrics };
    await expect(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      hydrateSigint(makePayload(), deps, makeEvent() as any),
    ).rejects.toThrow();

    expect(mockLogger.warn).toHaveBeenCalled();
    const warnArgs = vi.mocked(mockLogger.warn).mock.calls[0];
    expect(warnArgs[0]).toContain("Sigint token redemption threw");
  });

  it("happy path: when redeemSigintTokens resolves, hydrateSigint runs through (sanity)", async () => {
    // Layer-2's anyHydrated check will throw HttpError(400) because the
    // mock returns a payload with no hydrated probes, but the IMPORTANT
    // assertion is: it does NOT throw 503. The function got past the
    // catch arm. Different error → different code path.
    vi.mocked(redeemSigintTokens).mockResolvedValueOnce(makePayload());

    const deps = { logger: mockLogger, metrics: mockMetrics };
    let caught: unknown;
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await hydrateSigint(makePayload(), deps, makeEvent() as any);
    } catch (e) {
      caught = e;
    }
    if (caught instanceof HttpError) {
      // Layer-2 path or downstream — anything BUT 503 is acceptable here.
      expect(caught.statusCode).not.toBe(503);
    }
    // Either way: no 503 → catch arm correctly didn't fire.
  });
});
