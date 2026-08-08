import { MetricUnit, type Metrics } from "@aws-lambda-powertools/metrics";
import type { Logger } from "@aws-lambda-powertools/logger";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ArgusPayload } from "../../helpers/payload-schema";
import type { PhaseTimer } from "../../helpers/phase-timer";

const serviceMocks = vi.hoisted(() => ({
  prewarmAsn: vi.fn(),
  prewarmOverlay: vi.fn(),
  buildRecord: vi.fn(),
}));

vi.mock("../../services/network/asn-classifier", () => ({
  prewarmAsnDataset: serviceMocks.prewarmAsn,
}));
vi.mock("../../services/network/auto-overlay", () => ({
  prewarmAutoOverlay: serviceMocks.prewarmOverlay,
}));
vi.mock("./integrity-record-builder", () => ({
  buildIntegrityRecord: serviceMocks.buildRecord,
}));

import { handleProxyIntegrity } from "./proxy-ingestion";

const logger = { info: vi.fn() } as unknown as Logger;
const metrics = { addMetric: vi.fn() } as unknown as Metrics;
const phaseTimer = {
  mark: vi.fn(),
  record: vi.fn(),
  summary: vi.fn(() => ({ total_ms: 7 })),
} satisfies PhaseTimer;

function makePayload(): ArgusPayload {
  return {
    identifiers: { session_id: "session-1", cpi: "argus_cpi_test" },
    hashes: { stable: "stable", fuzzy: "fuzzy" },
    device: { browser: "fixture" },
    meta: { version: "test", product: "proxy_v1" },
  } as unknown as ArgusPayload;
}

type ProxyArgs = Parameters<typeof handleProxyIntegrity>[0];

function makeArgs(overrides: Partial<ProxyArgs> = {}): ProxyArgs {
  const payload = makePayload();
  return {
    ctx: {
      payload,
      sessionId: "session-1",
      cpi: "argus_cpi_test",
      event: { headers: { "user-agent": "Argus Browser" } },
      deps: { logger, metrics },
      start: 900,
    },
    hydratedPayload: payload,
    phaseTimer,
    ttlSeconds: 2_592_000,
    resolveMerchantId: vi.fn().mockResolvedValue("merchant-1"),
    enrichAndProject: vi.fn(async (item) => ({ ...item, projected: true })),
    persist: vi.fn().mockResolvedValue({ duplicate: false }),
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  serviceMocks.prewarmAsn.mockResolvedValue(undefined);
  serviceMocks.prewarmOverlay.mockResolvedValue(undefined);
  serviceMocks.buildRecord.mockReturnValue({
    keep: true,
    analysis: {
      device_history: { scan_count: 12 },
      network: { proxy: true },
    },
  });
  process.env.SIGINT_AES_KEY = "sigint-key";
  process.env.PHASE_TIMING = "true";
  vi.spyOn(Date, "now").mockReturnValue(1_000);
});

afterEach(() => {
  delete process.env.SIGINT_AES_KEY;
  delete process.env.PHASE_TIMING;
  vi.restoreAllMocks();
});

describe("handleProxyIntegrity", () => {
  it("runs the reduced ingestion path and strips full-product history", async () => {
    const args = makeArgs();

    await expect(handleProxyIntegrity(args)).resolves.toEqual({
      statusCode: 200,
      body: JSON.stringify({ session_id: "session-1" }),
      headers: { "Content-Type": "application/json" },
    });

    expect(serviceMocks.prewarmAsn).toHaveBeenCalledOnce();
    expect(serviceMocks.prewarmOverlay).toHaveBeenCalledOnce();
    expect(args.resolveMerchantId).toHaveBeenCalledOnce();
    expect(serviceMocks.buildRecord).toHaveBeenCalledWith(
      expect.objectContaining({
        identity: {
          present: false,
          verified: false,
          pubkey: null,
          sig_present: false,
          reason: "absent",
        },
        merchantId: "merchant-1",
        sigintAesKey: "sigint-key",
        ttlSeconds: 2_592_000,
        deviceHistory: expect.objectContaining({ scanCount: 0 }),
      }),
    );
    expect(args.enrichAndProject).toHaveBeenCalledWith(
      {
        keep: true,
        analysis: { network: { proxy: true } },
      },
      expect.objectContaining({ present: false, verified: false }),
    );
    expect(args.persist).toHaveBeenCalledWith({
      keep: true,
      analysis: { network: { proxy: true } },
      projected: true,
    });
    expect(phaseTimer.mark.mock.calls.map(([name]) => name)).toEqual([
      "identity",
      "analysis",
      "velocity",
      "persist",
    ]);
    expect(phaseTimer.record.mock.calls.map(([name]) => name).sort()).toEqual([
      "id_asn",
      "id_merchant",
      "id_overlay",
    ]);
    expect(metrics.addMetric).toHaveBeenCalledWith(
      "ProxyIntegrityStored",
      MetricUnit.Count,
      1,
    );
    expect(metrics.addMetric).toHaveBeenCalledWith(
      "IntegrityDuration",
      MetricUnit.Milliseconds,
      100,
    );
    expect(logger.info).toHaveBeenCalledWith("phase_timing", { total_ms: 7 });
  });

  it("keeps sparse records intact and suppresses the stored metric for duplicates", async () => {
    delete process.env.PHASE_TIMING;
    serviceMocks.buildRecord.mockReturnValue({ keep: true });
    const persist = vi.fn().mockResolvedValue({ duplicate: true });
    const args = makeArgs({ persist });

    await handleProxyIntegrity(args);

    expect(args.enrichAndProject).toHaveBeenCalledWith(
      { keep: true },
      expect.any(Object),
    );
    expect(metrics.addMetric).not.toHaveBeenCalledWith(
      "ProxyIntegrityStored",
      expect.anything(),
      expect.anything(),
    );
    expect(metrics.addMetric).toHaveBeenCalledWith(
      "IntegrityDuration",
      MetricUnit.Milliseconds,
      100,
    );
    expect(logger.info).not.toHaveBeenCalled();
  });
});
