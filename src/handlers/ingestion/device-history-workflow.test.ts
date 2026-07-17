import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Metrics } from "@aws-lambda-powertools/metrics";
import type { DeviceHistoryAnalysis } from "../../analysis/device-history";
import type { IdentityOutcome } from "../../helpers/device-identity";
import type {
  DeviceHistoryBlob,
  ProcessDeviceHistoryResult,
} from "../../helpers/device-history";
import type { ArgusPayload } from "../../helpers/payload-schema";

const historyMocks = vi.hoisted(() => ({
  process: vi.fn(),
  hashUserAgent: vi.fn(),
}));
const analysisMocks = vi.hoisted(() => ({ compute: vi.fn() }));
const networkMocks = vi.hoisted(() => ({ classifyAsn: vi.fn() }));

vi.mock("../../helpers/device-history", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("../../helpers/device-history")>();
  return {
    ...actual,
    processDeviceHistory: historyMocks.process,
    hashUserAgent: historyMocks.hashUserAgent,
  };
});

vi.mock("../../analysis/device-history", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("../../analysis/device-history")>();
  return { ...actual, computeDeviceHistoryAnalysis: analysisMocks.compute };
});

vi.mock("../../services/network/asn-classifier", async (importOriginal) => {
  const actual =
    await importOriginal<
      typeof import("../../services/network/asn-classifier")
    >();
  return { ...actual, classifyAsnSync: networkMocks.classifyAsn };
});

import {
  runDeviceHistoryWorkflow,
  type DeviceHistoryWorkflowContext,
} from "./device-history-workflow";

const metrics = { addMetric: vi.fn() } as unknown as Metrics;

function makeContext(
  headers: Record<string, string | undefined> = {},
): DeviceHistoryWorkflowContext {
  return {
    payload: {
      identifiers: { session_id: "session-123", cpi: "argus_cpi_test" },
      hashes: { stable: "stable", fuzzy: "fuzzy" },
      device: {},
      cache: "incoming-cache",
    } as ArgusPayload,
    cpi: "argus_cpi_test",
    sessionId: "session-123",
    event: {
      headers,
      requestContext: { http: { sourceIp: "203.0.113.7" } },
    },
    deps: { metrics },
  };
}

function identity(pubkey: string | null = "device-pubkey"): IdentityOutcome {
  if (pubkey) {
    return { present: true, verified: true, pubkey, sig_present: true };
  }
  return {
    present: false,
    verified: false,
    pubkey: null,
    sig_present: false,
    reason: "absent",
  };
}

const historyBlob: DeviceHistoryBlob = {
  v: 1,
  id: "device-pubkey",
  created: 1,
  updated: 2,
  visits: [],
};

function historyResult(
  overrides: Partial<ProcessDeviceHistoryResult> = {},
): ProcessDeviceHistoryResult {
  return {
    outcomeKind: "absent",
    identityMatched: false,
    outboundBlob: "outbound-cache",
    preVisitBlob: historyBlob,
    ...overrides,
  };
}

const analysis: DeviceHistoryAnalysis = {
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

beforeEach(() => {
  vi.clearAllMocks();
  historyMocks.hashUserAgent.mockReturnValue("ua-hash");
  networkMocks.classifyAsn.mockReturnValue("mobile");
  historyMocks.process.mockReturnValue(historyResult());
  analysisMocks.compute.mockReturnValue(analysis);
});

describe("runDeviceHistoryWorkflow", () => {
  it("builds a server-observed visit from request and CloudFront headers", () => {
    const result = runDeviceHistoryWorkflow({
      ctx: makeContext({
        "user-agent": "Argus Browser",
        "cloudfront-viewer-asn": "64512",
        "cloudfront-viewer-country": "us",
        "cloudfront-viewer-country-region": "US-TX",
        "cloudfront-viewer-city": "Dallas",
        "cloudfront-viewer-latitude": "32.7767",
        "cloudfront-viewer-longitude": "-96.7970",
      }),
      identity: identity(),
      sigintAesKey: "aes-key",
    });

    expect(historyMocks.hashUserAgent).toHaveBeenCalledWith("Argus Browser");
    expect(networkMocks.classifyAsn).toHaveBeenCalledWith(64512);
    expect(historyMocks.process).toHaveBeenCalledWith({
      incomingBlob: "incoming-cache",
      pubkey: "device-pubkey",
      sigintAesKey: "aes-key",
      visit: {
        cpi: "argus_cpi_test",
        session: "session-123",
        ip: "203.0.113.7",
        ua_hash: "ua-hash",
        net_class: "mobile",
        country: "US",
        region: "US-TX",
        city: "Dallas",
        lat: 32.7767,
        lon: -96.797,
      },
    });
    expect(result).toEqual({ dh: expect.any(Object), analysis });
  });

  it("maps malformed optional location and ASN headers to null", () => {
    runDeviceHistoryWorkflow({
      ctx: makeContext({
        "cloudfront-viewer-asn": "not-an-asn",
        "cloudfront-viewer-latitude": "north",
        "cloudfront-viewer-longitude": "west",
      }),
      identity: identity(null),
      sigintAesKey: undefined,
    });

    expect(networkMocks.classifyAsn).not.toHaveBeenCalled();
    expect(historyMocks.process).toHaveBeenCalledWith(
      expect.objectContaining({
        pubkey: null,
        sigintAesKey: undefined,
        visit: expect.objectContaining({
          ua_hash: "ua-hash",
          net_class: null,
          country: null,
          region: null,
          city: null,
          lat: null,
          lon: null,
        }),
      }),
    );
  });

  it("analyzes a matched round trip with the pre-visit blob", () => {
    const dh = historyResult({
      outcomeKind: "ok",
      identityMatched: true,
      preVisitBlob: historyBlob,
    });
    historyMocks.process.mockReturnValueOnce(dh);

    const result = runDeviceHistoryWorkflow({
      ctx: makeContext(),
      identity: identity(),
      sigintAesKey: "aes-key",
    });

    expect(analysisMocks.compute).toHaveBeenCalledWith({
      outcome: { kind: "ok", blob: historyBlob },
      pubkey: "device-pubkey",
    });
    expect(metrics.addMetric).toHaveBeenCalledWith(
      "DeviceHistoryRoundtrip",
      "Count",
      1,
    );
    expect(result).toEqual({ dh, analysis });
  });

  it("preserves auth failures for tampering analysis and metrics", () => {
    historyMocks.process.mockReturnValueOnce(
      historyResult({ outcomeKind: "auth_fail", preVisitBlob: historyBlob }),
    );

    runDeviceHistoryWorkflow({
      ctx: makeContext(),
      identity: identity(),
      sigintAesKey: "aes-key",
    });

    expect(analysisMocks.compute).toHaveBeenCalledWith({
      outcome: { kind: "auth_fail" },
      pubkey: "device-pubkey",
    });
    expect(metrics.addMetric).toHaveBeenCalledWith(
      "DeviceHistoryAuthFail",
      "Count",
      1,
    );
  });

  it("classifies an absent history blob as a fresh device", () => {
    runDeviceHistoryWorkflow({
      ctx: makeContext(),
      identity: identity(),
      sigintAesKey: "aes-key",
    });

    expect(analysisMocks.compute).toHaveBeenCalledWith({
      outcome: { kind: "absent" },
      pubkey: "device-pubkey",
    });
    expect(metrics.addMetric).toHaveBeenCalledWith(
      "DeviceHistoryAbsent",
      "Count",
      1,
    );
  });

  it("treats a decrypted identity mismatch as absent for analysis", () => {
    historyMocks.process.mockReturnValueOnce(
      historyResult({ outcomeKind: "ok", identityMatched: false }),
    );

    runDeviceHistoryWorkflow({
      ctx: makeContext(),
      identity: identity(),
      sigintAesKey: "aes-key",
    });

    expect(analysisMocks.compute).toHaveBeenCalledWith({
      outcome: { kind: "absent" },
      pubkey: "device-pubkey",
    });
    expect(metrics.addMetric).toHaveBeenCalledWith(
      "DeviceHistoryIdentityMismatch",
      "Count",
      1,
    );
  });
});
