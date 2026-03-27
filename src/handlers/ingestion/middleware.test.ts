/**
 * Unit tests for ingestion middleware — specifically the ECDH decrypt path
 * which is not easily exercised via the full handler integration test.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../helpers/get-ecdh-keys", () => ({
  getEcdhKeys: vi.fn(),
  getCurrentRawPublicKey: vi.fn().mockResolvedValue(null),
}));

vi.mock("../../helpers/ecdh-decrypt", () => ({
  decryptArgusPayload: vi.fn(),
}));

import { getEcdhKeys } from "../../helpers/get-ecdh-keys";
import { decryptArgusPayload } from "../../helpers/ecdh-decrypt";
import { binaryGzipBodyParser } from "./middleware";
import { Metrics } from "@aws-lambda-powertools/metrics";

const mockMetrics = {
  addMetric: vi.fn(),
} as unknown as Metrics;

const config = { maxBodyBytes: 1024 * 256, maxDecompressedBytes: 1024 * 2048 };

function makeRequest(headers: Record<string, string>, body = "body") {
  return {
    event: {
      headers,
      body,
      isBase64Encoded: false,
      requestContext: { http: { method: "POST" } },
      rawPath: "/v1/collect",
    },
  } as any;
}

describe("binaryGzipBodyParser — ECDH path", () => {
  beforeEach(() => {
    vi.mocked(getEcdhKeys).mockReset();
    vi.mocked(decryptArgusPayload).mockReset();
    vi.mocked(mockMetrics.addMetric).mockReset();
  });

  it("skips ECDH when content-type is not octet-stream", async () => {
    const mw = binaryGzipBodyParser(config, mockMetrics);
    const request = makeRequest({ "content-type": "application/json" });
    await mw.before!(request);
    expect(getEcdhKeys).not.toHaveBeenCalled();
  });

  it("throws 503 when keys not configured", async () => {
    vi.mocked(getEcdhKeys).mockResolvedValue(null);
    const mw = binaryGzipBodyParser(config, mockMetrics);
    const request = makeRequest({
      "content-type": "application/octet-stream",
      "x-argus-origin": "fakepubkey",
    });
    await expect(mw.before!(request)).rejects.toMatchObject({
      statusCode: 503,
    });
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "EcdhNotConfigured",
      expect.any(String),
      1,
    );
  });

  it("throws 400 when decryption fails", async () => {
    vi.mocked(getEcdhKeys).mockResolvedValue({
      current: {} as any,
      previous: undefined,
    });
    vi.mocked(decryptArgusPayload).mockResolvedValue(null);
    const mw = binaryGzipBodyParser(config, mockMetrics);
    const request = makeRequest({
      "content-type": "application/octet-stream",
      "x-argus-origin": "fakepubkey",
    });
    await expect(mw.before!(request)).rejects.toMatchObject({
      statusCode: 400,
    });
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "EcdhDecryptFailed",
      expect.any(String),
      1,
    );
  });

  it("replaces body with decrypted JSON on success", async () => {
    const decrypted = {
      identifiers: { session_id: "s1" },
      hashes: { stable: "h1", fuzzy: "h2" },
      device: {},
    };
    vi.mocked(getEcdhKeys).mockResolvedValue({
      current: {} as any,
      previous: undefined,
    });
    vi.mocked(decryptArgusPayload).mockResolvedValue(decrypted);
    const mw = binaryGzipBodyParser(config, mockMetrics);
    const request = makeRequest({
      "content-type": "application/octet-stream",
      "x-argus-origin": "fakepubkey",
    });
    await mw.before!(request);
    expect(request.event.body).toBe(JSON.stringify(decrypted));
    expect(request.event.isBase64Encoded).toBe(false);
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "EcdhPayloadReceived",
      expect.any(String),
      1,
    );
  });
});
