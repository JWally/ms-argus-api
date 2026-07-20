/**
 * Unit tests for ingestion middleware — specifically the ECDH decrypt path
 * which is not easily exercised via the full handler integration test.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../helpers/get-ecdh-keys", () => ({
  getEcdhKeys: vi.fn(),
}));

vi.mock("../../helpers/ecdh-decrypt", () => ({
  decryptArgusPayload: vi.fn(),
  decryptIntegrityPayloadV3: vi.fn(),
}));

import { getEcdhKeys } from "../../helpers/get-ecdh-keys";
import {
  decryptArgusPayload,
  decryptIntegrityPayloadV3,
} from "../../helpers/ecdh-decrypt";
import { binaryGzipBodyParser, sigintTokenValidator } from "./middleware";
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
    vi.mocked(decryptIntegrityPayloadV3).mockReset();
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

describe("binaryGzipBodyParser — /v1/integrity-collect seal (Layer 6)", () => {
  function makeCollectRequest(headers: Record<string, string>, body = "body") {
    return {
      event: {
        headers,
        body,
        isBase64Encoded: false,
        requestContext: { http: { method: "POST" } },
        rawPath: "/v1/integrity-collect",
      },
    } as any;
  }

  beforeEach(() => {
    vi.mocked(getEcdhKeys).mockReset();
    vi.mocked(decryptArgusPayload).mockReset();
    vi.mocked(decryptIntegrityPayloadV3).mockReset();
    vi.mocked(mockMetrics.addMetric).mockReset();
  });

  it("rejects integrity-collect POST with application/json (415)", async () => {
    const mw = binaryGzipBodyParser(config, mockMetrics);
    const req = makeCollectRequest({ "content-type": "application/json" });
    await expect(mw.before!(req)).rejects.toMatchObject({ statusCode: 415 });
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "UnencryptedSubmissionRejected",
      expect.any(String),
      1,
    );
  });

  it("rejects integrity-collect POST with octet-stream but no X-Argus-Origin (415)", async () => {
    const mw = binaryGzipBodyParser(config, mockMetrics);
    const req = makeCollectRequest({
      "content-type": "application/octet-stream",
      // x-argus-origin deliberately absent
    });
    await expect(mw.before!(req)).rejects.toMatchObject({ statusCode: 415 });
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "UnencryptedSubmissionRejected",
      expect.any(String),
      1,
    );
  });

  it("uses the v3 uncompressed ECDH decrypt path for X-Argus-V: 3", async () => {
    vi.mocked(getEcdhKeys).mockResolvedValue({
      current: {} as any,
      previous: undefined,
    });
    vi.mocked(decryptIntegrityPayloadV3).mockResolvedValue({
      identifiers: { session_id: "s" },
      device: {},
    });
    const mw = binaryGzipBodyParser(config, mockMetrics);
    const req = makeCollectRequest({
      "content-type": "application/octet-stream",
      "x-argus-origin": "fakepubkey",
      "x-argus-session": "test-session-token",
      "x-argus-v": "3",
    });

    await mw.before!(req);

    expect(decryptIntegrityPayloadV3).toHaveBeenCalledWith(
      expect.objectContaining({
        body: "body",
        isBase64Encoded: false,
        clientPubKey: "fakepubkey",
        sessionToken: "test-session-token",
      }),
    );
    expect(req.event.body).toBe(
      JSON.stringify({ identifiers: { session_id: "s" }, device: {} }),
    );
  });

  it("does not seal non-POST methods (OPTIONS preflight still works)", async () => {
    const mw = binaryGzipBodyParser(config, mockMetrics);
    const req = makeCollectRequest({ "content-type": "application/json" });
    req.event.requestContext.http.method = "OPTIONS";
    await mw.before!(req); // does not throw — preflight passes through
    expect(mockMetrics.addMetric).not.toHaveBeenCalledWith(
      "UnencryptedSubmissionRejected",
      expect.any(String),
      expect.any(Number),
    );
  });

  it("does not seal non-integrity-collect paths (JSON still ok elsewhere)", async () => {
    const mw = binaryGzipBodyParser(config, mockMetrics);
    const req = makeCollectRequest({ "content-type": "application/json" });
    req.event.rawPath = "/some/other/path";
    await mw.before!(req); // does not throw
    expect(mockMetrics.addMetric).not.toHaveBeenCalledWith(
      "UnencryptedSubmissionRejected",
      expect.any(String),
      expect.any(Number),
    );
  });
});

describe("sigintTokenValidator", () => {
  function makeIntegrityRequest(parsedBody: unknown) {
    return {
      event: {
        headers: {},
        body: JSON.stringify(parsedBody ?? {}),
        isBase64Encoded: false,
        requestContext: { http: { method: "POST" } },
        rawPath: "/v1/integrity-collect",
        parsedBody,
      },
    } as any;
  }

  beforeEach(() => {
    vi.mocked(mockMetrics.addMetric).mockReset();
  });

  it("skips non-POST", async () => {
    const mw = sigintTokenValidator(mockMetrics);
    const req = makeIntegrityRequest({});
    req.event.requestContext.http.method = "OPTIONS";
    await mw.before!(req);
    expect(mockMetrics.addMetric).not.toHaveBeenCalled();
  });

  it("skips non-integrity-collect paths", async () => {
    const mw = sigintTokenValidator(mockMetrics);
    const req = makeIntegrityRequest({});
    req.event.rawPath = "/v1/collect";
    await mw.before!(req);
    expect(mockMetrics.addMetric).not.toHaveBeenCalled();
  });

  it("throws 400 when no tokens, emits per-probe absence metrics", async () => {
    const mw = sigintTokenValidator(mockMetrics);
    const req = makeIntegrityRequest({ identifiers: { cpi: "x" } });
    await expect(mw.before!(req)).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringContaining("sigintTcpToken"),
    });
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "SigintTcpProbeAbsent",
      expect.any(String),
      1,
    );
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "SigintCfProbeAbsent",
      expect.any(String),
      1,
    );
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "SigintH2ProbeAbsent",
      expect.any(String),
      1,
    );
  });

  it("throws 400 when only TCP probe present (CF + H2 still required)", async () => {
    const mw = sigintTokenValidator(mockMetrics);
    const req = makeIntegrityRequest({ sigintTcpToken: "nonce.expiry.sig" });
    await expect(mw.before!(req)).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringContaining("sigintTls"),
    });
  });

  it("throws 400 when only CF probe present (TCP + H2 still required)", async () => {
    const mw = sigintTokenValidator(mockMetrics);
    const req = makeIntegrityRequest({ sigintTls: '{"ip":"1.2.3.4"}' });
    await expect(mw.before!(req)).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringContaining("sigintTcpToken"),
    });
  });

  it("throws 400 when H2 probe is absent", async () => {
    const mw = sigintTokenValidator(mockMetrics);
    const req = makeIntegrityRequest({
      sigintTcpToken: "nonce.expiry.sig",
      sigintTls: '{"ip":"1.2.3.4"}',
      // no sigintH2Token
    });
    await expect(mw.before!(req)).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringContaining("sigintH2Token"),
    });
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "SigintH2ProbeAbsent",
      expect.any(String),
      1,
    );
    expect(mockMetrics.addMetric).not.toHaveBeenCalledWith(
      "SigintTcpProbeAbsent",
      expect.any(String),
      expect.any(Number),
    );
  });

  it("allows through when all three probes present", async () => {
    const mw = sigintTokenValidator(mockMetrics);
    const req = makeIntegrityRequest({
      sigintTcpToken: "nonce.expiry.sig",
      sigintTls: '{"ip":"1.2.3.4"}',
      sigintH2Token: "nonce.expiry.sig",
    });
    await expect(mw.before!(req)).resolves.toBeUndefined();
    expect(mockMetrics.addMetric).not.toHaveBeenCalled();
  });

  it("accepts inline sigint.tcp_probe.token + sigint.h2.token as evidence", async () => {
    const mw = sigintTokenValidator(mockMetrics);
    const req = makeIntegrityRequest({
      sigintTls: '{"ip":"1.2.3.4"}',
      sigint: {
        tcp_probe: { token: "nonce.expiry.sig" },
        h2: { token: "nonce.expiry.sig" },
      },
    });
    await expect(mw.before!(req)).resolves.toBeUndefined();
  });

  it("rejects inline encrypted-blob shape as TCP evidence (matches extractInlineToken)", async () => {
    const mw = sigintTokenValidator(mockMetrics);
    // { v, data } envelope is the encrypted-blob shape — extractInlineToken
    // excludes it; we must too, otherwise an attacker could submit a fake
    // encrypted blob to pass the check without owning a real token.
    const req = makeIntegrityRequest({
      sigintTls: '{"ip":"1.2.3.4"}',
      sigintH2Token: "nonce.expiry.sig",
      sigint: { tcp_probe: { v: 1, data: "garbage", token: "looks-real" } },
    });
    await expect(mw.before!(req)).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringContaining("sigintTcpToken"),
    });
  });

  it("rejects empty-string tokens", async () => {
    const mw = sigintTokenValidator(mockMetrics);
    const req = makeIntegrityRequest({
      sigintTls: "",
      sigintTcpToken: "",
      sigintH2Token: "",
    });
    await expect(mw.before!(req)).rejects.toMatchObject({ statusCode: 400 });
  });
});
