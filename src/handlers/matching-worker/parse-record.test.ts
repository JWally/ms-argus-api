import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createCipheriv, randomBytes } from "crypto";
import { SQSRecord } from "aws-lambda";
import { parseSqsRecord } from "./parse-record";
import type { EncryptedResponse } from "../../helpers/decrypt-probe";

const TEST_KEY_HEX = "a".repeat(64);

function encrypt(data: unknown): EncryptedResponse {
  const key = Buffer.from(TEST_KEY_HEX, "hex");
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const plaintext = Buffer.from(JSON.stringify(data), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const combined = Buffer.concat([nonce, ciphertext, tag]);
  return { v: 1, data: combined.toString("base64") };
}

const mockLogger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
const mockMetrics = { addMetric: vi.fn() };
const deps = { logger: mockLogger as any, metrics: mockMetrics as any };

function makeRecord(body: unknown): SQSRecord {
  return {
    messageId: "msg-1",
    body: JSON.stringify(body),
  } as SQSRecord;
}

const basePayload = {
  identifiers: { session_id: "sess-abc" },
  hashes: { stable: "s1", fuzzy: "f1" },
  device: {},
};

describe("parseSqsRecord — decryptSigintProbes", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    delete process.env.SIGINT_AES_KEY;
  });

  afterEach(() => {
    delete process.env.SIGINT_AES_KEY;
  });

  it("passes through plain sigint probes unchanged when no key set", () => {
    const payload = {
      ...basePayload,
      sigint: {
        tcpProbe: { tcp_info: null, rtt_fingerprint: { proxy_score: 0.1 } },
        h2Probe: { h2_fingerprint: { fingerprint: "abc" } },
      },
    };
    const result = parseSqsRecord(makeRecord(payload), deps);
    expect(result).not.toBeNull();
    expect(result!.rawPayload.sigint?.tcpProbe).toEqual(
      payload.sigint.tcpProbe,
    );
    expect(result!.rawPayload.sigint?.h2Probe).toEqual(payload.sigint.h2Probe);
  });

  it("decrypts encrypted tcpProbe when SIGINT_AES_KEY is set", () => {
    process.env.SIGINT_AES_KEY = TEST_KEY_HEX;
    const plainTcp = {
      tcp_info: { rtt: 5000 },
      rtt_fingerprint: {
        proxy_score: 0.2,
        vpn_score: 0.0,
        tls_to_tcp_ratio: 1.1,
      },
      client_ip: "1.2.3.4",
      domain: "test.io",
    };
    const payload = {
      ...basePayload,
      sigint: { tcpProbe: encrypt(plainTcp) },
    };
    const result = parseSqsRecord(makeRecord(payload), deps);
    expect(result).not.toBeNull();
    expect(result!.rawPayload.sigint?.tcpProbe).toEqual(plainTcp);
    expect(mockLogger.warn).not.toHaveBeenCalled();
  });

  it("decrypts encrypted h2Probe when SIGINT_AES_KEY is set", () => {
    process.env.SIGINT_AES_KEY = TEST_KEY_HEX;
    const plainH2 = {
      h2_fingerprint: { fingerprint: "1:65536|15663105|0|m,p,a,s" },
      client_ip: "5.6.7.8",
      domain: "test.io",
    };
    const payload = {
      ...basePayload,
      sigint: { h2Probe: encrypt(plainH2) },
    };
    const result = parseSqsRecord(makeRecord(payload), deps);
    expect(result).not.toBeNull();
    expect(result!.rawPayload.sigint?.h2Probe).toEqual(plainH2);
  });

  it("decrypts both probes in one pass", () => {
    process.env.SIGINT_AES_KEY = TEST_KEY_HEX;
    const plainTcp = {
      tcp_info: null,
      rtt_fingerprint: null,
      client_ip: "1.2.3.4",
      domain: "x",
    };
    const plainH2 = { h2_fingerprint: null, client_ip: "1.2.3.4", domain: "x" };
    const payload = {
      ...basePayload,
      sigint: { tcpProbe: encrypt(plainTcp), h2Probe: encrypt(plainH2) },
    };
    const result = parseSqsRecord(makeRecord(payload), deps);
    expect(result).not.toBeNull();
    expect(result!.rawPayload.sigint?.tcpProbe).toEqual(plainTcp);
    expect(result!.rawPayload.sigint?.h2Probe).toEqual(plainH2);
  });

  it("logs warning and continues on decryption failure", () => {
    process.env.SIGINT_AES_KEY = TEST_KEY_HEX;
    // Encrypted with a different key — will fail GCM auth
    const wrongKey = "b".repeat(64);
    const encryptedWithWrongKey = (() => {
      const key = Buffer.from(wrongKey, "hex");
      const nonce = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, nonce);
      const ct = Buffer.concat([
        cipher.update(Buffer.from("{}")),
        cipher.final(),
      ]);
      const tag = cipher.getAuthTag();
      return { v: 1, data: Buffer.concat([nonce, ct, tag]).toString("base64") };
    })();
    const payload = {
      ...basePayload,
      sigint: { tcpProbe: encryptedWithWrongKey },
    };
    // Should not throw — just warn and continue
    const result = parseSqsRecord(makeRecord(payload), deps);
    expect(result).not.toBeNull();
    expect(mockLogger.warn).toHaveBeenCalledWith(
      expect.stringContaining("decrypt"),
      expect.any(Object),
    );
  });

  it("skips decryption when sigint is absent", () => {
    process.env.SIGINT_AES_KEY = TEST_KEY_HEX;
    const result = parseSqsRecord(makeRecord(basePayload), deps);
    expect(result).not.toBeNull();
    expect(mockLogger.warn).not.toHaveBeenCalled();
  });

  it("skips decryption when probes are plain objects (no key)", () => {
    const payload = {
      ...basePayload,
      sigint: { tcpProbe: { tcp_info: null, rtt_fingerprint: null } },
    };
    const result = parseSqsRecord(makeRecord(payload), deps);
    expect(result).not.toBeNull();
    expect((result!.rawPayload.sigint?.tcpProbe as any)?.tcp_info).toBeNull();
  });

  it("returns null for malformed JSON", () => {
    const record = { messageId: "bad", body: "not-json" } as SQSRecord;
    const result = parseSqsRecord(record, deps);
    expect(result).toBeNull();
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "MalformedPayload",
      expect.any(String),
      1,
    );
  });

  it("returns null for missing session_id", () => {
    const payload = { hashes: { stable: "s", fuzzy: "f" }, device: {} };
    const result = parseSqsRecord(makeRecord(payload), deps);
    expect(result).toBeNull();
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "MissingSessionId",
      expect.any(String),
      1,
    );
  });
});
