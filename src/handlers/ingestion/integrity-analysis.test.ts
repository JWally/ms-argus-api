import { describe, expect, it } from "vitest";
import type { DeviceHistoryAnalysis } from "../../analysis/device-history";
import type { ArgusPayload } from "../../helpers/payload-schema";
import {
  buildAnalysisBlock,
  buildIdentificationField,
  buildPatFields,
  captureRequestHeaders,
  sigintSummary,
} from "./integrity-analysis";

function payload(overrides: Partial<ArgusPayload> = {}): ArgusPayload {
  return {
    identifiers: { session_id: "session-1", cpi: "argus_cpi_test" },
    hashes: { stable: "stable", fuzzy: "fuzzy" },
    device: {},
    ...overrides,
  } as ArgusPayload;
}

const freshHistory: DeviceHistoryAnalysis = {
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

describe("integrity analysis request evidence", () => {
  it("captures only allowlisted headers and cookie names", () => {
    expect(
      captureRequestHeaders({
        headers: {
          "user-agent": "test-agent",
          origin: "https://pair.example",
          authorization: "Bearer secret",
          cookie: "session=secret",
          "x-untrusted-extra": "drop-me",
        },
        cookies: ["fpid=secret-value", " theme=dark"],
      }),
    ).toEqual({
      headers: {
        "user-agent": "test-agent",
        origin: "https://pair.example",
      },
      cookie_names: ["fpid", "theme"],
    });
  });

  it("summarizes token presence without persisting token values", () => {
    expect(
      sigintSummary(
        payload({ sigintTcpToken: "secret", sigintTls: "tls-secret" }),
      ),
    ).toEqual({ tls: "present", tcp_token: "present", h2_token: "absent" });
  });

  it("omits absent identity and normalizes verified identity", () => {
    expect(
      buildIdentificationField({
        present: false,
        verified: false,
        pubkey: null,
        sig_present: false,
        reason: "absent",
      }),
    ).toBeUndefined();
    expect(
      buildIdentificationField({
        present: true,
        verified: true,
        pubkey: "public-key",
        sig_present: true,
      }),
    ).toEqual({
      pubkey: "public-key",
      verified: true,
      reason: null,
      sig_present: true,
    });
  });

  it("persists PAT outcomes but never the signed token", () => {
    const fields = buildPatFields(
      payload({
        patToken: "signed-secret",
        pat: {
          attested: true,
          issuer: "issuer.example",
          tokenHash: "hash",
          redeemedAt: 123,
        },
        patAttempt: { attempted: true, verified: true },
        patDiag: '{"status":200}',
      }),
    );
    expect(fields).toEqual({
      pat: {
        attested: true,
        issuer: "issuer.example",
        tokenHash: "hash",
        redeemedAt: 123,
      },
      patAttempt: { attempted: true, verified: true },
      patDiag: '{"status":200}',
    });
    expect(fields).not.toHaveProperty("patToken");
  });

  it("assembles every analyzer axis and preserves device history", () => {
    const analysis = buildAnalysisBlock({
      raw: { device: {} },
      hydratedPayload: payload({ sigint: {} }),
      clientIp: "203.0.113.7",
      ua: "Mozilla/5.0",
      acceptLanguage: "en-US",
      requestHeaders: { "sec-ch-ua": '"Chromium";v="126"' },
      webrtcSigint: {
        decoded: null,
        candidateCount: 0,
        reason: "no_candidates",
      },
      webrtcSigintField: undefined,
      deviceHistory: freshHistory,
    });
    expect(analysis).toMatchObject({
      device_history: freshHistory,
      network: expect.any(Object),
      worker: expect.any(Object),
      timezone: expect.any(Object),
      ip: expect.any(Object),
      ja4_ua: expect.any(Object),
      kernel_os: expect.any(Object),
      browser_engine: expect.any(Object),
      locale_geo: expect.any(Object),
      client_hints_ua: expect.any(Object),
      proxy_waterfall: expect.any(Object),
    });
    expect(analysis).not.toHaveProperty("webrtc_sigint");
  });
});
