import { describe, it, expect } from "vitest";
import {
  getSessionId,
  isArgusPayload,
  validateSessionResponse,
  type ArgusPayload,
} from "./payload-schema";

describe("payload-schema", () => {
  describe("getSessionId", () => {
    it("extracts session_id from payload", () => {
      const payload: ArgusPayload = {
        identifiers: { session_id: "test-session-123" },
        hashes: { stable: "abc", fuzzy: "def" },
        device: {},
      };
      expect(getSessionId(payload)).toBe("test-session-123");
    });
  });

  describe("isArgusPayload", () => {
    it("returns true for valid minimal payload", () => {
      const payload = {
        identifiers: { session_id: "sess-1" },
        hashes: { stable: "abc", fuzzy: "def" },
        device: {},
      };
      expect(isArgusPayload(payload)).toBe(true);
    });

    it("returns true for payload with optional fields", () => {
      const payload = {
        identifiers: {
          session_id: "sess-1",
          evercookie_id: "ec-123",
          public_key: "pk-456",
        },
        hashes: { stable: "abc", fuzzy: "def", canvas: "ghi" },
        device: { navigator: { userAgent: "Chrome" } },
        sigint: { tlsFingerprint: { ip: "1.2.3.4" } },
      };
      expect(isArgusPayload(payload)).toBe(true);
    });

    it("returns false for null", () => {
      expect(isArgusPayload(null)).toBe(false);
    });

    it("returns false for undefined", () => {
      expect(isArgusPayload(undefined)).toBe(false);
    });

    it("returns false for non-object primitives", () => {
      expect(isArgusPayload("string")).toBe(false);
      expect(isArgusPayload(123)).toBe(false);
      expect(isArgusPayload(true)).toBe(false);
    });

    it("returns false when identifiers is missing", () => {
      expect(
        isArgusPayload({
          hashes: { stable: "a", fuzzy: "b" },
          device: {},
        }),
      ).toBe(false);
    });

    it("returns false when identifiers is not an object", () => {
      expect(
        isArgusPayload({
          identifiers: "string",
          hashes: { stable: "a", fuzzy: "b" },
          device: {},
        }),
      ).toBe(false);
    });

    it("returns false when session_id is missing", () => {
      expect(
        isArgusPayload({
          identifiers: { evercookie_id: "ec" },
          hashes: { stable: "a", fuzzy: "b" },
          device: {},
        }),
      ).toBe(false);
    });

    it("returns false when session_id is not a string", () => {
      expect(
        isArgusPayload({
          identifiers: { session_id: 123 },
          hashes: { stable: "a", fuzzy: "b" },
          device: {},
        }),
      ).toBe(false);
    });

    it("returns false when hashes is missing", () => {
      expect(
        isArgusPayload({
          identifiers: { session_id: "s" },
          device: {},
        }),
      ).toBe(false);
    });

    it("returns false when hashes is not an object", () => {
      expect(
        isArgusPayload({
          identifiers: { session_id: "s" },
          hashes: "not-object",
          device: {},
        }),
      ).toBe(false);
    });

    it("returns false when stable hash is missing", () => {
      expect(
        isArgusPayload({
          identifiers: { session_id: "s" },
          hashes: { fuzzy: "b" },
          device: {},
        }),
      ).toBe(false);
    });

    it("returns false when stable hash is not a string", () => {
      expect(
        isArgusPayload({
          identifiers: { session_id: "s" },
          hashes: { stable: 123, fuzzy: "b" },
          device: {},
        }),
      ).toBe(false);
    });

    it("returns false when fuzzy hash is missing", () => {
      expect(
        isArgusPayload({
          identifiers: { session_id: "s" },
          hashes: { stable: "a" },
          device: {},
        }),
      ).toBe(false);
    });

    it("returns false when fuzzy hash is not a string", () => {
      expect(
        isArgusPayload({
          identifiers: { session_id: "s" },
          hashes: { stable: "a", fuzzy: null },
          device: {},
        }),
      ).toBe(false);
    });

    it("returns false when device is missing", () => {
      expect(
        isArgusPayload({
          identifiers: { session_id: "s" },
          hashes: { stable: "a", fuzzy: "b" },
        }),
      ).toBe(false);
    });

    it("returns false when device is not an object", () => {
      expect(
        isArgusPayload({
          identifiers: { session_id: "s" },
          hashes: { stable: "a", fuzzy: "b" },
          device: "not-object",
        }),
      ).toBe(false);
    });

    it("returns false when device is null", () => {
      expect(
        isArgusPayload({
          identifiers: { session_id: "s" },
          hashes: { stable: "a", fuzzy: "b" },
          device: null,
        }),
      ).toBe(false);
    });
  });

  describe("validateSessionResponse", () => {
    const validResponse = {
      identifiers: { session_id: "sess-1", device_id: "dev-1" },
      analysis: {
        status: "complete",
        confidence: 0.95,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.1,
        flags: [],
        evidence_codes: ["STABLE_HASH_MATCH"],
      },
      hashes: { stable: "abc", fuzzy: "def" },
      device: { navigator: {} },
    };

    it("returns valid response unchanged", () => {
      const result = validateSessionResponse(validResponse);
      expect(result).toBe(validResponse);
    });

    it("throws for null input", () => {
      expect(() => validateSessionResponse(null)).toThrow("not an object");
    });

    it("throws for undefined input", () => {
      expect(() => validateSessionResponse(undefined)).toThrow("not an object");
    });

    it("throws for non-object input", () => {
      expect(() => validateSessionResponse("string")).toThrow("not an object");
      expect(() => validateSessionResponse(42)).toThrow("not an object");
    });

    it("throws when identifiers is missing", () => {
      const { identifiers: _identifiers, ...rest } = validResponse;
      expect(() => validateSessionResponse(rest)).toThrow(
        "missing identifiers",
      );
    });

    it("throws when identifiers is not an object", () => {
      expect(() =>
        validateSessionResponse({ ...validResponse, identifiers: "bad" }),
      ).toThrow("missing identifiers");
    });

    it("throws when session_id is missing from identifiers", () => {
      expect(() =>
        validateSessionResponse({
          ...validResponse,
          identifiers: { device_id: "d" },
        }),
      ).toThrow("missing session_id");
    });

    it("throws when session_id is not a string", () => {
      expect(() =>
        validateSessionResponse({
          ...validResponse,
          identifiers: { session_id: 123, device_id: "d" },
        }),
      ).toThrow("missing session_id");
    });

    it("throws when device_id is missing from identifiers", () => {
      expect(() =>
        validateSessionResponse({
          ...validResponse,
          identifiers: { session_id: "s" },
        }),
      ).toThrow("missing device_id");
    });

    it("throws when device_id is not a string", () => {
      expect(() =>
        validateSessionResponse({
          ...validResponse,
          identifiers: { session_id: "s", device_id: null },
        }),
      ).toThrow("missing device_id");
    });

    it("throws when analysis is missing", () => {
      const { analysis: _analysis, ...rest } = validResponse;
      expect(() => validateSessionResponse(rest)).toThrow("missing analysis");
    });

    it("throws when analysis is not an object", () => {
      expect(() =>
        validateSessionResponse({ ...validResponse, analysis: [] }),
      ).toThrow("missing analysis");
    });

    it("throws when analysis.status is missing", () => {
      expect(() =>
        validateSessionResponse({
          ...validResponse,
          analysis: { ...validResponse.analysis, status: undefined },
        }),
      ).toThrow("missing analysis.status");
    });

    it("throws when analysis.status is not a string", () => {
      expect(() =>
        validateSessionResponse({
          ...validResponse,
          analysis: { ...validResponse.analysis, status: 123 },
        }),
      ).toThrow("missing analysis.status");
    });

    it("throws when analysis.confidence is missing", () => {
      expect(() =>
        validateSessionResponse({
          ...validResponse,
          analysis: { ...validResponse.analysis, confidence: undefined },
        }),
      ).toThrow("missing analysis.confidence");
    });

    it("throws when analysis.confidence is not a number", () => {
      expect(() =>
        validateSessionResponse({
          ...validResponse,
          analysis: { ...validResponse.analysis, confidence: "high" },
        }),
      ).toThrow("missing analysis.confidence");
    });

    it("throws when hashes is missing", () => {
      const { hashes: _hashes, ...rest } = validResponse;
      expect(() => validateSessionResponse(rest)).toThrow("missing hashes");
    });

    it("throws when hashes.stable is missing", () => {
      expect(() =>
        validateSessionResponse({
          ...validResponse,
          hashes: { fuzzy: "f" },
        }),
      ).toThrow("missing hashes.stable");
    });

    it("throws when hashes.stable is not a string", () => {
      expect(() =>
        validateSessionResponse({
          ...validResponse,
          hashes: { stable: 0, fuzzy: "f" },
        }),
      ).toThrow("missing hashes.stable");
    });

    it("throws when hashes.fuzzy is missing", () => {
      expect(() =>
        validateSessionResponse({
          ...validResponse,
          hashes: { stable: "s" },
        }),
      ).toThrow("missing hashes.fuzzy");
    });

    it("throws when hashes.fuzzy is not a string", () => {
      expect(() =>
        validateSessionResponse({
          ...validResponse,
          hashes: { stable: "s", fuzzy: 999 },
        }),
      ).toThrow("missing hashes.fuzzy");
    });

    it("throws when device is missing", () => {
      const { device: _device, ...rest } = validResponse;
      expect(() => validateSessionResponse(rest)).toThrow("missing device");
    });

    it("throws when device is not an object", () => {
      expect(() =>
        validateSessionResponse({ ...validResponse, device: "bad" }),
      ).toThrow("missing device");
    });

    it("throws when device is null", () => {
      expect(() =>
        validateSessionResponse({ ...validResponse, device: null }),
      ).toThrow("missing device");
    });

    it("accepts response with optional sigint", () => {
      const withSigint = {
        ...validResponse,
        sigint: { tlsFingerprint: { ip: "1.2.3.4" } },
      };
      expect(() => validateSessionResponse(withSigint)).not.toThrow();
    });

    it("accepts response with extra fields", () => {
      const withExtra = { ...validResponse, extra_field: "value" };
      expect(() => validateSessionResponse(withExtra)).not.toThrow();
    });
  });
});
