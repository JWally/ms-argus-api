import { describe, it, expect } from "vitest";
import {
  DEFAULT_INTEGRITY_TTL_SECONDS,
  resolveIntegrityTtlSeconds,
} from "./ttl";

describe("DEFAULT_INTEGRITY_TTL_SECONDS", () => {
  it("equals 30 days in seconds", () => {
    expect(DEFAULT_INTEGRITY_TTL_SECONDS).toBe(30 * 24 * 60 * 60);
  });

  it("equals exactly 2_592_000", () => {
    expect(DEFAULT_INTEGRITY_TTL_SECONDS).toBe(2_592_000);
  });
});

describe("resolveIntegrityTtlSeconds", () => {
  it("returns the default when env var is unset", () => {
    expect(resolveIntegrityTtlSeconds({})).toBe(DEFAULT_INTEGRITY_TTL_SECONDS);
  });

  it("returns the default when env var is the empty string", () => {
    expect(resolveIntegrityTtlSeconds({ INTEGRITY_TTL_SECONDS: "" })).toBe(
      DEFAULT_INTEGRITY_TTL_SECONDS,
    );
  });

  it("returns the parsed env value when set to a positive integer", () => {
    expect(resolveIntegrityTtlSeconds({ INTEGRITY_TTL_SECONDS: "86400" })).toBe(
      86_400,
    );
  });

  it("returns the parsed env value when set to a positive non-integer", () => {
    expect(
      resolveIntegrityTtlSeconds({ INTEGRITY_TTL_SECONDS: "3600.5" }),
    ).toBe(3_600.5);
  });

  it("falls back to the default for non-numeric env values (typos in stage config)", () => {
    expect(
      resolveIntegrityTtlSeconds({ INTEGRITY_TTL_SECONDS: "thirty days" }),
    ).toBe(DEFAULT_INTEGRITY_TTL_SECONDS);
  });

  it("falls back to the default for zero (would defeat the TTL)", () => {
    expect(resolveIntegrityTtlSeconds({ INTEGRITY_TTL_SECONDS: "0" })).toBe(
      DEFAULT_INTEGRITY_TTL_SECONDS,
    );
  });

  it("falls back to the default for negative values", () => {
    expect(resolveIntegrityTtlSeconds({ INTEGRITY_TTL_SECONDS: "-100" })).toBe(
      DEFAULT_INTEGRITY_TTL_SECONDS,
    );
  });

  it("falls back to the default for Infinity / NaN", () => {
    expect(
      resolveIntegrityTtlSeconds({ INTEGRITY_TTL_SECONDS: "Infinity" }),
    ).toBe(DEFAULT_INTEGRITY_TTL_SECONDS);
    expect(resolveIntegrityTtlSeconds({ INTEGRITY_TTL_SECONDS: "NaN" })).toBe(
      DEFAULT_INTEGRITY_TTL_SECONDS,
    );
  });

  it("does not mutate the env object", () => {
    const env = { INTEGRITY_TTL_SECONDS: "120" };
    resolveIntegrityTtlSeconds(env);
    expect(env).toEqual({ INTEGRITY_TTL_SECONDS: "120" });
  });
});
