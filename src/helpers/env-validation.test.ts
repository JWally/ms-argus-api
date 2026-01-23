import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { validateRequiredEnvVars } from "./env-validation";

describe("validateRequiredEnvVars", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("should not throw when all required vars are present", () => {
    process.env.FOO = "bar";
    process.env.BAZ = "qux";

    expect(() => validateRequiredEnvVars(["FOO", "BAZ"])).not.toThrow();
  });

  it("should throw listing missing variables", () => {
    delete process.env.MISSING_VAR;
    delete process.env.ANOTHER_MISSING;

    expect(() =>
      validateRequiredEnvVars(["MISSING_VAR", "ANOTHER_MISSING"]),
    ).toThrow(
      "Missing required environment variables: MISSING_VAR, ANOTHER_MISSING",
    );
  });

  it("should throw for a single missing variable", () => {
    process.env.PRESENT = "yes";
    delete process.env.ABSENT;

    expect(() => validateRequiredEnvVars(["PRESENT", "ABSENT"])).toThrow(
      "Missing required environment variables: ABSENT",
    );
  });

  it("should pass with an empty required list", () => {
    expect(() => validateRequiredEnvVars([])).not.toThrow();
  });
});
