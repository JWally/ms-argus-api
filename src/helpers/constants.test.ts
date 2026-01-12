// src/helpers/constants.test.ts
import { describe, it, expect } from "vitest";
import {
  DEFAULT_HEADERS,
  ALLOWED_HEADERS,
  ALLOWED_ORIGINS,
  MIDDY_CORS_CONFIG,
  WARMUP_EVENT,
  AWS_SECRETS_REQUIRED_KEYS,
  ERROR_STRINGS,
} from "./constants";

describe("DEFAULT_HEADERS", () => {
  it("should contain all required security headers", () => {
    expect(DEFAULT_HEADERS).toHaveProperty("Content-Security-Policy");
    expect(DEFAULT_HEADERS).toHaveProperty("Strict-Transport-Security");
    expect(DEFAULT_HEADERS).toHaveProperty("X-Content-Type-Options");
    expect(DEFAULT_HEADERS).toHaveProperty("X-Frame-Options");
    expect(DEFAULT_HEADERS).toHaveProperty("X-XSS-Protection");
  });

  it("should have correct X-Frame-Options value", () => {
    expect(DEFAULT_HEADERS["X-Frame-Options"]).toBe("DENY");
  });

  it("should have HSTS with includeSubDomains", () => {
    expect(DEFAULT_HEADERS["Strict-Transport-Security"]).toContain(
      "includeSubDomains",
    );
  });

  it("should have nosniff for content type", () => {
    expect(DEFAULT_HEADERS["X-Content-Type-Options"]).toBe("nosniff");
  });
});

describe("ALLOWED_HEADERS", () => {
  it("should include Content-Type", () => {
    expect(ALLOWED_HEADERS).toContain("Content-Type");
  });

  it("should include Authorization", () => {
    expect(ALLOWED_HEADERS).toContain("Authorization");
  });

  it("should include Accept headers", () => {
    expect(ALLOWED_HEADERS).toContain("Accept");
    expect(ALLOWED_HEADERS).toContain("Accept-Language");
  });

  it("should include AWS-specific headers", () => {
    expect(ALLOWED_HEADERS).toContain("X-Amz-Date");
    expect(ALLOWED_HEADERS).toContain("X-Amz-Security-Token");
  });

  it("should be an array of strings", () => {
    expect(Array.isArray(ALLOWED_HEADERS)).toBe(true);
    ALLOWED_HEADERS.forEach((header) => {
      expect(typeof header).toBe("string");
    });
  });
});

describe("ALLOWED_ORIGINS", () => {
  it("should be an array of origin strings", () => {
    expect(Array.isArray(ALLOWED_ORIGINS)).toBe(true);
    expect(ALLOWED_ORIGINS.length).toBeGreaterThan(0);
  });

  it("should contain only HTTPS origins", () => {
    ALLOWED_ORIGINS.forEach((origin) => {
      expect(origin).toMatch(/^https:\/\//);
    });
  });

  it("should not contain wildcard origin", () => {
    expect(ALLOWED_ORIGINS).not.toContain("*");
  });
});

describe("MIDDY_CORS_CONFIG", () => {
  it("should allow credentials", () => {
    expect(MIDDY_CORS_CONFIG.credentials).toBe(true);
  });

  it("should use origins array (not wildcard origin)", () => {
    // Security: Using origins array instead of origin: "*"
    // The CORS spec forbids origin: "*" with credentials: true
    expect(MIDDY_CORS_CONFIG.origins).toBeDefined();
    expect(Array.isArray(MIDDY_CORS_CONFIG.origins)).toBe(true);
    expect(MIDDY_CORS_CONFIG.origin).toBeUndefined();
  });

  it("should not use wildcard origin with credentials", () => {
    // Security check: This combination is forbidden by CORS spec
    const hasWildcard = MIDDY_CORS_CONFIG.origins?.includes("*");
    expect(hasWildcard).toBeFalsy();
  });

  it("should only allow POST and OPTIONS methods", () => {
    expect(MIDDY_CORS_CONFIG.methods).toContain("POST");
    expect(MIDDY_CORS_CONFIG.methods).toContain("OPTIONS");
    expect(MIDDY_CORS_CONFIG.methods).not.toContain("GET");
    expect(MIDDY_CORS_CONFIG.methods).not.toContain("DELETE");
  });

  it("should have headers as comma-separated string", () => {
    expect(typeof MIDDY_CORS_CONFIG.headers).toBe("string");
    expect(MIDDY_CORS_CONFIG.headers).toContain("Content-Type");
  });
});

describe("WARMUP_EVENT", () => {
  it("should have correct source", () => {
    expect(WARMUP_EVENT.source).toBe("serverless-plugin-warmup");
  });

  it("should have event with warmup type", () => {
    expect(WARMUP_EVENT.event.source).toBe("warmup");
    expect(WARMUP_EVENT.event.type).toBe("keepalive");
  });
});

describe("AWS_SECRETS_REQUIRED_KEYS", () => {
  it("should include ENCRYPTION_KEY", () => {
    expect(AWS_SECRETS_REQUIRED_KEYS).toContain("ENCRYPTION_KEY");
  });

  it("should include HMAC_KEY", () => {
    expect(AWS_SECRETS_REQUIRED_KEYS).toContain("HMAC_KEY");
  });

  it("should have exactly 2 required keys", () => {
    expect(AWS_SECRETS_REQUIRED_KEYS).toHaveLength(2);
  });
});

describe("ERROR_STRINGS", () => {
  it("should contain all expected error messages", () => {
    expect(ERROR_STRINGS).toHaveProperty("SECRETS_MANAGER_FAILED");
    expect(ERROR_STRINGS).toHaveProperty("KEY_ARN_NOT_SET");
    expect(ERROR_STRINGS).toHaveProperty("CANNOT_PARSE_JSON");
    expect(ERROR_STRINGS).toHaveProperty("CANNOT_DECRYPT");
    expect(ERROR_STRINGS).toHaveProperty("CANNOT_VERIFY_SIGNATURE");
  });

  it("should have descriptive error messages", () => {
    expect(ERROR_STRINGS.SECRETS_MANAGER_FAILED).toContain("Secrets Manager");
    expect(ERROR_STRINGS.CANNOT_PARSE_JSON).toContain("JSON");
  });
});
