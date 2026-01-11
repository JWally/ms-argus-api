// src/helpers/constants.test.ts
import { describe, it, expect } from "vitest";
import {
  DEFAULT_HEADERS,
  ALLOWED_HEADERS,
  MIDDY_CORS_CONFIG,
  WARMUP_EVENT,
  AWS_SECRETS_REQUIRED_KEYS,
  ERROR_STRINGS,
  ARGUS_COLUMNS,
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

describe("MIDDY_CORS_CONFIG", () => {
  it("should allow credentials", () => {
    expect(MIDDY_CORS_CONFIG.credentials).toBe(true);
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

describe("ARGUS_COLUMNS", () => {
  it("should be an array of column definitions", () => {
    expect(Array.isArray(ARGUS_COLUMNS)).toBe(true);
    expect(ARGUS_COLUMNS.length).toBeGreaterThan(0);
  });

  it("should have session_id as first column", () => {
    expect(ARGUS_COLUMNS[0].name).toBe("session_id");
    expect(ARGUS_COLUMNS[0].type).toBe("string");
  });

  it("should have ipAddress column", () => {
    const ipColumn = ARGUS_COLUMNS.find((col) => col.name === "ipAddress");
    expect(ipColumn).toBeDefined();
    expect(ipColumn?.type).toBe("string");
  });

  it("should have TCP fingerprint columns", () => {
    const tcpColumns = ARGUS_COLUMNS.filter((col) =>
      col.name?.startsWith("tcp."),
    );
    expect(tcpColumns.length).toBeGreaterThan(0);
  });

  it("should have TLS fingerprint columns", () => {
    const tlsColumns = ARGUS_COLUMNS.filter((col) =>
      col.name?.startsWith("tls."),
    );
    expect(tlsColumns.length).toBeGreaterThan(0);
    expect(tlsColumns.find((c) => c.name === "tls.ja3")).toBeDefined();
    expect(tlsColumns.find((c) => c.name === "tls.ja4")).toBeDefined();
  });

  it("should have JS fingerprint columns", () => {
    const jsColumns = ARGUS_COLUMNS.filter((col) =>
      col.name?.startsWith("js."),
    );
    expect(jsColumns.length).toBeGreaterThan(0);
  });

  it("should have bot detection columns", () => {
    const botColumns = ARGUS_COLUMNS.filter((col) =>
      col.name?.startsWith("bot."),
    );
    expect(botColumns.length).toBeGreaterThan(0);
    expect(botColumns.find((c) => c.name === "bot.is_headless")).toBeDefined();
  });

  it("should have analysis result columns", () => {
    const analysisColumns = ARGUS_COLUMNS.filter((col) =>
      col.name?.startsWith("analysis."),
    );
    expect(analysisColumns.length).toBeGreaterThan(0);
    expect(
      analysisColumns.find((c) => c.name === "analysis.device_id"),
    ).toBeDefined();
    expect(
      analysisColumns.find((c) => c.name === "analysis.risk_score"),
    ).toBeDefined();
  });

  it("should have DATE_INFO partition columns", () => {
    const dateColumns = ARGUS_COLUMNS.filter((col) =>
      col.name?.startsWith("DATE_INFO."),
    );
    expect(dateColumns.length).toBeGreaterThan(0);
    expect(dateColumns.find((c) => c.name === "DATE_INFO.year")).toBeDefined();
    expect(dateColumns.find((c) => c.name === "DATE_INFO.month")).toBeDefined();
  });

  it("should have valid Glue types", () => {
    const validTypes = ["string", "int", "bigint", "double", "boolean"];
    ARGUS_COLUMNS.forEach((col) => {
      expect(validTypes).toContain(col.type);
    });
  });

  it("should have unique column names", () => {
    const names = ARGUS_COLUMNS.map((col) => col.name);
    const uniqueNames = new Set(names);
    expect(uniqueNames.size).toBe(names.length);
  });
});
