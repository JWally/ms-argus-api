// tests/integration/api.integration.test.ts
// Integration tests for the deployed Argus API
// Run with: ARGUS_API_URL=https://api-dev-jw.argus.pw npx vitest run tests/integration/

import { describe, it, expect, beforeAll } from "vitest";

const API_URL = process.env.ARGUS_API_URL || "https://api-dev-jw.argus.pw";

describe("Argus API Integration Tests", () => {
  beforeAll(() => {
    if (!process.env.ARGUS_API_URL) {
      console.log(`Using default API URL: ${API_URL}`);
    }
  });

  describe("Health Check", () => {
    it("should return healthy status", async () => {
      const response = await fetch(`${API_URL}/health`);
      expect(response.status).toBe(200);

      const body = await response.json();
      expect(body.status).toBe("healthy");
    });
  });

  describe("Collect Endpoint", () => {
    it("should accept valid fingerprint payload and return 204", async () => {
      const sessionId = `test-session-${Date.now()}`;
      const payload = {
        session_id: sessionId,
        tenant_id: "test-tenant",
        fingerprint: {
          stable_hash: "test-stable-hash-123",
          canvas_hash: "test-canvas-hash-456",
          user_agent: "Mozilla/5.0 (Test)",
        },
      };

      const response = await fetch(`${API_URL}/v1/collect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Tenant-ID": "test-tenant",
        },
        body: JSON.stringify(payload),
      });

      expect(response.status).toBe(204);
    });

    it("should reject request without session_id", async () => {
      const payload = {
        tenant_id: "test-tenant",
        fingerprint: {
          stable_hash: "test-hash",
        },
      };

      const response = await fetch(`${API_URL}/v1/collect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      expect(response.status).toBe(400);
    });

    it("should reject invalid JSON", async () => {
      const response = await fetch(`${API_URL}/v1/collect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: "not-valid-json",
      });

      expect(response.status).toBe(400);
    });

    it("should reject non-POST methods", async () => {
      const response = await fetch(`${API_URL}/v1/collect`, {
        method: "GET",
      });

      expect(response.status).toBe(405);
    });

    it("should use default tenant when X-Tenant-ID not provided", async () => {
      const sessionId = `test-session-default-${Date.now()}`;
      const payload = {
        session_id: sessionId,
        fingerprint: {
          stable_hash: "test-hash",
        },
      };

      const response = await fetch(`${API_URL}/v1/collect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      // Should succeed with default tenant
      expect(response.status).toBe(204);
    });

    it("should handle complete fingerprint payloads", async () => {
      const sessionId = `test-session-complete-${Date.now()}`;
      const payload = {
        session_id: sessionId,
        tenant_id: "test-tenant",
        fingerprint: {
          stable_hash:
            "sha256-abc123def456ghi789jkl012mno345pqr678stu901vwx234",
          fuzzy_hash: "fuzzy-xyz789abc123def456ghi789jkl012mno345pqr678stu901",
          canvas_hash: "canvas-hash-12345678901234567890123456789012",
          webgl_hash: "webgl-hash-98765432109876543210987654321098",
          audio_hash: "audio-hash-abcdefghijklmnopqrstuvwxyz123456",
          gpu_renderer: "NVIDIA GeForce RTX 4090",
          screen_dims: "3840x2160",
          timezone: "America/New_York",
          user_agent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
          hardware_concurrency: 16,
          device_memory: 32,
          ip_address: "192.168.1.100",
          ja4: "t13d1516h2_8daaf6152771_b0da82dd1658",
          evercookie_id: "ev-cookie-id-1234567890abcdef",
        },
        tcp_blob: "base64encodedtcpdata12345",
        tls_blob: "base64encodedtlsdata67890",
      };

      const response = await fetch(`${API_URL}/v1/collect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Tenant-ID": "test-tenant",
        },
        body: JSON.stringify(payload),
      });

      expect(response.status).toBe(204);
    });
  });
});
