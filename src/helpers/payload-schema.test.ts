import { describe, it, expect } from "vitest";
import { getSessionId, type ArgusPayload } from "./payload-schema";

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
});
