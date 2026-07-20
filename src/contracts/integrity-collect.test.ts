import { describe, expect, it } from "vitest";
import { requireV3IntegrityTransport } from "./integrity-collect";

describe("requireV3IntegrityTransport", () => {
  it("accepts the only supported transport version", () => {
    expect(
      requireV3IntegrityTransport({
        "x-argus-v": "3",
        "x-argus-session": "session-token",
      }),
    ).toBe("session-token");
  });

  it.each([undefined, "1", "2", "99"])(
    "rejects unsupported transport version %s",
    (version) => {
      const headers: Record<string, string | undefined> = {
        "x-argus-session": "session-token",
      };
      if (version !== undefined) headers["x-argus-v"] = version;

      expect(() => requireV3IntegrityTransport(headers)).toThrowError(
        expect.objectContaining({
          statusCode: 400,
          message: "Unsupported integrity transport version",
        }),
      );
    },
  );

  it("rejects a missing session binding on v3", () => {
    expect(() =>
      requireV3IntegrityTransport({ "x-argus-v": "3" }),
    ).toThrowError(
      expect.objectContaining({
        statusCode: 400,
        message: "Missing X-Argus-Session header",
      }),
    );
  });
});
