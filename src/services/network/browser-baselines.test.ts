import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { gzipSync } from "node:zlib";
import { Readable } from "node:stream";
import {
  lookupBrowserBaselineSync,
  lookupEngineFamilyBaselineSync,
  prewarmBrowserBaselines,
  _resetBrowserBaselinesForTesting,
  _seedBrowserBaselinesForTesting,
} from "./browser-baselines";

const s3Mock = mockClient(S3Client);

function gzippedJson(payload: unknown): Buffer {
  return gzipSync(Buffer.from(JSON.stringify(payload)));
}

/**
 * Build the body shape S3 returns: an object with transformToByteArray().
 * The runtime only calls that method, so a thin stub is enough.
 */
function s3Body(buf: Buffer) {
  return {
    transformToByteArray: () => Promise.resolve(new Uint8Array(buf)),
    // The S3 SDK types want a Readable here; the runtime never reads it.
    // Cast at the call site keeps the test focused.
  } as unknown as Readable;
}

const SAMPLE_PAYLOAD = {
  generated_at: "2026-05-06T00:00:00Z",
  lookback_hours: 24,
  n_total: 1000,
  n_after_dedup: 800,
  browsers: {
    "Chrome 147": { n_sessions: 500, fields: { jsEngine: { V8: 500 } } },
    "Safari iOS 18.7": {
      n_sessions: 200,
      fields: { jsEngine: { JavaScriptCore: 200 } },
    },
  },
  engine_families: {
    chromium: { n_sessions: 600, fields: { jsEngine: { V8: 600 } } },
    webkit: {
      n_sessions: 250,
      fields: { jsEngine: { JavaScriptCore: 250 } },
    },
  },
};

describe("browser-baselines", () => {
  beforeEach(() => {
    _resetBrowserBaselinesForTesting();
    s3Mock.reset();
    process.env.IP_CLASS_BUCKET = "test-bucket";
    delete process.env.BROWSER_BASELINES_KEY;
  });

  afterEach(() => {
    _resetBrowserBaselinesForTesting();
  });

  describe("lookupBrowserBaselineSync", () => {
    it("returns null before prewarm completes", () => {
      expect(lookupBrowserBaselineSync("Chrome 147")).toBeNull();
    });

    it("returns the baseline for an exact key after seed", () => {
      _seedBrowserBaselinesForTesting({
        browsers: { "Chrome 147": SAMPLE_PAYLOAD.browsers["Chrome 147"] },
      });
      const r = lookupBrowserBaselineSync("Chrome 147");
      expect(r?.n_sessions).toBe(500);
      expect(r?.fields.jsEngine.V8).toBe(500);
    });

    it("returns null when key is not in the cache", () => {
      _seedBrowserBaselinesForTesting({
        browsers: { "Chrome 147": SAMPLE_PAYLOAD.browsers["Chrome 147"] },
      });
      expect(lookupBrowserBaselineSync("Chrome 999")).toBeNull();
    });
  });

  describe("lookupEngineFamilyBaselineSync", () => {
    it("returns null before prewarm completes", () => {
      expect(lookupEngineFamilyBaselineSync("chromium")).toBeNull();
    });

    it("returns the family baseline after seed", () => {
      _seedBrowserBaselinesForTesting({
        engine_families: { chromium: SAMPLE_PAYLOAD.engine_families.chromium },
      });
      expect(lookupEngineFamilyBaselineSync("chromium")?.n_sessions).toBe(600);
    });

    it("returns null for unknown family", () => {
      _seedBrowserBaselinesForTesting({
        engine_families: { chromium: SAMPLE_PAYLOAD.engine_families.chromium },
      });
      expect(lookupEngineFamilyBaselineSync("gecko")).toBeNull();
    });
  });

  describe("prewarmBrowserBaselines", () => {
    it("loads from S3, gunzips, and populates both maps", async () => {
      s3Mock.on(GetObjectCommand).resolves({
        Body: s3Body(gzippedJson(SAMPLE_PAYLOAD)),
      } as any);

      await prewarmBrowserBaselines();

      expect(lookupBrowserBaselineSync("Chrome 147")?.n_sessions).toBe(500);
      expect(lookupEngineFamilyBaselineSync("webkit")?.n_sessions).toBe(250);
    });

    it("honors BROWSER_BASELINES_KEY env override", async () => {
      process.env.BROWSER_BASELINES_KEY = "custom/key.json.gz";
      s3Mock.on(GetObjectCommand).resolves({
        Body: s3Body(gzippedJson(SAMPLE_PAYLOAD)),
      } as any);

      await prewarmBrowserBaselines();

      const calls = s3Mock.commandCalls(GetObjectCommand);
      expect(calls).toHaveLength(1);
      expect(calls[0].args[0].input.Key).toBe("custom/key.json.gz");
      expect(calls[0].args[0].input.Bucket).toBe("test-bucket");
    });

    it("uses a default key when BROWSER_BASELINES_KEY is unset", async () => {
      s3Mock.on(GetObjectCommand).resolves({
        Body: s3Body(gzippedJson(SAMPLE_PAYLOAD)),
      } as any);

      await prewarmBrowserBaselines();

      const calls = s3Mock.commandCalls(GetObjectCommand);
      expect(calls[0].args[0].input.Key).toBe("browser-baselines.json.gz");
    });

    it("throws when IP_CLASS_BUCKET is missing", async () => {
      delete process.env.IP_CLASS_BUCKET;
      await expect(prewarmBrowserBaselines()).rejects.toThrow(
        "IP_CLASS_BUCKET",
      );
    });

    it("throws when S3 returns an empty body", async () => {
      s3Mock.on(GetObjectCommand).resolves({ Body: undefined } as any);
      await expect(prewarmBrowserBaselines()).rejects.toThrow("empty body");
    });

    it("dedupes concurrent prewarm calls into one S3 request", async () => {
      s3Mock.on(GetObjectCommand).resolves({
        Body: s3Body(gzippedJson(SAMPLE_PAYLOAD)),
      } as any);

      await Promise.all([
        prewarmBrowserBaselines(),
        prewarmBrowserBaselines(),
        prewarmBrowserBaselines(),
      ]);

      expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(1);
    });

    it("reuses the cache on subsequent calls within TTL", async () => {
      s3Mock.on(GetObjectCommand).resolves({
        Body: s3Body(gzippedJson(SAMPLE_PAYLOAD)),
      } as any);

      await prewarmBrowserBaselines();
      await prewarmBrowserBaselines();
      await prewarmBrowserBaselines();

      expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(1);
    });

    it("falls back to empty maps when payload omits browsers/engine_families", async () => {
      s3Mock.on(GetObjectCommand).resolves({
        Body: s3Body(gzippedJson({ generated_at: "2026-05-06T00:00:00Z" })),
      } as any);

      await prewarmBrowserBaselines();

      expect(lookupBrowserBaselineSync("Chrome 147")).toBeNull();
      expect(lookupEngineFamilyBaselineSync("chromium")).toBeNull();
    });
  });

  describe("test hooks", () => {
    it("_resetBrowserBaselinesForTesting clears cached state", () => {
      _seedBrowserBaselinesForTesting({
        browsers: { "Chrome 147": SAMPLE_PAYLOAD.browsers["Chrome 147"] },
      });
      expect(lookupBrowserBaselineSync("Chrome 147")).not.toBeNull();
      _resetBrowserBaselinesForTesting();
      expect(lookupBrowserBaselineSync("Chrome 147")).toBeNull();
    });

    it("_seedBrowserBaselinesForTesting accepts a partial payload", () => {
      _seedBrowserBaselinesForTesting({});
      expect(lookupBrowserBaselineSync("Chrome 147")).toBeNull();
      expect(lookupEngineFamilyBaselineSync("chromium")).toBeNull();
    });
  });
});
