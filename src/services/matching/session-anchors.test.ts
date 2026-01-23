// src/services/matching/session-anchors.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  QueryCommand,
  GetItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import {
  sessionAnchorLookup,
  ipUaAnchorLookup,
  buildSessionAnchorKey,
  buildIpUaAnchorKey,
  SessionAnchorDeps,
} from "./session-anchors";
import type { Fingerprint } from "../../types";

const dynamoMock = mockClient(DynamoDBClient);

function createDeps(): SessionAnchorDeps {
  return {
    dynamodb: new DynamoDBClient({}),
    tier2BucketsTable: "test-tier2-buckets",
    profilesTable: "test-profiles",
  };
}

function createFingerprint(overrides: Partial<Fingerprint> = {}): Fingerprint {
  return {
    ip_address: "192.168.1.1",
    user_agent: "Mozilla/5.0 Chrome/120",
    screen_dims: "1920x1080",
    ...overrides,
  };
}

function buildBucketItem(
  deviceId: string,
  createdAt: number,
  extra: Record<string, unknown> = {},
) {
  return marshall({
    device_id: deviceId,
    created_at: createdAt,
    ...extra,
  });
}

function buildProfileItem(
  deviceId: string,
  riskScore: number = 0.3,
  flags: string[] = [],
) {
  return marshall({
    device_id: deviceId,
    risk_score: riskScore,
    flags,
  });
}

describe("Session Anchors", () => {
  beforeEach(() => {
    dynamoMock.reset();
  });

  // ==================== BUILD KEY FUNCTIONS ====================

  describe("buildSessionAnchorKey", () => {
    it("builds key with IP, UA hash, and screen dims", () => {
      const key = buildSessionAnchorKey(createFingerprint());
      expect(key).not.toBeNull();
      expect(key!).toContain("session_anchor#");
      expect(key!).toContain("192.168.1.1");
      expect(key!).toContain("1920x1080");
    });

    it("returns null when IP is missing", () => {
      const key = buildSessionAnchorKey(
        createFingerprint({ ip_address: undefined }),
      );
      expect(key).toBeNull();
    });

    it("returns null when user_agent is missing", () => {
      const key = buildSessionAnchorKey(
        createFingerprint({ user_agent: undefined }),
      );
      expect(key).toBeNull();
    });

    it("returns null when screen_dims is missing", () => {
      const key = buildSessionAnchorKey(
        createFingerprint({ screen_dims: undefined }),
      );
      expect(key).toBeNull();
    });

    it("different user agents produce different keys", () => {
      const key1 = buildSessionAnchorKey(
        createFingerprint({ user_agent: "Chrome/120" }),
      );
      const key2 = buildSessionAnchorKey(
        createFingerprint({ user_agent: "Firefox/121" }),
      );
      expect(key1).not.toBe(key2);
    });
  });

  describe("buildIpUaAnchorKey", () => {
    it("builds key with IP and UA hash (no screen)", () => {
      const key = buildIpUaAnchorKey(createFingerprint());
      expect(key).not.toBeNull();
      expect(key!).toContain("ip_ua_anchor#");
      expect(key!).toContain("192.168.1.1");
      expect(key!).not.toContain("1920x1080");
    });

    it("returns null when IP is missing", () => {
      const key = buildIpUaAnchorKey(
        createFingerprint({ ip_address: undefined }),
      );
      expect(key).toBeNull();
    });

    it("returns null when user_agent is missing", () => {
      const key = buildIpUaAnchorKey(
        createFingerprint({ user_agent: undefined }),
      );
      expect(key).toBeNull();
    });

    it("works without screen_dims (doesn't require it)", () => {
      const key = buildIpUaAnchorKey(
        createFingerprint({ screen_dims: undefined }),
      );
      expect(key).not.toBeNull();
    });
  });

  // ==================== SESSION ANCHOR LOOKUP ====================

  describe("sessionAnchorLookup", () => {
    it("returns null when fingerprint lacks required fields", async () => {
      const result = await sessionAnchorLookup(
        createDeps(),
        createFingerprint({ ip_address: undefined }),
      );
      expect(result).toBeNull();
    });

    it("returns null when no bucket entries exist", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const result = await sessionAnchorLookup(
        createDeps(),
        createFingerprint(),
      );
      expect(result).toBeNull();
    });

    it("returns null when bucket items are undefined", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: undefined });

      const result = await sessionAnchorLookup(
        createDeps(),
        createFingerprint(),
      );
      expect(result).toBeNull();
    });

    it("returns match for entry within 10-minute validity window", async () => {
      const now = Date.now();
      const fiveMinutesAgo = now - 5 * 60 * 1000;

      dynamoMock.on(QueryCommand).resolves({
        Items: [buildBucketItem("device-123", fiveMinutesAgo)],
      });
      dynamoMock.on(GetItemCommand).resolves({
        Item: buildProfileItem("device-123", 0.25, ["RETURNING"]),
      });

      const result = await sessionAnchorLookup(
        createDeps(),
        createFingerprint(),
      );

      expect(result).not.toBeNull();
      expect(result!.device_id).toBe("device-123");
      expect(result!.confidence).toBe(0.65);
      expect(result!.match_tier).toBe(2);
      expect(result!.is_new_device).toBe(false);
      expect(result!.evidence_codes).toContain("SESSION_ANCHOR_BUCKET");
    });

    it("returns null for entry outside 10-minute validity window", async () => {
      const now = Date.now();
      const fifteenMinutesAgo = now - 15 * 60 * 1000;

      dynamoMock.on(QueryCommand).resolves({
        Items: [buildBucketItem("device-old", fifteenMinutesAgo)],
      });

      const result = await sessionAnchorLookup(
        createDeps(),
        createFingerprint(),
      );
      expect(result).toBeNull();
    });

    it("picks the most recent valid entry", async () => {
      const now = Date.now();
      const twoMinutesAgo = now - 2 * 60 * 1000;
      const eightMinutesAgo = now - 8 * 60 * 1000;

      dynamoMock.on(QueryCommand).resolves({
        Items: [
          buildBucketItem("device-old", eightMinutesAgo),
          buildBucketItem("device-recent", twoMinutesAgo),
        ],
      });
      dynamoMock.on(GetItemCommand).resolves({
        Item: buildProfileItem("device-recent", 0.2),
      });

      const result = await sessionAnchorLookup(
        createDeps(),
        createFingerprint(),
      );

      expect(result).not.toBeNull();
      expect(result!.device_id).toBe("device-recent");
    });

    it("filters out _stats entries", async () => {
      const now = Date.now();
      const fiveMinutesAgo = now - 5 * 60 * 1000;

      dynamoMock.on(QueryCommand).resolves({
        Items: [
          buildBucketItem("_stats", fiveMinutesAgo),
          buildBucketItem("device-real", fiveMinutesAgo),
        ],
      });
      dynamoMock.on(GetItemCommand).resolves({
        Item: buildProfileItem("device-real", 0.3),
      });

      const result = await sessionAnchorLookup(
        createDeps(),
        createFingerprint(),
      );

      expect(result!.device_id).toBe("device-real");
    });

    it("uses profile risk_score and flags when available", async () => {
      const now = Date.now();
      dynamoMock.on(QueryCommand).resolves({
        Items: [buildBucketItem("device-risky", now - 60000)],
      });
      dynamoMock.on(GetItemCommand).resolves({
        Item: buildProfileItem("device-risky", 0.85, [
          "HIGH_RISK",
          "BOT_SUSPECT",
        ]),
      });

      const result = await sessionAnchorLookup(
        createDeps(),
        createFingerprint(),
      );

      expect(result!.risk_score).toBe(0.85);
      expect(result!.flags).toEqual(["HIGH_RISK", "BOT_SUSPECT"]);
    });

    it("uses defaults when profile is not found", async () => {
      const now = Date.now();
      dynamoMock.on(QueryCommand).resolves({
        Items: [buildBucketItem("device-no-profile", now - 60000)],
      });
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await sessionAnchorLookup(
        createDeps(),
        createFingerprint(),
      );

      expect(result!.risk_score).toBe(0.4);
      expect(result!.flags).toEqual([]);
    });

    it("skips entries without created_at", async () => {
      const now = Date.now();
      dynamoMock.on(QueryCommand).resolves({
        Items: [
          marshall({ device_id: "no-timestamp" }), // No created_at
          buildBucketItem("has-timestamp", now - 60000),
        ],
      });
      dynamoMock.on(GetItemCommand).resolves({
        Item: buildProfileItem("has-timestamp", 0.3),
      });

      const result = await sessionAnchorLookup(
        createDeps(),
        createFingerprint(),
      );

      expect(result!.device_id).toBe("has-timestamp");
    });
  });

  // ==================== IP+UA ANCHOR LOOKUP ====================

  describe("ipUaAnchorLookup", () => {
    it("returns null when fingerprint lacks required fields", async () => {
      const result = await ipUaAnchorLookup(
        createDeps(),
        createFingerprint({ user_agent: undefined }),
      );
      expect(result).toBeNull();
    });

    it("returns null when no bucket entries exist", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const result = await ipUaAnchorLookup(createDeps(), createFingerprint());
      expect(result).toBeNull();
    });

    it("returns match for entry within 3-minute validity window", async () => {
      const now = Date.now();
      const oneMinuteAgo = now - 60 * 1000;

      dynamoMock.on(QueryCommand).resolves({
        Items: [buildBucketItem("device-ua", oneMinuteAgo)],
      });
      dynamoMock.on(GetItemCommand).resolves({
        Item: buildProfileItem("device-ua", 0.2),
      });

      const result = await ipUaAnchorLookup(createDeps(), createFingerprint());

      expect(result).not.toBeNull();
      expect(result!.device_id).toBe("device-ua");
      expect(result!.confidence).toBe(0.6); // Lower than session anchor
      expect(result!.match_tier).toBe(2);
      expect(result!.evidence_codes).toContain("IP_UA_ANCHOR_BUCKET");
    });

    it("returns null for entry outside 3-minute validity window", async () => {
      const now = Date.now();
      const fiveMinutesAgo = now - 5 * 60 * 1000;

      dynamoMock.on(QueryCommand).resolves({
        Items: [buildBucketItem("device-expired", fiveMinutesAgo)],
      });

      const result = await ipUaAnchorLookup(createDeps(), createFingerprint());
      expect(result).toBeNull();
    });

    it("filters out _stats entries", async () => {
      const now = Date.now();
      dynamoMock.on(QueryCommand).resolves({
        Items: [
          buildBucketItem("_stats", now - 30000),
          buildBucketItem("real-device", now - 30000),
        ],
      });
      dynamoMock.on(GetItemCommand).resolves({
        Item: buildProfileItem("real-device", 0.1),
      });

      const result = await ipUaAnchorLookup(createDeps(), createFingerprint());

      expect(result!.device_id).toBe("real-device");
    });

    it("picks most recent valid entry", async () => {
      const now = Date.now();
      dynamoMock.on(QueryCommand).resolves({
        Items: [
          buildBucketItem("device-older", now - 120000),
          buildBucketItem("device-newer", now - 30000),
        ],
      });
      dynamoMock.on(GetItemCommand).resolves({
        Item: buildProfileItem("device-newer", 0.15),
      });

      const result = await ipUaAnchorLookup(createDeps(), createFingerprint());

      expect(result!.device_id).toBe("device-newer");
    });
  });
});
