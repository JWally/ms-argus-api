/**
 * IP velocity counter — atomic per-session update + return-snapshot.
 *
 * For each ingested session we update a row keyed by (ip, hour-bucket).
 * The row holds:
 *   - hits         — total submissions in this hour
 *   - blocked      — count of those that ended verdict=block
 *   - hll_devices  — HLL of device pubkey hashes (binary, ~3KB)
 *   - first_seen_ms / last_seen_ms — timestamps
 *
 * Flow: read row → mutate HLL locally → UpdateItem with
 * ReturnValues=ALL_NEW. Single round-trip per session, snapshot
 * returned in the same response is what we stamp on the integrity
 * row for the dashboard.
 *
 * TTL: configured on the table (7 days from bucket start). Old buckets
 * self-prune; we never delete explicitly.
 */
import {
  DynamoDBClient,
  GetItemCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import { createHash } from "node:crypto";
import { Hll, HLL_SERIALIZED_BYTES } from "./hll";

const HOUR_MS = 60 * 60 * 1000;
const BUCKET_TTL_SEC = 7 * 24 * 60 * 60; // 7 days

export interface IpVelocitySnapshot {
  /** Source IP. */
  ip: string;
  /** Hour-bucket label, e.g. "1h:2026052914". */
  bucket: string;
  /** Total submissions in this hour bucket (including the current one). */
  hits: number;
  /** Number that ended verdict=block. */
  blocked: number;
  /** Estimated distinct devices seen in this hour bucket. */
  distinct_devices_est: number;
  /** Epoch ms when this IP first appeared in this hour bucket. */
  first_seen_ms: number;
  /** Epoch ms of the current submission. */
  last_seen_ms: number;
}

/** Compute the hour-bucket label for a given timestamp. Format is
 *  "1h:YYYYMMDDHH" in UTC. */
export function hourBucket(nowMs: number = Date.now()): string {
  const d = new Date(Math.floor(nowMs / HOUR_MS) * HOUR_MS);
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  const hr = String(d.getUTCHours()).padStart(2, "0");
  return `1h:${y}${m}${day}${hr}`;
}

/** Hash a string identifier (pubkey or client_uuid) down to a stable
 *  16-byte device fingerprint suitable for HLL.add. */
export function deviceHashFor(input: string): Buffer {
  return createHash("sha256").update(input, "utf-8").digest().subarray(0, 16);
}

/** Pick the most stable device identifier available from the payload
 *  fields. Pubkey is the cryptographic P-256 device identity (most
 *  stable, survives across browser sessions via IndexedDB). Falls back
 *  to client_uuid for legacy SDK bundles. Returns null if neither is
 *  present — caller should skip the velocity update. */
export function pickDeviceId(
  pubkey: string | null | undefined,
  clientUuid: string | null | undefined,
): string | null {
  if (pubkey && pubkey.length > 0) return pubkey;
  if (clientUuid && clientUuid.length > 0) return clientUuid;
  return null;
}

interface UpdateInput {
  ip: string;
  deviceId: string;
  verdictWasBlock: boolean;
  ddb: DynamoDBClient;
  nowMs?: number;
}

/**
 * Add this session to the velocity rollup for the IP's current hour
 * bucket. Returns the post-update snapshot suitable for stamping on
 * the integrity row.
 *
 * Two-step on the wire (DDB doesn't have an atomic HLL primitive, but
 * we hide the read inside this helper so callers see one call):
 *   1. GetItem to retrieve current HLL state (~3KB binary).
 *   2. Mutate HLL locally, UpdateItem with ReturnValues=ALL_NEW.
 *
 * Failure is non-fatal — caller logs and stamps null. Velocity is a
 * stats signal, not a correctness-critical path.
 */
/** Load the current HLL state for (ip, bucket). Returns an empty HLL on
 *  any failure or absent row — callers shouldn't distinguish. */
async function loadHll(
  ddb: DynamoDBClient,
  tableName: string,
  ip: string,
  bucket: string,
): Promise<Hll> {
  try {
    const got = await ddb.send(
      new GetItemCommand({
        TableName: tableName,
        Key: { ip: { S: ip }, bucket: { S: bucket } },
        ProjectionExpression: "hll_devices",
        ConsistentRead: false,
      }),
    );
    const bytes = got.Item?.hll_devices?.B;
    if (bytes && bytes.length === HLL_SERIALIZED_BYTES) {
      return Hll.fromBytes(Buffer.from(bytes));
    }
  } catch {
    /* fall through to empty */
  }
  return Hll.empty();
}

interface WriteVelocityArgs {
  ddb: DynamoDBClient;
  tableName: string;
  ip: string;
  bucket: string;
  hllBytes: Buffer;
  verdictWasBlock: boolean;
  nowMs: number;
  ttl: number;
}

/** Write the mutated counter+HLL back with ReturnValues=ALL_NEW. */
async function writeVelocityRow(
  args: WriteVelocityArgs,
): Promise<Record<string, { N?: string; B?: Uint8Array }>> {
  const resp = await args.ddb.send(
    new UpdateItemCommand({
      TableName: args.tableName,
      Key: { ip: { S: args.ip }, bucket: { S: args.bucket } },
      UpdateExpression: [
        "ADD hits :one, blocked :b",
        "SET hll_devices = :hll, last_seen_ms = :now, #ttl = :ttl,",
        "    first_seen_ms = if_not_exists(first_seen_ms, :now)",
      ].join(" "),
      ExpressionAttributeNames: { "#ttl": "ttl" },
      ExpressionAttributeValues: {
        ":one": { N: "1" },
        ":b": { N: args.verdictWasBlock ? "1" : "0" },
        ":hll": { B: args.hllBytes },
        ":now": { N: String(args.nowMs) },
        ":ttl": { N: String(args.ttl) },
      },
      ReturnValues: "ALL_NEW",
    }),
  );
  return resp.Attributes ?? {};
}

export async function updateIpVelocity(
  input: UpdateInput,
): Promise<IpVelocitySnapshot | null> {
  // Read env at call time so test bootstrapping (and config reloads)
  // see updated values. Empty / unset → feature is disabled, caller
  // stamps null on the row.
  const tableName = process.env.IP_VELOCITY_TABLE;
  if (!tableName) return null;
  const now = input.nowMs ?? Date.now();
  const bucket = hourBucket(now);
  const ttl = Math.floor(now / 1000) + BUCKET_TTL_SEC;

  const hll = await loadHll(input.ddb, tableName, input.ip, bucket);
  hll.add(deviceHashFor(input.deviceId));
  const attrs = await writeVelocityRow({
    ddb: input.ddb,
    tableName,
    ip: input.ip,
    bucket,
    hllBytes: hll.toBytes(),
    verdictWasBlock: input.verdictWasBlock,
    nowMs: now,
    ttl,
  });
  return {
    ip: input.ip,
    bucket,
    hits: Number(attrs.hits?.N ?? 0),
    blocked: Number(attrs.blocked?.N ?? 0),
    distinct_devices_est: hll.count(),
    first_seen_ms: Number(attrs.first_seen_ms?.N ?? now),
    last_seen_ms: Number(attrs.last_seen_ms?.N ?? now),
  };
}
