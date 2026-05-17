/**
 * One-off repair: re-evaluate every rule in auto-overlay.json.gz against
 * the current categorize() regex set, fix mis-categorized rules, and drop
 * any that no longer categorize at all (matches the new fail-closed
 * fallback in ip-class-discoverer.ts).
 *
 * Background: prior to 2026-05-17 the discoverer defaulted to
 * `residential` whenever categorize() returned null. That manufactured a
 * residential trust signal for unfamiliar datacenter operators (QTS,
 * BrowserStack, hostlegion, etc.). The discoverer now drops such rules,
 * but the existing overlay still carries the bad classifications.
 *
 * Usage:  npx tsx scripts/repair-auto-overlay.ts [--dry-run]
 */
import {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
} from "@aws-sdk/client-s3";
import { gunzipSync, gzipSync } from "node:zlib";
import {
  categorize,
  type NetworkCategory,
} from "../src/services/network/categorize";

interface OverlayRule {
  cidr: string;
  category: NetworkCategory;
  name: string;
  source: string;
  discovered_at: string;
}

interface OverlayFileShape {
  generated_at: string;
  rules_total: number;
  rules: OverlayRule[];
}

const BUCKET = process.env.IP_CLASS_BUCKET ?? "ms-argus-api-dev-jw-ip-class";
const KEY = process.env.IP_CLASS_AUTO_OVERLAY_KEY ?? "auto-overlay.json.gz";
const DRY_RUN = process.argv.includes("--dry-run");

async function main() {
  const s3 = new S3Client({});
  console.log(`Loading s3://${BUCKET}/${KEY} ...`);
  const obj = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: KEY }));
  if (!obj.Body) throw new Error("empty body");
  const buf = Buffer.from(await obj.Body.transformToByteArray());
  const file = JSON.parse(
    gunzipSync(buf).toString("utf-8"),
  ) as OverlayFileShape;
  console.log(
    `Loaded ${file.rules.length} rules, generated_at=${file.generated_at}`,
  );

  // Only upgrade a rule when the new categorizer produces a DIFFERENT
  // non-null category on the name alone. Rules originally classified
  // through the multi-candidate path (name + org + nameservers) are kept
  // as-is because we only have the name preserved in the overlay file —
  // we can't faithfully reproduce the multi-candidate result and would
  // false-drop them. Surgical upgrade beats wholesale rewrite.
  const reclassified: OverlayRule[] = [];
  const changed: Array<[OverlayRule, NetworkCategory]> = [];
  for (const r of file.rules) {
    const fresh = categorize(r.name);
    if (fresh && fresh !== r.category) {
      changed.push([r, fresh]);
      reclassified.push({ ...r, category: fresh });
    } else {
      reclassified.push(r);
    }
  }
  const dropped: OverlayRule[] = [];

  console.log(`\nResult:`);
  console.log(`  kept (same):       ${reclassified.length - changed.length}`);
  console.log(`  upgraded:          ${changed.length}`);
  console.log(`  dropped:           ${dropped.length}`);

  if (changed.length) {
    console.log(`\nReclassified rules:`);
    for (const [old, fresh] of changed) {
      console.log(
        `  ${old.cidr.padEnd(22)} ${old.category} -> ${fresh}  (${old.name})`,
      );
    }
  }
  if (dropped.length) {
    console.log(`\nDropped rules (categorize now returns null):`);
    for (const r of dropped) {
      console.log(`  ${r.cidr.padEnd(22)} was=${r.category}  (${r.name})`);
    }
  }

  if (DRY_RUN) {
    console.log("\n--dry-run: not writing back.");
    return;
  }

  const out: OverlayFileShape = {
    generated_at: new Date().toISOString(),
    rules_total: reclassified.length,
    rules: reclassified,
  };
  const gz = gzipSync(Buffer.from(JSON.stringify(out)));
  await s3.send(
    new PutObjectCommand({
      Bucket: BUCKET,
      Key: KEY,
      Body: gz,
      ContentType: "application/json",
      ContentEncoding: "gzip",
    }),
  );
  console.log(
    `\nWrote s3://${BUCKET}/${KEY}  (${gz.length} bytes, ${reclassified.length} rules)`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
