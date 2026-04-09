/**
 * Generate an integrity API key and store in SSM Parameter Store.
 *
 * Usage:
 *   npx tsx scripts/generate-integrity-api-key.ts            # create (fails if exists)
 *   npx tsx scripts/generate-integrity-api-key.ts --force    # overwrite existing
 *   STACK_NAME=ms-argus-api-prod npx tsx scripts/generate-integrity-api-key.ts
 *
 * Stored at: /${STACK_NAME}/integrity-api-key  (SecureString)
 * Format: ak_integrity_{64 hex chars}
 */

import * as crypto from "node:crypto";
import {
  SSMClient,
  GetParameterCommand,
  PutParameterCommand,
} from "@aws-sdk/client-ssm";

const STACK_NAME = process.env.STACK_NAME ?? "ms-argus-api-dev-jw";
const PARAM_NAME = `/${STACK_NAME}/integrity-api-key`;

async function main() {
  const ssm = new SSMClient({});
  const force = process.argv.includes("--force");

  // Check if key already exists
  if (!force) {
    try {
      await ssm.send(
        new GetParameterCommand({
          Name: PARAM_NAME,
          WithDecryption: true,
        }),
      );
      console.error(
        `Key already exists at ${PARAM_NAME}. Use --force to overwrite.`,
      );
      process.exit(1);
    } catch (err: unknown) {
      if ((err as { name: string }).name !== "ParameterNotFound") throw err;
    }
  }

  // Generate key: ak_integrity_ + 32 random bytes as hex
  const key = `ak_integrity_${crypto.randomBytes(32).toString("hex")}`;

  await ssm.send(
    new PutParameterCommand({
      Name: PARAM_NAME,
      Value: key,
      Type: "SecureString",
      Overwrite: force,
      Description: "API key for integrity endpoint access",
    }),
  );

  console.log(`Stored integrity API key at ${PARAM_NAME}`);
  console.log(`Key: ${key}`);
  console.log(
    `\nSave this key — it cannot be retrieved from SSM without AWS access.`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
