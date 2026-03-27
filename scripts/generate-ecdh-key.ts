/**
 * Generate a P-256 ECDH key pair and store in SSM Parameter Store.
 *
 * Usage:
 *   npx tsx scripts/generate-ecdh-key.ts            # create (fails if exists)
 *   npx tsx scripts/generate-ecdh-key.ts --force    # overwrite existing
 *   STACK_NAME=ms-argus-api-prod npx tsx scripts/generate-ecdh-key.ts
 *
 * Stored at: /${STACK_NAME}/ecdh-keypair  (SecureString)
 * Structure: { current: EcdhKeyData, previous: EcdhKeyData | null }
 */

import {
  SSMClient,
  GetParameterCommand,
  PutParameterCommand,
} from "@aws-sdk/client-ssm";

const STACK_NAME = process.env.STACK_NAME ?? "ms-argus-api-dev-jw";
const PARAM_NAME = `/${STACK_NAME}/ecdh-keypair`;

interface EcdhKeyData {
  privateKey: string; // PKCS8 base64 — server import
  publicKey: string; // SPKI base64 — reference only
  rawPublicKey: string; // Raw P-256, 65 bytes, 88 chars base64 — served to clients
  createdAt: number; // Unix ms
}

async function generateKeyPair(): Promise<EcdhKeyData> {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true, // extractable for export
    ["deriveKey", "deriveBits"],
  );

  const [pkcs8, spki, raw] = await Promise.all([
    globalThis.crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
    globalThis.crypto.subtle.exportKey("spki", keyPair.publicKey),
    globalThis.crypto.subtle.exportKey("raw", keyPair.publicKey),
  ]);

  return {
    privateKey: Buffer.from(pkcs8).toString("base64"),
    publicKey: Buffer.from(spki).toString("base64"),
    rawPublicKey: Buffer.from(raw).toString("base64"),
    createdAt: Date.now(),
  };
}

async function main(): Promise<void> {
  const force = process.argv.includes("--force");
  const ssm = new SSMClient({});

  if (!force) {
    try {
      await ssm.send(
        new GetParameterCommand({ Name: PARAM_NAME, WithDecryption: true }),
      );
      console.log(
        `Key already exists at ${PARAM_NAME}. Use --force to overwrite.`,
      );
      process.exit(0);
    } catch (err: unknown) {
      const name = (err as { name?: string }).name;
      if (name !== "ParameterNotFound") throw err;
    }
  }

  const current = await generateKeyPair();
  const value = JSON.stringify({ current, previous: null });

  await ssm.send(
    new PutParameterCommand({
      Name: PARAM_NAME,
      Value: value,
      Type: "SecureString",
      Overwrite: true,
    }),
  );

  console.log(`ECDH key pair stored at ${PARAM_NAME}`);
  console.log(`Raw public key (88 chars): ${current.rawPublicKey}`);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
