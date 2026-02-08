/**
 * Singleton PostgreSQL connection pool for Lambda.
 *
 * Follows the same pattern as valkey-client.ts:
 * - Lazy initialization on first use
 * - Module-level singleton survives Lambda container reuse
 * - Secrets fetched once from Secrets Manager and cached
 * - Returns null when POSTGRES_HOST is not configured
 *
 * @module services/postgres/client
 */

import { Pool } from "pg";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { Logger } from "@aws-lambda-powertools/logger";

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME || "postgres-client",
});

let pool: Pool | null = null;
const secretsClient = new SecretsManagerClient({});

interface PgSecret {
  username: string;
  password: string;
}

async function fetchSecret(secretArn: string): Promise<PgSecret> {
  const result = await secretsClient.send(
    new GetSecretValueCommand({ SecretId: secretArn }),
  );
  if (!result.SecretString) {
    throw new Error("Postgres secret has no SecretString");
  }
  return JSON.parse(result.SecretString) as PgSecret;
}

/**
 * Get or create the singleton PostgreSQL pool.
 * Returns null if POSTGRES_HOST is not configured.
 */
export async function getPool(): Promise<Pool | null> {
  if (!process.env.POSTGRES_HOST) return null;
  if (pool) return pool;

  const secretArn = process.env.POSTGRES_SECRET_ARN;
  if (!secretArn) {
    logger.warn("POSTGRES_HOST set but POSTGRES_SECRET_ARN missing");
    return null;
  }

  try {
    const secret = await fetchSecret(secretArn);
    pool = new Pool({
      host: process.env.POSTGRES_HOST,
      port: parseInt(process.env.POSTGRES_PORT || "5432", 10),
      database: process.env.POSTGRES_DB,
      user: secret.username,
      password: secret.password,
      // RDS is VPC-internal; system CAs don't include the RDS self-signed cert
      ssl: { rejectUnauthorized: false },
      max: 2, // Lambda concurrency = 1, keep pool small
      idleTimeoutMillis: 60_000,
      connectionTimeoutMillis: 5000,
    });

    pool.on("error", (err) => {
      logger.warn("Postgres pool error", { error: String(err) });
    });

    logger.info("Postgres pool created", {
      host: process.env.POSTGRES_HOST,
      database: process.env.POSTGRES_DB,
    });

    return pool;
  } catch (error) {
    logger.error("Failed to create Postgres pool", { error });
    return null;
  }
}

/**
 * Gracefully close the PostgreSQL pool.
 */
export async function closePool(): Promise<void> {
  if (pool) {
    try {
      await pool.end();
      logger.info("Postgres pool closed");
    } catch (error) {
      logger.warn("Error closing Postgres pool", { error });
    } finally {
      pool = null;
    }
  }
}
