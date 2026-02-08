import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { getPool } from "../../services/postgres";
import type { AdminRequest, AdminResponse } from "./types";

interface AdminDeps {
  logger: Logger;
  metrics: Metrics;
}

/** Handle admin requests (Valkey cache management, Postgres migrations). */
export async function handleAdminRequest(
  request: AdminRequest,
  deps: AdminDeps,
): Promise<AdminResponse> {
  deps.logger.info("Admin handler invoked", { action: request.action });

  if (request.action === "run_pg_migration") {
    return runPgMigration(request.sql, deps);
  }

  return {
    success: false,
    action: request.action,
    message: `Action '${request.action}' not yet implemented`,
  };
}

async function runPgMigration(
  sql: string | undefined,
  deps: AdminDeps,
): Promise<AdminResponse> {
  if (!sql) {
    return {
      success: false,
      action: "run_pg_migration",
      message: "Missing 'sql' field in request",
    };
  }

  try {
    const pool = await getPool();
    if (!pool) {
      return {
        success: false,
        action: "run_pg_migration",
        message: "Postgres not configured (POSTGRES_HOST not set)",
      };
    }

    const result = await pool.query(sql);
    deps.logger.info("Migration executed successfully", {
      command: result.command,
      rowCount: result.rowCount,
    });

    return {
      success: true,
      action: "run_pg_migration",
      message: `Migration completed: ${result.command}`,
      data: { rowCount: result.rowCount, rows: result.rows },
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    deps.logger.error("Migration failed", { error: msg });
    return {
      success: false,
      action: "run_pg_migration",
      message: `Migration failed: ${msg}`,
    };
  }
}
