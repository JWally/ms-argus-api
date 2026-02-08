import type { SQSEvent } from "aws-lambda";

/** Admin request for direct Lambda invocation (Valkey cache management). */
export interface AdminRequest {
  action: "flush_cache" | "cache_stats" | "run_pg_migration";
  /** Optional SQL to execute (for run_pg_migration) */
  sql?: string;
}

/** Admin response returned from direct Lambda invocation. */
export interface AdminResponse {
  success: boolean;
  action: string;
  message?: string;
  data?: Record<string, unknown>;
}

/** Type guard to distinguish admin requests from SQS events. */
export function isAdminRequest(
  event: SQSEvent | AdminRequest,
): event is AdminRequest {
  return "action" in event && !("Records" in event);
}
