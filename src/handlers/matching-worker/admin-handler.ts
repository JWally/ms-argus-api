import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import type { AdminRequest, AdminResponse } from "./types";

interface AdminDeps {
  logger: Logger;
  metrics: Metrics;
}

/** Handle admin requests (Valkey cache management). */
export async function handleAdminRequest(
  request: AdminRequest,
  deps: AdminDeps,
): Promise<AdminResponse> {
  deps.logger.info("Admin handler invoked", { action: request.action });

  return {
    success: false,
    action: request.action,
    message: `Action '${request.action}' not yet implemented`,
  };
}
