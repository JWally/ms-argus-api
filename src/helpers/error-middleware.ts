// src/helpers/error-middleware.ts
// AR-166: Shared error handling middleware for API handlers
// Extracted from ingestion.ts and session-get.ts

import middy from "@middy/core";
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";

/**
 * Configuration options for the JSON error handler
 */
export interface JsonErrorHandlerConfig {
  /** Logger instance for error logging */
  logger: Logger;
  /**
   * Whether to expose error messages in responses.
   * - "client-only": Only expose 4xx error messages (default, more secure)
   * - "all": Expose all error messages (use with caution)
   */
  exposeErrors?: "client-only" | "all";
  /** Default message for 5xx errors when exposeErrors is "client-only" */
  serverErrorMessage?: string;
}

/**
 * Middy middleware that converts errors to JSON responses.
 * Extracts statusCode from HttpError instances and logs all errors.
 *
 * Note: CORS headers should be handled by corsMiddleware, which runs
 * after this middleware and adds headers to the response.
 *
 * @param config - Error handler configuration
 * @returns Middy middleware object
 *
 * @example
 * ```typescript
 * const handler = middy(baseHandler)
 *   .use(corsMiddleware({ methods: "GET, OPTIONS", headers: "Content-Type" }))
 *   .use(jsonErrorHandler({ logger })); // Must be last
 * ```
 */
export const jsonErrorHandler = (
  config: JsonErrorHandlerConfig,
): middy.MiddlewareObj<APIGatewayProxyEventV2, APIGatewayProxyResultV2> => {
  const {
    logger,
    exposeErrors = "client-only",
    serverErrorMessage = "Service temporarily unavailable",
  } = config;

  return {
    onError: (request) => {
      const { error } = request;

      // Extract status code from HttpError or default to 500
      const statusCode =
        error && typeof error === "object" && "statusCode" in error
          ? (error as { statusCode: number }).statusCode
          : 500;

      // Determine error message based on configuration
      let message: string;
      if (exposeErrors === "all") {
        message =
          error instanceof Error ? error.message : "Internal server error";
      } else {
        // "client-only" - only expose 4xx error messages
        message =
          statusCode < 500 && error instanceof Error
            ? error.message
            : serverErrorMessage;
      }

      logger.warn("Request error", { error, statusCode });

      request.response = {
        statusCode,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: message }),
      };
    },
  };
};
