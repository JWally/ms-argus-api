// src/helpers/http-error.ts
// AR-162: Shared HttpError class extracted from handlers
// Custom HttpError class to replace http-errors module (ESM bundling compatible)

/**
 * Custom HTTP error class for consistent error handling across handlers.
 * Provides statusCode for HTTP responses and expose flag for error message visibility.
 */
export class HttpError extends Error {
  statusCode: number;
  expose: boolean;

  constructor(statusCode: number, message: string) {
    super(message);
    this.name = "HttpError";
    this.statusCode = statusCode;
    this.expose = statusCode < 500; // Only expose client errors
  }
}

/**
 * Factory function for creating HttpError instances.
 * Provides a cleaner API similar to the http-errors package.
 */
export const createError = (statusCode: number, message: string): HttpError =>
  new HttpError(statusCode, message);
