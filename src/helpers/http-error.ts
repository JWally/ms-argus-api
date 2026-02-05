/**
 * Custom HTTP error class for consistent error handling across handlers.
 * Provides statusCode for HTTP responses and expose flag for error message visibility.
 */
export class HttpError extends Error {
  /** HTTP status code */
  statusCode: number;
  /** Whether to expose error message to client (true for 4xx, false for 5xx) */
  expose: boolean;

  /**
   * Create an HttpError
   * @param statusCode - HTTP status code (e.g., 400, 404, 500)
   * @param message - Error message
   */
  constructor(statusCode: number, message: string) {
    super(message);
    this.name = "HttpError";
    this.statusCode = statusCode;
    this.expose = statusCode < 500; // Only expose client errors
  }
}
