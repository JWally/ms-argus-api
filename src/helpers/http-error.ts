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
