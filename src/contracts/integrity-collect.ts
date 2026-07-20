import { HttpError } from "../helpers/http-error";

/**
 * Enforce the current browser-to-API integrity transport contract and return
 * the session token that seeds its inner scramble.
 */
export function requireV3IntegrityTransport(
  headers: Record<string, string | undefined>,
): string {
  if (headers["x-argus-v"] !== "3") {
    throw new HttpError(400, "Unsupported integrity transport version");
  }

  const sessionToken = headers["x-argus-session"] ?? "";
  if (!sessionToken) {
    throw new HttpError(400, "Missing X-Argus-Session header");
  }

  return sessionToken;
}
