/**
 * Check if an SQS message body is a warmup message from EventBridge.
 * Warmup messages keep the SQS polling pipeline active.
 */
export function isWarmupMessage(body: string): boolean {
  try {
    const parsed = JSON.parse(body);
    return parsed.warmup === true || parsed.source === "warmup-rule";
  } catch {
    return false;
  }
}
