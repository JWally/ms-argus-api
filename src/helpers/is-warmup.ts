/**
 * Check if an SQS message body is a warmup message from EventBridge.
 *
 * Warmup messages keep the SQS polling pipeline active and prevent
 * Lambda cold starts. They should be ignored by the processing logic.
 *
 * @param body - Raw SQS message body string
 * @returns True if the message is a warmup signal
 */
export function isWarmupMessage(body: string): boolean {
  try {
    const parsed = JSON.parse(body);
    return parsed.warmup === true || parsed.source === "warmup-rule";
  } catch {
    return false;
  }
}
