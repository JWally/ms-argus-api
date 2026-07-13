import type { Context } from "aws-lambda";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  baseHandler: vi.fn(),
}));

vi.mock("./pat-attest/handler", () => mocks);

import { handler } from "./pat-attest";

const context = {
  callbackWaitsForEmptyEventLoop: false,
  functionName: "pat-attest-test",
  functionVersion: "$LATEST",
  invokedFunctionArn: "arn:aws:lambda:us-east-1:123:function:pat-attest-test",
  memoryLimitInMB: "256",
  awsRequestId: "test-request",
  logGroupName: "/aws/lambda/pat-attest-test",
  logStreamName: "test-stream",
  getRemainingTimeInMillis: () => 5_000,
  done: vi.fn(),
  fail: vi.fn(),
  succeed: vi.fn(),
} satisfies Context;

describe("PAT entrypoint warmup", () => {
  beforeEach(() => {
    mocks.baseHandler.mockReset();
  });

  it("short-circuits heater events before reading HTTP request context", async () => {
    const result = await handler(
      { source: "serverless-plugin-warmup" } as never,
      context,
    );

    expect(result).toBe("warmup");
    expect(mocks.baseHandler).not.toHaveBeenCalled();
  });
});
