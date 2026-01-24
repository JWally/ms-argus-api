import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { FirehoseClient, PutRecordCommand } from "@aws-sdk/client-firehose";
import type { MatchResult } from "../../services/matching";

export async function emitObservation(
  params: {
    sessionId: string;
    matchResult: MatchResult;
    tier2TimedOut: boolean;
    durationMs: number;
  },
  deps: {
    firehose: FirehoseClient;
    streamName: string | undefined;
    logger: Logger;
    metrics: Metrics;
  },
): Promise<void> {
  if (!deps.streamName) {
    return;
  }

  const observation = {
    session_id: params.sessionId,
    device_id: params.matchResult.device_id,
    match_tier: params.matchResult.match_tier,
    is_new_device: params.matchResult.is_new_device,
    tier2_timed_out: params.tier2TimedOut,
    duration_ms: params.durationMs,
    timestamp: new Date().toISOString(),
  };

  try {
    await deps.firehose.send(
      new PutRecordCommand({
        DeliveryStreamName: deps.streamName,
        Record: {
          Data: Buffer.from(JSON.stringify(observation) + "\n"),
        },
      }),
    );
  } catch (error) {
    deps.logger.warn("Failed to emit observation to Firehose", {
      error,
      sessionId: params.sessionId,
    });
    deps.metrics.addMetric("ObservationEmitError", MetricUnit.Count, 1);
  }
}
