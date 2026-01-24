import {
  MatchingService,
  MatchingServiceConfig,
  MatchingServiceDeps,
} from "../../services/matching";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { SQSClient } from "@aws-sdk/client-sqs";
import { DynamoCacheService } from "../../services/cache";
import { SESSION_TTL_SECONDS, TIER2_TIMEOUT_MS } from "../../helpers/constants";
import type { MatchingWorkerEnvConfig } from "../../config/env";

function getConfig(envConfig: MatchingWorkerEnvConfig): MatchingServiceConfig {
  return {
    tier1IndexTable: envConfig.TIER1_INDEX_TABLE,
    tier2BucketsTable: envConfig.TIER2_BUCKETS_TABLE,
    profilesTable: envConfig.PROFILES_TABLE,
    profileQueueUrl: envConfig.PROFILE_QUEUE_URL,
    sessionTtlSeconds: SESSION_TTL_SECONDS,
    tier2TimeoutMs: TIER2_TIMEOUT_MS,
  };
}

export function createMatchingService(deps: {
  dynamodb: DynamoDBClient;
  sqs: SQSClient;
  cacheService: DynamoCacheService;
  envConfig: MatchingWorkerEnvConfig;
}): MatchingService {
  const serviceDeps: MatchingServiceDeps = {
    dynamodb: deps.dynamodb,
    sqs: deps.sqs,
    cache: deps.cacheService,
    config: getConfig(deps.envConfig),
  };
  return new MatchingService(serviceDeps);
}
