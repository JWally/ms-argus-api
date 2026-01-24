import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  ProfileService,
  ProfileServiceConfig,
  ProfileServiceDeps,
} from "../../services/profile";
import { DynamoCacheService } from "../../services/cache";
import {
  PROFILE_TTL_DAYS,
  TIER2_BUCKET_TTL_DAYS,
  MUTATION_GATE_TTL_SECONDS,
} from "../../helpers/constants";
import type { ProfileUpdaterEnvConfig } from "../../config/env";

function getConfig(envConfig: ProfileUpdaterEnvConfig): ProfileServiceConfig {
  return {
    profilesTable: envConfig.PROFILES_TABLE,
    tier1IndexTable: envConfig.TIER1_INDEX_TABLE,
    tier2BucketsTable: envConfig.TIER2_BUCKETS_TABLE,
    profileTtlDays: PROFILE_TTL_DAYS,
    tier2BucketTtlDays: TIER2_BUCKET_TTL_DAYS,
    mutationGateTtlSeconds: MUTATION_GATE_TTL_SECONDS,
  };
}

export function createProfileService(deps: {
  dynamodb: DynamoDBClient;
  cacheService: DynamoCacheService;
  envConfig: ProfileUpdaterEnvConfig;
}): ProfileService {
  const serviceDeps: ProfileServiceDeps = {
    dynamodb: deps.dynamodb,
    cache: deps.cacheService,
    config: getConfig(deps.envConfig),
  };
  return new ProfileService(serviceDeps);
}
