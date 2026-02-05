/**
 * @fileoverview Configuration factory for the profile updater handler.
 * Creates and configures ProfileService instances with proper TTL settings.
 * @module handlers/profile-updater/config
 */

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

/**
 * Builds ProfileService configuration from environment config.
 *
 * Maps environment variable table names to config properties and applies
 * standard TTL constants from the constants module.
 *
 * @param envConfig - Environment configuration with table names
 * @returns ProfileService configuration object
 *
 * @internal
 */
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

/**
 * Factory function to create a configured ProfileService instance.
 *
 * Wires up the DynamoDB client, cache service, and configuration into
 * a ready-to-use ProfileService for the profile updater Lambda.
 *
 * @param deps - Dependencies required to create the service
 * @param deps.dynamodb - DynamoDB client for profile/index operations
 * @param deps.cacheService - Cache service for mutation gating
 * @param deps.envConfig - Environment configuration with table names
 * @returns Configured ProfileService instance
 *
 * @example
 * ```typescript
 * const profileService = createProfileService({ dynamodb, cacheService, envConfig });
 * await profileService.updateProfile(deviceId, fingerprint);
 * ```
 */
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
