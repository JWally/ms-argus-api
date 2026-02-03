/**
 * Cache services for ms-argus-api.
 * @module services/cache
 */

export { DynamoCacheService, type DynamoCacheConfig } from "./dynamo-cache";

export {
  recordAndGetStats,
  isValkeyEnabled,
  closeClient,
  type StatisticalData,
  // Statistical v2 exports
  recordFingerprintV2,
  fetchStatisticalV2Data,
  isStatisticalV2Enabled,
  getTieredTTL,
  type StatisticalV2Data,
} from "./valkey-client";

export { extractUaFamily } from "./ua-parser";
