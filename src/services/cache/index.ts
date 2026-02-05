/**
 * Cache services for ms-argus-api.
 * @module services/cache
 */

export { DynamoCacheService, type DynamoCacheConfig } from "./dynamo-cache";

export {
  closeClient,
  // Statistical v2 exports
  recordFingerprintV2,
  fetchStatisticalV2Data,
  isStatisticalV2Enabled,
  getTieredTTL,
  type StatisticalV2Data,
} from "./valkey-client";

export { extractUaFamily } from "./ua-parser";
