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
} from "./valkey-client";

export { extractUaFamily } from "./ua-parser";
