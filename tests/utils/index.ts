// tests/utils/index.ts
// AR-60: Central exports for test utilities

export {
  createFingerprint,
  createFingerprintFromPreset,
  createDriftedFingerprint,
  createMultipleFingerprints,
  createMatchingFingerprints,
  FingerprintPresets,
  type FingerprintOptions,
} from "./fingerprint.factory";

export {
  TestDbClient,
  TestScenarios,
  seedScenario,
  cleanupTenant,
  DEFAULT_TEST_DB_CONFIG,
  type TestDbConfig,
  type SeedDeviceProfile,
} from "./db.utils";
