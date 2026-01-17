// src/services/profile/anomaly/index.ts
// AR-141: Public exports for anomaly detection module

export * from "./types";
export {
  detectAllAnomalies,
  registerDetector,
  getDetectorCount,
} from "./detector";
