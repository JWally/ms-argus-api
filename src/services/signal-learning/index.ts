export {
  extractSignalObservation,
  resolveEngineKey,
  type SignalObservation,
} from "./extract";
export { passesDeterministicChecks } from "./validate";
export {
  learnSignals,
  getBaseline,
  getBaselines,
  SIGNAL_MODULES,
  type CachedBaseline,
} from "./repository";
