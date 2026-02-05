export * from "./types";

export * from "./matching-service";

export {
  writeMatchResult,
  writeDegradedResult,
  type SessionCacheDeps,
} from "./session-cache";

export {
  publicKeyLookup,
  cookieLookup,
  sigintIdLookup,
  hashMatch,
  type IndexLookupDeps,
} from "./index-lookup";

export { simHashMatch, type SimHashMatchDeps } from "./simhash-match";

export {
  loadProfile,
  type ProfileLoaderDeps,
  type ProfileData,
} from "./profile-loader";

export {
  vectorMatchWithTimeout,
  upsertDeviceVector,
  type VectorMatchDeps,
} from "./vector-match";

export {
  sessionAnchorLookup,
  ipUaAnchorLookup,
  type SessionAnchorDeps,
} from "./session-anchors";

export {
  buildSessionAnchorKey,
  buildIpUaAnchorKey,
} from "../../helpers/bucket-keys";
