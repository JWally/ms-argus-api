import { createHash } from "node:crypto";
import type { IntegrityResultsData } from "./payload-schema";

const CONSENSUS_FIELDS = [
  "hardwareConcurrency",
  "deviceMemory",
  "languages",
] as const;
const SHARED_PARTITION_FIELDS = new Set<string>(CONSENSUS_FIELDS);

type WorkerScope = Record<string, unknown>;

interface WorkerScopes {
  main: WorkerScope;
  web: WorkerScope;
  shared: WorkerScope;
}

export interface WorkerScopeEvidence {
  /** The outside scan has no analyzer issue and all three scopes agree. */
  all_scopes_consistent: boolean;
  /** Opaque comparison key for main + dedicated-worker stable attributes. */
  main_web_consensus_id: string | null;
  /** Only SharedWorker compute/memory/language values diverged. */
  shared_partition_candidate: boolean;
  /** Brave was independently observed by shielding and UA-CH brand checks. */
  brave_detected: boolean;
  /** Counterfactual score after removing worker-scope divergence alone. */
  device_tampering_without_worker: number;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function readScopes(integrity: IntegrityResultsData): WorkerScopes | null {
  const workerScope = (
    integrity.device as { workerScope?: { scopes?: unknown } } | undefined
  )?.workerScope;
  if (!isObject(workerScope?.scopes)) return null;
  const { main, web, shared } = workerScope.scopes;
  if (!isObject(main) || !isObject(web) || !isObject(shared)) return null;
  return { main, web, shared };
}

function equalField(
  scopes: WorkerScopes,
  field: (typeof CONSENSUS_FIELDS)[number],
): boolean {
  const main = scopes.main[field];
  return (
    main !== undefined &&
    scopes.web[field] !== undefined &&
    scopes.shared[field] !== undefined &&
    main === scopes.web[field] &&
    main === scopes.shared[field]
  );
}

function mainWebConsensusId(scopes: WorkerScopes | null): string | null {
  if (!scopes) return null;
  const values: Array<[string, unknown]> = [];
  for (const field of CONSENSUS_FIELDS) {
    const main = scopes.main[field];
    if (main === undefined || main !== scopes.web[field]) return null;
    values.push([field, main]);
  }
  return createHash("sha256")
    .update(JSON.stringify(["worker-consensus-v1", values]))
    .digest("hex");
}

function scopeHasBraveBrand(scope: WorkerScope): boolean {
  const brands = (scope.userAgentData as { brands?: unknown } | undefined)
    ?.brands;
  return (
    Array.isArray(brands) &&
    brands.some(
      (entry) =>
        (typeof entry === "string" && entry.toLowerCase() === "brave") ||
        (isObject(entry) &&
          typeof entry.brand === "string" &&
          entry.brand.toLowerCase() === "brave"),
    )
  );
}

function isBrave(integrity: IntegrityResultsData, scopes: WorkerScopes | null) {
  if (!scopes) return false;
  const shielding = (
    integrity.device as
      | { shielding?: { privacy?: unknown; engine?: unknown } }
      | undefined
  )?.shielding;
  return (
    shielding?.privacy === "Brave" &&
    shielding.engine === "Blink" &&
    scopeHasBraveBrand(scopes.main) &&
    scopeHasBraveBrand(scopes.web) &&
    scopeHasBraveBrand(scopes.shared)
  );
}

function isSharedPartitionCandidate(integrity: IntegrityResultsData): boolean {
  const divergences = integrity.analysis.worker.divergences ?? [];
  return (
    divergences.length > 0 &&
    divergences.every(
      ({ field, main, web, shared }) =>
        SHARED_PARTITION_FIELDS.has(field) &&
        main !== undefined &&
        main === web &&
        shared !== undefined &&
        shared !== main,
    )
  );
}

export function deriveWorkerScopeEvidence(
  integrity: IntegrityResultsData,
  deviceTamperingWithoutWorker: number,
): WorkerScopeEvidence {
  const scopes = readScopes(integrity);
  const worker = integrity.analysis.worker;
  const allScopesConsistent =
    !!scopes &&
    worker.lied === false &&
    (worker.divergences ?? []).length === 0 &&
    (worker.signals ?? []).length === 0 &&
    CONSENSUS_FIELDS.every((field) => equalField(scopes, field));

  return {
    all_scopes_consistent: allScopesConsistent,
    main_web_consensus_id: mainWebConsensusId(scopes),
    shared_partition_candidate:
      !!scopes && isSharedPartitionCandidate(integrity),
    brave_detected: isBrave(integrity, scopes),
    device_tampering_without_worker: deviceTamperingWithoutWorker,
  };
}
