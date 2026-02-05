/**
 * Baseline Filtering Rules for Statistical V2.
 *
 * Config-driven rule engine that prevents tampered/spoofed fingerprints
 * from polluting the statistical v2 baseline. Matching fingerprints are
 * still scored against the existing baseline, but their observations
 * are not recorded.
 *
 * @module services/profile/anomaly/baseline-rules
 */

import type { Fingerprint } from "../../../types/fingerprint";
import rulesConfig from "../../../config/baseline-rules.json";

// ============================================================================
// Types
// ============================================================================

export interface RuleCondition {
  field: string;
  operator: "==" | "!=" | ">" | "<" | ">=" | "<=";
  value: string | number | boolean;
}

export interface CompositeCondition {
  all?: RuleCondition[];
  any?: RuleCondition[];
}

export interface BaselineRule {
  id: string;
  description: string;
  condition: RuleCondition | CompositeCondition;
}

export interface RuleEvaluationResult {
  shouldSkipBaseline: boolean;
  matchedRules: string[];
}

export interface RuleContext {
  lie_count: number;
  is_headless: boolean;
  worker_ua_mismatch: boolean;
  proxy_score: number;
  vpn_score: number;
}

type PayloadDevice = Record<string, Record<string, unknown> | undefined>;

// ============================================================================
// Rule Context Builder
// ============================================================================

/**
 * Build a flat rule context from normalized fingerprint and raw device payload.
 *
 * Extracts fields from the fingerprint and computes derived fields like
 * worker_ua_mismatch by comparing navigator.userAgent against worker scope UAs.
 */
export function buildRuleContext(
  fingerprint: Fingerprint,
  device?: PayloadDevice,
): RuleContext {
  return {
    lie_count: fingerprint.lie_count ?? 0,
    is_headless: fingerprint.is_headless ?? false,
    worker_ua_mismatch: detectWorkerUaMismatch(device),
    proxy_score: fingerprint.proxy_score ?? 0,
    vpn_score: fingerprint.vpn_score ?? 0,
  };
}

/**
 * Detect mismatch between navigator.userAgent and worker scope userAgents.
 *
 * Compares `device.navigator.userAgent` against each available worker scope:
 * - `device.workerScope.scopes.web.userAgent`
 * - `device.workerScope.scopes.shared.userAgent`
 * - `device.workerScope.scopes.service.userAgent`
 *
 * Returns true if any worker scope has a different userAgent than navigator.
 */
function detectWorkerUaMismatch(device?: PayloadDevice): boolean {
  if (!device) return false;

  const navigator = device.navigator as Record<string, unknown> | undefined;
  const navUa = navigator?.userAgent;
  if (typeof navUa !== "string") return false;

  const workerScope = device.workerScope as Record<string, unknown> | undefined;
  if (!workerScope) return false;

  const scopes = workerScope.scopes as
    | Record<string, Record<string, unknown> | null | undefined>
    | undefined;

  if (!scopes) {
    // Fallback: top-level workerScope.userAgent
    const wsUa = workerScope.userAgent;
    if (typeof wsUa === "string") {
      return wsUa !== navUa;
    }
    return false;
  }

  const scopeKeys = ["web", "shared", "service"] as const;
  for (const key of scopeKeys) {
    const scope = scopes[key];
    if (scope && typeof scope === "object") {
      const scopeUa = (scope as Record<string, unknown>).userAgent;
      if (typeof scopeUa === "string" && scopeUa !== navUa) {
        return true;
      }
    }
  }

  return false;
}

// ============================================================================
// Rule Evaluation
// ============================================================================

/**
 * Get a field value from the flat rule context.
 */
function getFieldValue(
  context: RuleContext,
  field: string,
): string | number | boolean | undefined {
  if (!(field in context)) return undefined;
  return (context as unknown as Record<string, string | number | boolean>)[
    field
  ];
}

/**
 * Evaluate a single rule condition against the context.
 */
function evaluateCondition(
  context: RuleContext,
  condition: RuleCondition,
): boolean {
  const actual = getFieldValue(context, condition.field);
  if (actual === undefined) return false;

  const expected = condition.value;
  switch (condition.operator) {
    case "==":
      return actual === expected;
    case "!=":
      return actual !== expected;
    case ">":
      return (actual as number) > (expected as number);
    case "<":
      return (actual as number) < (expected as number);
    case ">=":
      return (actual as number) >= (expected as number);
    case "<=":
      return (actual as number) <= (expected as number);
    default:
      return false;
  }
}

/**
 * Check if a condition object is a composite condition (has `all` or `any`).
 */
function isCompositeCondition(
  condition: RuleCondition | CompositeCondition,
): condition is CompositeCondition {
  return "all" in condition || "any" in condition;
}

/**
 * Evaluate a rule's condition (simple or composite) against the context.
 */
function evaluateRuleCondition(
  context: RuleContext,
  condition: RuleCondition | CompositeCondition,
): boolean {
  if (!isCompositeCondition(condition)) {
    return evaluateCondition(context, condition);
  }

  if (condition.all) {
    return condition.all.every((c) => evaluateCondition(context, c));
  }

  if (condition.any) {
    return condition.any.some((c) => evaluateCondition(context, c));
  }

  return false;
}

/**
 * Evaluate all baseline rules against the given context.
 *
 * Iterates over rules from baseline-rules.json, skips any rules disabled
 * for the current environment, and returns the list of matched rule IDs.
 */
export function evaluateBaselineRules(
  context: RuleContext,
  environment?: string,
): RuleEvaluationResult {
  const rules = rulesConfig.rules as BaselineRule[];
  const envConfig =
    environment &&
    rulesConfig.environments[
      environment as keyof typeof rulesConfig.environments
    ];
  const disabledRules = new Set(
    envConfig ? (envConfig as { disabled_rules: string[] }).disabled_rules : [],
  );

  const matchedRules: string[] = [];

  for (const rule of rules) {
    if (disabledRules.has(rule.id)) continue;

    if (evaluateRuleCondition(context, rule.condition)) {
      matchedRules.push(rule.id);
    }
  }

  return {
    shouldSkipBaseline: matchedRules.length > 0,
    matchedRules,
  };
}
