# Baseline Filtering Rules - Design Sketch

## Problem

Tampered/spoofed fingerprints can poison the statistical baseline, making anomaly detection less effective. We need rules to skip baseline updates when fingerprints show signs of manipulation.

## Design

### 1. Rule Configuration File

Location: `src/config/baseline-rules.yaml` (or JSON)

```yaml
# Baseline update filtering rules
# If ANY rule matches, skip updating the statistical baseline
# The fingerprint is still scored against existing baseline

version: 1

rules:
  # Skip if excessive API tampering detected
  - id: excessive_lies
    description: "Skip baseline update if too many lies detected"
    condition:
      field: "device.lies_count"
      operator: ">"
      value: 50

  # Skip if worker UA disagrees with main UA
  - id: worker_ua_mismatch
    description: "Skip if shared-worker reports different UA"
    condition:
      field: "fingerprint.worker_ua_mismatch"
      operator: "=="
      value: true

  # Skip if navigator properties were modified
  - id: navigator_tampering
    description: "Skip if navigator API shows tampering"
    condition:
      field: "device.navigator_tampered"
      operator: "=="
      value: true

  # Skip known automation patterns
  - id: headless_with_stealth
    description: "Skip headless browsers using stealth plugins"
    condition:
      all:
        - field: "device.headless_detected"
          operator: "=="
          value: true
        - field: "device.lies_count"
          operator: ">"
          value: 10

  # Skip if WebGL renderer is spoofed
  - id: webgl_spoofed
    description: "Skip if WebGL renderer doesn't match expected for UA"
    condition:
      field: "fingerprint.webgl_renderer_mismatch"
      operator: "=="
      value: true

  # Environment-specific overrides
  # In dev, we might want to be more permissive for testing
  environments:
    dev:
      disabled_rules:
        - headless_with_stealth  # Allow for bot testing
    prod:
      disabled_rules: []
```

### 2. Rule Engine Types

```typescript
// src/services/profile/anomaly/baseline-rules.ts

export interface RuleCondition {
  field: string;
  operator: "==" | "!=" | ">" | "<" | ">=" | "<=";
  value: string | number | boolean;
}

export interface CompositeCondition {
  all?: RuleCondition[]; // AND
  any?: RuleCondition[]; // OR
}

export interface BaselineRule {
  id: string;
  description: string;
  condition: RuleCondition | CompositeCondition;
}

export interface BaselineRulesConfig {
  version: number;
  rules: BaselineRule[];
  environments?: {
    [env: string]: {
      disabled_rules?: string[];
    };
  };
}

export interface RuleContext {
  fingerprint: {
    user_agent?: string;
    worker_ua_mismatch?: boolean;
    webgl_renderer_mismatch?: boolean;
    // ... other fields
  };
  device: {
    lies_count?: number;
    headless_detected?: boolean;
    navigator_tampered?: boolean;
    // ... other fields
  };
}

export interface RuleEvaluationResult {
  shouldSkipBaseline: boolean;
  matchedRules: string[];
}
```

### 3. Rule Engine Implementation

```typescript
// src/services/profile/anomaly/baseline-rules.ts

import { Logger } from "@aws-lambda-powertools/logger";
import baselineRulesConfig from "../../../config/baseline-rules.json";

const logger = new Logger({ serviceName: "baseline-rules" });

/**
 * Evaluate a single condition against the context
 */
function evaluateCondition(
  condition: RuleCondition,
  context: RuleContext,
): boolean {
  const value = getFieldValue(context, condition.field);

  switch (condition.operator) {
    case "==":
      return value === condition.value;
    case "!=":
      return value !== condition.value;
    case ">":
      return (value as number) > (condition.value as number);
    case "<":
      return (value as number) < (condition.value as number);
    case ">=":
      return (value as number) >= (condition.value as number);
    case "<=":
      return (value as number) <= (condition.value as number);
    default:
      return false;
  }
}

/**
 * Get nested field value from context using dot notation
 * e.g., "device.lies_count" -> context.device.lies_count
 */
function getFieldValue(context: RuleContext, field: string): unknown {
  const parts = field.split(".");
  let value: unknown = context;
  for (const part of parts) {
    if (value == null) return undefined;
    value = (value as Record<string, unknown>)[part];
  }
  return value;
}

/**
 * Evaluate whether baseline update should be skipped
 */
export function evaluateBaselineRules(
  context: RuleContext,
): RuleEvaluationResult {
  const env = process.env.STAGE || "dev";
  const disabledRules = new Set(
    baselineRulesConfig.environments?.[env]?.disabled_rules ?? [],
  );

  const matchedRules: string[] = [];

  for (const rule of baselineRulesConfig.rules) {
    // Skip disabled rules for this environment
    if (disabledRules.has(rule.id)) continue;

    const matches = evaluateRule(rule, context);
    if (matches) {
      matchedRules.push(rule.id);
      logger.debug("Baseline rule matched", {
        ruleId: rule.id,
        description: rule.description,
      });
    }
  }

  return {
    shouldSkipBaseline: matchedRules.length > 0,
    matchedRules,
  };
}

function evaluateRule(rule: BaselineRule, context: RuleContext): boolean {
  const condition = rule.condition;

  // Composite condition with 'all' (AND)
  if ("all" in condition && condition.all) {
    return condition.all.every((c) => evaluateCondition(c, context));
  }

  // Composite condition with 'any' (OR)
  if ("any" in condition && condition.any) {
    return condition.any.some((c) => evaluateCondition(c, context));
  }

  // Simple condition
  return evaluateCondition(condition as RuleCondition, context);
}
```

### 4. Integration with Statistical V2

```typescript
// In statistical-v2.ts fetchStatisticalContextV2()

export async function fetchStatisticalContextV2(
  fingerprint: Fingerprint,
  network: RawNetworkData | undefined,
  device?: DeviceData, // NEW: pass device data for rule evaluation
): Promise<StatisticalContextV2 | null> {
  // ... existing extraction code ...

  // Build rule context from available data
  const ruleContext: RuleContext = {
    fingerprint: {
      user_agent: userAgent,
      worker_ua_mismatch: detectWorkerUaMismatch(fingerprint),
      webgl_renderer_mismatch: detectWebglMismatch(fingerprint),
    },
    device: {
      lies_count: device?.lies?.length ?? 0,
      headless_detected: device?.headless_detected ?? false,
      navigator_tampered: device?.navigator_tampered ?? false,
    },
  };

  // Evaluate baseline rules
  const ruleResult = evaluateBaselineRules(ruleContext);

  if (ruleResult.shouldSkipBaseline) {
    logger.info("Skipping baseline update due to rule match", {
      matchedRules: ruleResult.matchedRules,
      uaFamily,
    });

    // Still compute scores against existing baseline, just don't update it
    const [ja4Data, h2Data] = await Promise.all([
      ja4 ? fetchStatisticalV2Data(uaFamily, "ja4", ja4) : null, // Read-only
      h2 ? fetchStatisticalV2Data(uaFamily, "h2", h2) : null, // Read-only
    ]);

    // ... compute scores without recording ...
  } else {
    // Normal flow: record and compute
    const [ja4Data, h2Data] = await Promise.all([
      ja4 ? recordFingerprintV2(uaFamily, "ja4", ja4) : null,
      h2 ? recordFingerprintV2(uaFamily, "h2", h2) : null,
    ]);

    // ... compute scores ...
  }
}
```

### 5. Files to Create/Modify

| File                                                  | Action | Description                                        |
| ----------------------------------------------------- | ------ | -------------------------------------------------- |
| `src/config/baseline-rules.json`                      | Create | Rule configuration                                 |
| `src/services/profile/anomaly/baseline-rules.ts`      | Create | Rule engine                                        |
| `src/services/profile/anomaly/baseline-rules.test.ts` | Create | Unit tests                                         |
| `src/services/profile/anomaly/statistical-v2.ts`      | Modify | Integrate rule evaluation                          |
| `src/services/cache/valkey-client.ts`                 | Verify | Ensure `fetchStatisticalV2Data` exists (read-only) |

### 6. Example Rule Scenarios

| Scenario                             | Rule Triggered          | Baseline Updated? | Scored? |
| ------------------------------------ | ----------------------- | ----------------- | ------- |
| Normal Chrome user                   | None                    | ✅ Yes            | ✅ Yes  |
| Headless + 305 lies (stealth plugin) | `headless_with_stealth` | ❌ No             | ✅ Yes  |
| Worker UA mismatch                   | `worker_ua_mismatch`    | ❌ No             | ✅ Yes  |
| Firefox bot (no tampering)           | None                    | ✅ Yes            | ✅ Yes  |
| Spoofed WebGL renderer               | `webgl_spoofed`         | ❌ No             | ✅ Yes  |

### 7. Future Enhancements

- **Rule weights**: Instead of binary skip, weight contributions to baseline
- **Confidence penalty**: Reduce confidence for suspicious fingerprints
- **Rule analytics**: Track which rules fire most often
- **Dynamic rules**: Load rules from remote config (S3, Parameter Store)
- **ML-based rules**: Use model to predict tampering probability

## Next Steps

1. Create the JSON config file with initial rules
2. Implement the rule engine with tests
3. Add helper functions to detect mismatches (worker UA, WebGL)
4. Integrate into `fetchStatisticalContextV2`
5. Add metrics for rule matches
6. Deploy to dev and test with bots
