import type { IFunction } from "aws-cdk-lib/aws-lambda";
import type { Construct } from "constructs";

import { RecurringAliasHeater } from "./recurring-alias-heater";

export const API_ALIAS_HEATER_CADENCE = {
  invokesPerMinute: 6,
  spacingSeconds: 10,
} as const;

interface ApiAliasHeatersProps {
  stackName: string;
  ingestion: IFunction;
  sessionGet: IFunction;
  patAttest?: IFunction;
}

/** Keep every deployed request-path alias warm on the same cadence. */
export function addApiAliasHeaters(
  scope: Construct,
  props: ApiAliasHeatersProps,
): void {
  const targets: Array<{
    id: string;
    ruleName: string;
    target: IFunction;
    ruleLogicalId?: string;
  }> = [
    {
      id: "IngestionSocketHeater",
      ruleName: `${props.stackName}-ingestion-heater`,
      target: props.ingestion,
      // Preserve the deployed ingestion rule during this refactor.
      ruleLogicalId: "IngestionSocketHeater7405AD4B",
    },
    {
      id: "SessionGetHeater",
      ruleName: `${props.stackName}-session-get-heater`,
      target: props.sessionGet,
    },
  ];

  if (props.patAttest) {
    targets.push({
      id: "PatAttestHeater",
      ruleName: `${props.stackName}-pat-attest-heater`,
      target: props.patAttest,
    });
  }

  for (const target of targets) {
    new RecurringAliasHeater(scope, target.id, {
      ruleName: target.ruleName,
      target: target.target,
      ...API_ALIAS_HEATER_CADENCE,
      ruleLogicalId: target.ruleLogicalId,
    });
  }
}
