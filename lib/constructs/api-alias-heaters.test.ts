import { Stack } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import * as lambda from "aws-cdk-lib/aws-lambda";
import { describe, expect, it } from "vitest";

import {
  addApiAliasHeaters,
  API_ALIAS_HEATER_CADENCE,
} from "./api-alias-heaters";

function makeAlias(stack: Stack, id: string): lambda.Alias {
  const fn = new lambda.Function(stack, id, {
    runtime: lambda.Runtime.NODEJS_20_X,
    handler: "index.handler",
    code: lambda.Code.fromInline("exports.handler = async () => undefined;"),
  });
  return fn.addAlias("live");
}

describe("API alias heaters", () => {
  it("heats every request-path alias every 10 seconds", () => {
    const stack = new Stack();

    addApiAliasHeaters(stack, {
      stackName: "test-api",
      ingestion: makeAlias(stack, "Ingestion"),
      sessionGet: makeAlias(stack, "SessionGet"),
      patAttest: makeAlias(stack, "PatAttest"),
    });

    const template = Template.fromStack(stack);
    template.resourceCountIs("AWS::Events::Rule", 3);
    for (const suffix of [
      "ingestion-heater",
      "session-get-heater",
      "pat-attest-heater",
    ]) {
      template.hasResourceProperties("AWS::Events::Rule", {
        Name: `test-api-${suffix}`,
        ScheduleExpression: "rate(1 minute)",
      });
    }

    const heaterFunctions = template.findResources("AWS::Lambda::Function", {
      Properties: {
        Environment: {
          Variables: Match.objectLike({
            INVOKES_PER_RUN: String(API_ALIAS_HEATER_CADENCE.invokesPerMinute),
            DELAY_MS: String(API_ALIAS_HEATER_CADENCE.spacingSeconds * 1000),
          }),
        },
      },
    });
    expect(Object.keys(heaterFunctions)).toHaveLength(3);
  });

  it("omits the PAT heater when PAT is not deployed", () => {
    const stack = new Stack();

    addApiAliasHeaters(stack, {
      stackName: "test-api",
      ingestion: makeAlias(stack, "Ingestion"),
      sessionGet: makeAlias(stack, "SessionGet"),
    });

    Template.fromStack(stack).resourceCountIs("AWS::Events::Rule", 2);
  });
});
