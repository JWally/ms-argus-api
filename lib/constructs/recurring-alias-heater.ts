// lib/constructs/recurring-alias-heater.ts
//
// EventBridge rules have one-minute resolution. This helper gets a true
// sub-minute warmup cadence by running once per minute and spacing async
// Lambda invokes inside a tiny heater function.

import { Duration, RemovalPolicy } from "aws-cdk-lib";
import { Construct } from "constructs";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";

export interface RecurringAliasHeaterProps {
  ruleName: string;
  target: lambda.IFunction;
  invokesPerMinute?: number;
  spacingSeconds?: number;
  /**
   * Existing logical ID to preserve when replacing an older EventBridge rule
   * that has the same physical ruleName.
   */
  ruleLogicalId?: string;
}

export class RecurringAliasHeater extends Construct {
  constructor(scope: Construct, id: string, props: RecurringAliasHeaterProps) {
    super(scope, id);

    const invokesPerMinute = props.invokesPerMinute ?? 6;
    const spacingSeconds = props.spacingSeconds ?? 10;

    const logGroup = new logs.LogGroup(this, "LogGroup", {
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const heater = new lambda.Function(this, "Function", {
      runtime: lambda.Runtime.NODEJS_20_X,
      architecture: lambda.Architecture.ARM_64,
      handler: "index.handler",
      memorySize: 128,
      timeout: Duration.seconds(70),
      reservedConcurrentExecutions: 1,
      logGroup,
      environment: {
        TARGET_ARN: props.target.functionArn,
        INVOKES_PER_RUN: String(invokesPerMinute),
        DELAY_MS: String(spacingSeconds * 1000),
      },
      code: lambda.Code.fromInline(`
const { LambdaClient, InvokeCommand } = require("@aws-sdk/client-lambda");

const lambda = new LambdaClient({});
const targetArn = process.env.TARGET_ARN;
const invokesPerRun = Number(process.env.INVOKES_PER_RUN || "6");
const delayMs = Number(process.env.DELAY_MS || "10000");
const payload = Buffer.from(JSON.stringify({ source: "serverless-plugin-warmup" }));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

exports.handler = async () => {
  for (let i = 0; i < invokesPerRun; i += 1) {
    await lambda.send(new InvokeCommand({
      FunctionName: targetArn,
      InvocationType: "Event",
      Payload: payload,
    }));
    if (i < invokesPerRun - 1) await sleep(delayMs);
  }
  return { invoked: invokesPerRun };
};
`),
    });

    props.target.grantInvoke(heater);

    const rule = new events.Rule(this, "Rule", {
      ruleName: props.ruleName,
      description: `Warm ${props.target.functionName} every ${spacingSeconds}s`,
      schedule: events.Schedule.rate(Duration.minutes(1)),
      targets: [new targets.LambdaFunction(heater)],
    });
    if (props.ruleLogicalId) {
      const cfnRule = rule.node.defaultChild as events.CfnRule;
      cfnRule.overrideLogicalId(props.ruleLogicalId);
    }
  }
}
