// lib/constructs/browser-baseline-builder.ts

import * as path from "path";
import { Construct } from "constructs";
import { Duration } from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda-nodejs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import { createBaseLambdaConfig, createWorkerEnv } from "./lambda-config";
import { getStageConfig } from "../config";

interface BrowserBaselineBuilderProps {
  stackName: string;
  stage: string;
  /** S3 bucket for the output baselines file (shared with ip-class-builder). */
  outputBucket: s3.IBucket;
  /** Integrity archive bucket; aggregator reads recent sessions from here. */
  archiveBucket: s3.IBucket;
  /** Cron hour (UTC). Default 04:00 — runs after ip-class-discoverer @ 03:00. */
  hour?: string;
}

/**
 * Daily cron Lambda that walks recent integrity-archive sessions, extracts
 * engine-invariant fields, and builds per-(browser, version, incognito)
 * histograms of observed values. Output `browser-baselines.json.gz`
 * consumed by the runtime `analyzeBrowserEngine` analyzer to detect
 * engine-claim inconsistencies (e.g. UA claims Safari but jsEngine=V8 →
 * hard tampering signal at sev 0.95).
 *
 * Anti-poisoning: per-(browser_version_key, ip, day) dedup at aggregation
 * time means a botnet must spread across many unique IPs to move histograms.
 *
 * Cost: ~7d × ~500 firehose batches × ~50KB = ~175MB scanned per run.
 * Single Lambda execution, well under timeout.
 */
export class BrowserBaselineBuilderConstruct extends Construct {
  public readonly builderFunction: lambda.NodejsFunction;
  public readonly baselinesKey: string;

  constructor(
    scope: Construct,
    id: string,
    props: BrowserBaselineBuilderProps,
  ) {
    super(scope, id);

    const { stackName, stage, outputBucket, archiveBucket, hour = "4" } = props;
    const config = getStageConfig(stage);
    this.baselinesKey = "browser-baselines.json.gz";

    this.builderFunction = new lambda.NodejsFunction(this, "BuilderFn", {
      ...createBaseLambdaConfig({
        tracing: config.lambda.tracingEnabled,
        keepNames: true,
      }),
      entry: path.join(
        __dirname,
        "../../src/handlers/browser-baseline-builder.ts",
      ),
      functionName: `${stackName}-browser-baseline-builder`,
      memorySize: 1024, // headroom for parallel S3 fetches + dedup Set
      timeout: Duration.minutes(10),
      environment: {
        ...createWorkerEnv(
          stage,
          stackName,
          `${stackName}-browser-baseline-builder`,
        ),
        IP_CLASS_BUCKET: outputBucket.bucketName,
        BROWSER_BASELINES_KEY: this.baselinesKey,
        INTEGRITY_ARCHIVE_BUCKET: archiveBucket.bucketName,
      },
      // Single-instance only — concurrent runs would race on output file.
      reservedConcurrentExecutions: 1,
    });

    outputBucket.grantPut(this.builderFunction);
    archiveBucket.grantRead(this.builderFunction);

    new events.Rule(this, "DailyRule", {
      ruleName: `${stackName}-browser-baseline-daily`,
      description:
        "Daily aggregation of browser-engine invariant baselines from recent sessions",
      schedule: events.Schedule.cron({ hour, minute: "0" }),
      targets: [new targets.LambdaFunction(this.builderFunction)],
    });
  }

  /**
   * Grant a consumer Lambda read access to the baselines file + add the
   * env var with the key. Caller must have already received the
   * IP_CLASS_BUCKET env var from IpClassBuilderConstruct.grantReadTo.
   */
  public grantReadTo(fn: lambda.NodejsFunction): void {
    fn.addEnvironment("BROWSER_BASELINES_KEY", this.baselinesKey);
  }
}
