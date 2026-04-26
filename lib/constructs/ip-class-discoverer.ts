// lib/constructs/ip-class-discoverer.ts

import * as path from "path";
import { Construct } from "constructs";
import { Duration } from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda-nodejs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import { createBaseLambdaConfig, createWorkerEnv } from "./lambda-config";
import { getStageConfig } from "../config";

interface IpClassDiscovererProps {
  stackName: string;
  stage: string;
  /** S3 bucket holding the auto-overlay file (shared with ip-class-builder). */
  overlayBucket: s3.IBucket;
  /** The integrity-archive bucket; discoverer reads recent sessions from here. */
  archiveBucket: s3.IBucket;
  /** Cron hour (UTC) to run nightly. Default 03:00. */
  hour?: string;
}

/**
 * Nightly cron Lambda that discovers new CIDR rules via RDAP.
 *
 * Reads recent sessions from the integrity archive, finds IPs the runtime
 * classifier couldn't categorize, walks them through ARIN/RIPE/APNIC/
 * LACNIC/AFRINIC RDAP, applies reverse-search amplification, and merges
 * the resulting rules into `auto-overlay.json.gz` in the IP-class bucket.
 *
 * Runtime ingestion Lambdas pick up the updated overlay on next cold
 * start (or 24h TTL refresh). No DDB; everything is S3-backed for the
 * same per-request-cost reasons as ip-class-builder.
 *
 * Cost: ~1 Lambda execution per night, ~5 minutes wall-clock for ~100
 * unmapped IPs. Pennies/year. RDAP is free, no auth required.
 */
export class IpClassDiscovererConstruct extends Construct {
  public readonly discovererFunction: lambda.NodejsFunction;
  public readonly overlayKey: string;

  constructor(scope: Construct, id: string, props: IpClassDiscovererProps) {
    super(scope, id);

    const {
      stackName,
      stage,
      overlayBucket,
      archiveBucket,
      hour = "3",
    } = props;
    const config = getStageConfig(stage);
    this.overlayKey = "auto-overlay.json.gz";

    this.discovererFunction = new lambda.NodejsFunction(this, "DiscovererFn", {
      ...createBaseLambdaConfig({
        tracing: config.lambda.tracingEnabled,
        keepNames: true,
      }),
      entry: path.join(__dirname, "../../src/handlers/ip-class-discoverer.ts"),
      functionName: `${stackName}-ip-class-discoverer`,
      memorySize: 1024, // headroom for parallel S3 fetches + RDAP buffering
      timeout: Duration.minutes(15), // RDAP polite delay → up to ~15 min for big batches
      environment: {
        ...createWorkerEnv(
          stage,
          stackName,
          `${stackName}-ip-class-discoverer`,
        ),
        IP_CLASS_BUCKET: overlayBucket.bucketName,
        IP_CLASS_AUTO_OVERLAY_KEY: this.overlayKey,
        INTEGRITY_ARCHIVE_BUCKET: archiveBucket.bucketName,
      },
      // Single-instance only — concurrent runs would race on overlay file.
      reservedConcurrentExecutions: 1,
    });

    overlayBucket.grantReadWrite(this.discovererFunction);
    archiveBucket.grantRead(this.discovererFunction);

    // Daily 03:00 UTC. Runs after the weekly Friday ip-class-builder so it
    // operates on the freshest ASN dict.
    new events.Rule(this, "DailyRule", {
      ruleName: `${stackName}-ip-class-discoverer-daily`,
      description:
        "Daily RDAP-discovery walk over recent unmapped IPs in the integrity archive",
      schedule: events.Schedule.cron({ hour, minute: "0" }),
      targets: [new targets.LambdaFunction(this.discovererFunction)],
    });
  }

  /**
   * Grant a consumer Lambda read access to the auto-overlay file. Caller
   * must have already received the existing IP_CLASS_BUCKET / IP_CLASS_KEY
   * env vars from IpClassBuilderConstruct.grantReadTo — this construct
   * just adds the auto-overlay-specific key.
   */
  public grantReadTo(fn: lambda.NodejsFunction): void {
    fn.addEnvironment("IP_CLASS_AUTO_OVERLAY_KEY", this.overlayKey);
  }
}
