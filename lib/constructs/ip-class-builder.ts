// lib/constructs/ip-class-builder.ts

import * as path from "path";
import { Construct } from "constructs";
import { Duration, RemovalPolicy } from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda-nodejs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as cr from "aws-cdk-lib/custom-resources";
import * as iam from "aws-cdk-lib/aws-iam";
import { createBaseLambdaConfig, createWorkerEnv } from "./lambda-config";
import { getStageConfig } from "../config";

interface IpClassBuilderProps {
  stackName: string;
  stage: string;
  /**
   * Day of week to refresh the dataset. IPtoASN refreshes on Mondays from
   * BGP RIB dumps, so any non-Monday day catches the new data with margin.
   * Default: Friday — gives the freshest mid-week-business-traffic snapshot.
   */
  refreshDay?: "MON" | "TUE" | "WED" | "THU" | "FRI" | "SAT" | "SUN";
}

/**
 * Weekly cron Lambda that pulls the public IPtoASN BGP-derived dataset,
 * runs each ASN's organization name through a regex categorizer (with manual
 * overrides for ASNs whose names don't match cleanly), and uploads
 * `asn-categories.json.gz` to a versioned S3 bucket. Runtime Lambdas
 * (matching workers, ingestion handlers) consume the file via the
 * `services/network/asn-classifier.ts` module.
 *
 * Initialization: a CloudFormation custom resource invokes the builder once
 * during stack create/update so the bucket is seeded before any consumer
 * tries to read it. Without this, the first cold start after a fresh deploy
 * would 404 until the next Friday.
 *
 * Cost: ~$0.01/year (one Lambda run per week + ~12KB S3 storage).
 */
export class IpClassBuilderConstruct extends Construct {
  public readonly bucket: s3.Bucket;
  public readonly builderFunction: lambda.NodejsFunction;
  public readonly datasetKey: string;

  constructor(scope: Construct, id: string, props: IpClassBuilderProps) {
    super(scope, id);

    const { stackName, stage, refreshDay = "FRI" } = props;
    const config = getStageConfig(stage);

    this.datasetKey = "asn-categories.json.gz";

    this.bucket = new s3.Bucket(this, "Bucket", {
      bucketName: `${stackName}-ip-class`,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy:
        stage === "prod" ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
      autoDeleteObjects: stage !== "prod",
      lifecycleRules: [
        {
          id: "expire-old-versions",
          noncurrentVersionExpiration: Duration.days(30),
        },
      ],
    });

    this.builderFunction = new lambda.NodejsFunction(this, "BuilderFn", {
      ...createBaseLambdaConfig({
        tracing: config.lambda.tracingEnabled,
        keepNames: true,
      }),
      entry: path.join(__dirname, "../../src/handlers/ip-class-builder.ts"),
      functionName: `${stackName}-ip-class-builder`,
      memorySize: 512,
      timeout: Duration.minutes(5),
      environment: {
        ...createWorkerEnv(stage, stackName, `${stackName}-ip-class-builder`),
        IP_CLASS_BUCKET: this.bucket.bucketName,
        IP_CLASS_KEY: this.datasetKey,
      },
    });

    this.bucket.grantPut(this.builderFunction);

    // Weekly schedule. cron(min, hour, day-of-month, month, day-of-week, year)
    new events.Rule(this, "WeeklyRefreshRule", {
      ruleName: `${stackName}-ip-class-weekly`,
      description:
        "Weekly refresh of the ASN→category dataset from IPtoASN.com",
      schedule: events.Schedule.cron({
        weekDay: refreshDay,
        hour: "6",
        minute: "0",
      }),
      targets: [new targets.LambdaFunction(this.builderFunction)],
    });

    // Initialize on stack create/update — invoke the builder once so the
    // bucket is seeded immediately. The custom resource fires synchronously
    // during CFN deploy; if this fails, deploy fails (loud).
    const initInvoke = new cr.AwsCustomResource(this, "InitInvoke", {
      onCreate: {
        service: "Lambda",
        action: "invoke",
        parameters: {
          FunctionName: this.builderFunction.functionName,
          InvocationType: "RequestResponse",
        },
        physicalResourceId: cr.PhysicalResourceId.of(
          `${stackName}-ip-class-init`,
        ),
      },
      onUpdate: {
        service: "Lambda",
        action: "invoke",
        parameters: {
          FunctionName: this.builderFunction.functionName,
          InvocationType: "RequestResponse",
        },
        physicalResourceId: cr.PhysicalResourceId.of(
          `${stackName}-ip-class-init-${Date.now()}`,
        ),
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ["lambda:InvokeFunction"],
          resources: [this.builderFunction.functionArn],
        }),
      ]),
      timeout: Duration.minutes(6),
    });
    initInvoke.node.addDependency(this.builderFunction);
  }

  /** Grant a consumer Lambda read access + inject the env vars it needs. */
  public grantReadTo(fn: lambda.NodejsFunction): void {
    this.bucket.grantRead(fn);
    fn.addEnvironment("IP_CLASS_BUCKET", this.bucket.bucketName);
    fn.addEnvironment("IP_CLASS_KEY", this.datasetKey);
  }
}
