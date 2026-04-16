// lib/constructs/workers.ts

import * as path from "path";
import { Construct } from "constructs";
import * as lambda from "aws-cdk-lib/aws-lambda-nodejs";
import {
  FilterCriteria,
  FilterRule,
  StartingPosition,
} from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import * as iam from "aws-cdk-lib/aws-iam";
import * as sns from "aws-cdk-lib/aws-sns";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import { Duration } from "aws-cdk-lib";
import { getStageConfig } from "../config";
import { createBaseLambdaConfig, createWorkerEnv } from "./lambda-config";

interface WorkersConstructProps {
  stackName: string;
  stage: string;
  projectName: string;
  alarmsTopic: sns.ITopic;
  /** S3 bucket for integrity result archiving (DynamoDB Stream → S3). */
  integrityArchiveBucket: s3.IBucket;
  /** Integrity results table (with stream enabled) for archiver event source. */
  integrityResultsTable: dynamodb.ITable;
}

/**
 * Background workers for the integrity-only pipeline.
 *
 * Only the IntegrityArchiver Lambda remains: it tails the integrity-results
 * DynamoDB stream and writes each INSERT to S3 for later analysis. The
 * matching-worker, profile-updater, and vector-results-writer Lambdas were
 * removed along with the /v1/collect fingerprint pipeline.
 */
export class WorkersConstruct extends Construct {
  public readonly integrityArchiver: lambda.NodejsFunction;

  constructor(scope: Construct, id: string, props: WorkersConstructProps) {
    super(scope, id);

    const { stackName, stage, integrityArchiveBucket, integrityResultsTable } =
      props;

    const config = getStageConfig(stage);
    const commonConfig = createBaseLambdaConfig({
      tracing: config.lambda.tracingEnabled,
      keepNames: true,
    });

    const loggingPolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ],
      resources: ["*"],
    });

    this.integrityArchiver = new lambda.NodejsFunction(
      this,
      "IntegrityArchiver",
      {
        ...commonConfig,
        entry: path.join(__dirname, "../../src/handlers/integrity-archiver.ts"),
        functionName: `${stackName}-integrity-archiver`,
        memorySize: 512,
        timeout: Duration.seconds(30),
        environment: {
          ...createWorkerEnv(
            stage,
            stackName,
            `${stackName}-integrity-archiver`,
          ),
          INTEGRITY_ARCHIVE_BUCKET: integrityArchiveBucket.bucketName,
        },
      },
    );

    this.integrityArchiver.addEventSource(
      new lambdaEventSources.DynamoEventSource(integrityResultsTable, {
        startingPosition: StartingPosition.LATEST,
        batchSize: 25,
        maxBatchingWindow: Duration.seconds(5),
        retryAttempts: 3,
        filters: [
          FilterCriteria.filter({
            eventName: FilterRule.isEqual("INSERT"),
          }),
        ],
      }),
    );

    this.integrityArchiver.addToRolePolicy(loggingPolicy);
    integrityArchiveBucket.grantWrite(this.integrityArchiver);
  }
}
