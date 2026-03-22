// lib/constructs/workers.ts

import * as path from "path";
import { Construct } from "constructs";
import * as lambda from "aws-cdk-lib/aws-lambda-nodejs";
import { Alias } from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as iam from "aws-cdk-lib/aws-iam";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as codedeploy from "aws-cdk-lib/aws-codedeploy";
import * as sns from "aws-cdk-lib/aws-sns";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import { Duration } from "aws-cdk-lib";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import { getStageConfig } from "../config";
import { createBaseLambdaConfig, createWorkerEnv } from "./lambda-config";

interface WorkersConstructProps {
  stackName: string;
  stage: string;
  projectName: string;
  alarmsTopic: sns.ITopic;
  matchingQueue: sqs.IQueue;
  profileQueue: sqs.IQueue;
  profilesTable: dynamodb.ITable;
  tier1IndexTable: dynamodb.ITable;
  tier2BucketsTable: dynamodb.ITable;
  sessionCacheTable: dynamodb.ITable;
  sessionPayloadTable: dynamodb.ITable; // AR-XXX: Full payload for gRPC stub
  vectorResultsTable: dynamodb.ITable; // Vector search results for session retrieval
  observationsDeliveryStreamName: string;
  /** Optional: Vector queue for Qdrant upserts. When provided, profile-updater queues embeddings. */
  vectorQueue?: sqs.IQueue;
  /** Optional: Vector results queue for search result writes. */
  vectorResultsQueue?: sqs.IQueue;
  /** Optional: Vector worker Lambda ARN for Tier 2 vector search. */
  vectorWorkerArn?: string;
  /** Optional: Qdrant collection name for fingerprint vectors. Defaults to 'fingerprints'. */
  vectorCollection?: string;
  /** Optional: S3 bucket for payload archiving */
  payloadArchiveBucket?: s3.IBucket;
  /**
   * Optional: AES-256 key (64 hex chars) for decrypting encrypted probe responses
   * from ms-argus-sigint. Must match the SIGINT_AES_KEY used by the probe services.
   */
  sigintAesKey?: string;
}

/**
 * Worker Lambdas for Argus async processing
 *
 * Simplified architecture - no VPC required
 * - Matching Worker: SQS -> tiered matching -> DynamoDB (session cache)
 * - Profile Updater: SQS -> mutation gate -> DynamoDB
 *
 * Why no VPC:
 * - DynamoDB and SQS accessible via IAM (no network path needed)
 * - Removes NAT Gateway costs (~$32/month per NAT)
 * - Faster cold starts (no ENI attachment)
 * - Simpler infrastructure
 */
export class WorkersConstruct extends Construct {
  public readonly matchingWorker: lambda.NodejsFunction;
  public readonly profileUpdater: lambda.NodejsFunction;
  public readonly vectorResultsWriter?: lambda.NodejsFunction;
  public readonly matchingWorkerAlias: Alias;
  public readonly profileUpdaterAlias: Alias;

  // eslint-disable-next-line complexity, sonarjs/cognitive-complexity
  constructor(scope: Construct, id: string, props: WorkersConstructProps) {
    super(scope, id);

    const {
      stackName,
      stage,
      projectName,
      alarmsTopic,
      matchingQueue,
      profileQueue,
      profilesTable,
      tier1IndexTable,
      tier2BucketsTable,
      sessionCacheTable,
      sessionPayloadTable,
      vectorResultsTable,
      observationsDeliveryStreamName,
      vectorQueue,
      vectorResultsQueue,
      vectorWorkerArn,
      vectorCollection = "fingerprints",
      payloadArchiveBucket,
      sigintAesKey,
    } = props;

    // Secrets Manager reference
    const secret = secretsmanager.Secret.fromSecretNameV2(
      this,
      `WorkerSecret`,
      `${stage}/${projectName}`,
    );

    const config = getStageConfig(stage);
    const tracing = config.lambda.tracingEnabled;

    const commonConfig = createBaseLambdaConfig({
      tracing,
      keepNames: true,
    });

    // IAM Logging Policy
    const loggingPolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ],
      resources: ["*"],
    });

    // =====================================
    // MATCHING WORKER LAMBDA
    // =====================================

    this.matchingWorker = new lambda.NodejsFunction(this, "MatchingWorker", {
      ...commonConfig,
      entry: path.join(__dirname, "../../src/handlers/matching-worker.ts"),
      functionName: `${stackName}-matching-worker`,
      memorySize: config.lambda.matching.memorySize,
      timeout: config.lambda.matching.timeout,
      reservedConcurrentExecutions: config.lambda.matching.reservedConcurrency,
      environment: {
        ...createWorkerEnv(stage, stackName, `${stackName}-matching`),
        SECRET_KEY_ARN: secret.secretArn,

        SESSION_CACHE_TABLE: sessionCacheTable.tableName,
        // AR-XXX: Full payload table for gRPC stub
        SESSION_PAYLOAD_TABLE: sessionPayloadTable.tableName,
        PROFILES_TABLE: profilesTable.tableName,
        TIER1_INDEX_TABLE: tier1IndexTable.tableName,
        TIER2_BUCKETS_TABLE: tier2BucketsTable.tableName,
        PROFILE_QUEUE_URL: profileQueue.queueUrl,

        OBSERVATIONS_STREAM_NAME: observationsDeliveryStreamName,
        // Vector search for Tier 2 (replaces compound buckets when enabled)
        ...(vectorWorkerArn && {
          VECTOR_WORKER_ARN: vectorWorkerArn,
          VECTOR_COLLECTION: vectorCollection,
        }),

        ...(payloadArchiveBucket && {
          PAYLOAD_ARCHIVE_BUCKET: payloadArchiveBucket.bucketName,
          PAYLOAD_ARCHIVE_SAMPLE_RATE: stage === "prod" ? "0" : "1.0",
        }),
        ...(sigintAesKey && { SIGINT_AES_KEY: sigintAesKey }),
      },
    });

    // SQS event source for matching worker
    this.matchingWorker.addEventSource(
      new lambdaEventSources.SqsEventSource(matchingQueue, {
        batchSize: 10,
        maxBatchingWindow: config.sqs.batchingWindow.matching,
        reportBatchItemFailures: true,
      }),
    );

    // Permissions
    this.matchingWorker.addToRolePolicy(loggingPolicy);
    secret.grantRead(this.matchingWorker);
    profilesTable.grantReadData(this.matchingWorker);
    tier1IndexTable.grantReadData(this.matchingWorker);
    tier2BucketsTable.grantReadData(this.matchingWorker);
    sessionCacheTable.grantReadWriteData(this.matchingWorker);
    sessionPayloadTable.grantWriteData(this.matchingWorker); // AR-XXX: Full payload storage
    profileQueue.grantSendMessages(this.matchingWorker);
    matchingQueue.grantConsumeMessages(this.matchingWorker);

    if (payloadArchiveBucket) {
      payloadArchiveBucket.grantWrite(this.matchingWorker);
    }

    this.matchingWorker.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["firehose:PutRecord", "firehose:PutRecordBatch"],
        resources: [
          `arn:aws:firehose:*:*:deliverystream/${observationsDeliveryStreamName}`,
        ],
      }),
    );

    // Grant Lambda invoke permission for vector worker (Tier 2 vector search)
    if (vectorWorkerArn) {
      this.matchingWorker.addToRolePolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ["lambda:InvokeFunction"],
          resources: [vectorWorkerArn],
        }),
      );
    }

    // =====================================
    // PROFILE UPDATER LAMBDA
    // =====================================
    this.profileUpdater = new lambda.NodejsFunction(this, "ProfileUpdater", {
      ...commonConfig,
      entry: path.join(__dirname, "../../src/handlers/profile-updater.ts"),
      functionName: `${stackName}-profile-updater`,
      memorySize: config.lambda.profile.memorySize,
      timeout: config.lambda.profile.timeout,
      reservedConcurrentExecutions: config.lambda.profile.reservedConcurrency,
      environment: {
        ...createWorkerEnv(stage, stackName, `${stackName}-profile-updater`),
        SECRET_KEY_ARN: secret.secretArn,

        SESSION_CACHE_TABLE: sessionCacheTable.tableName,
        PROFILES_TABLE: profilesTable.tableName,
        TIER1_INDEX_TABLE: tier1IndexTable.tableName,
        TIER2_BUCKETS_TABLE: tier2BucketsTable.tableName,
        // Optional: Vector queue for Qdrant embeddings (feature flag)
        ...(vectorQueue && { VECTOR_QUEUE_URL: vectorQueue.queueUrl }),
      },
    });

    // SQS event source for profile updater
    this.profileUpdater.addEventSource(
      new lambdaEventSources.SqsEventSource(profileQueue, {
        batchSize: 10,
        maxBatchingWindow: config.sqs.batchingWindow.profile,
        reportBatchItemFailures: true,
      }),
    );

    // Permissions
    this.profileUpdater.addToRolePolicy(loggingPolicy);
    secret.grantRead(this.profileUpdater);
    profilesTable.grantReadWriteData(this.profileUpdater);
    tier1IndexTable.grantReadWriteData(this.profileUpdater);
    tier2BucketsTable.grantReadWriteData(this.profileUpdater);
    sessionCacheTable.grantReadWriteData(this.profileUpdater);
    profileQueue.grantConsumeMessages(this.profileUpdater);

    // Optional: Grant send permission to vector queue for Qdrant embeddings
    if (vectorQueue) {
      vectorQueue.grantSendMessages(this.profileUpdater);
    }

    // =====================================
    // VECTOR RESULTS WRITER LAMBDA
    // =====================================
    // Consumes from vector-results SQS queue and writes to DynamoDB
    // Enables async vector search results to be returned via /session endpoint

    if (vectorResultsQueue) {
      this.vectorResultsWriter = new lambda.NodejsFunction(
        this,
        "VectorResultsWriter",
        {
          ...commonConfig,
          entry: path.join(
            __dirname,
            "../../src/handlers/vector-results-writer.ts",
          ),
          functionName: `${stackName}-vector-results-writer`,
          memorySize: 256, // Simple DynamoDB write - minimal CPU needed
          timeout: Duration.seconds(15),
          environment: {
            ...createWorkerEnv(
              stage,
              stackName,
              `${stackName}-vector-results-writer`,
            ),
            VECTOR_RESULTS_TABLE: vectorResultsTable.tableName,
          },
        },
      );

      // SQS event source
      this.vectorResultsWriter.addEventSource(
        new lambdaEventSources.SqsEventSource(vectorResultsQueue, {
          batchSize: 10,
          maxBatchingWindow: Duration.seconds(0), // Process immediately
          reportBatchItemFailures: true,
        }),
      );

      // Permissions
      this.vectorResultsWriter.addToRolePolicy(loggingPolicy);
      vectorResultsTable.grantWriteData(this.vectorResultsWriter);
      vectorResultsQueue.grantConsumeMessages(this.vectorResultsWriter);
    }

    // Alarms (only for prod — dev alarms cost ~$13/month and sit in INSUFFICIENT_DATA)
    let matchingWorkerAlarms:
      | { errorAlarm: cloudwatch.Alarm; durationAlarm: cloudwatch.Alarm }
      | undefined;
    let profileUpdaterAlarms:
      | { errorAlarm: cloudwatch.Alarm; durationAlarm: cloudwatch.Alarm }
      | undefined;

    if (config.alarms.enabled) {
      // Data loss in analytics pipeline when Firehose writes fail
      this.createObservationEmitErrorAlarm(stackName, alarmsTopic);

      matchingWorkerAlarms = this.createWorkerAlarms(
        this.matchingWorker,
        "MatchingWorker",
        alarmsTopic,
        config.lambda.matching.reservedConcurrency,
        config.alarms.lambda,
      );
      profileUpdaterAlarms = this.createWorkerAlarms(
        this.profileUpdater,
        "ProfileUpdater",
        alarmsTopic,
        config.lambda.profile.reservedConcurrency,
        config.alarms.lambda,
      );

      // Uses CloudWatch anomaly detection to alert on sudden spikes in new device creation
      this.createNewDeviceAnomalyAlarm(
        stackName,
        alarmsTopic,
        config.alarms.newDeviceAnomalyStdDev,
      );
    }

    // =====================================

    // =====================================
    this.matchingWorkerAlias = new Alias(this, "MatchingWorkerLive", {
      aliasName: "live",
      version: this.matchingWorker.currentVersion,
    });

    this.profileUpdaterAlias = new Alias(this, "ProfileUpdaterLive", {
      aliasName: "live",
      version: this.profileUpdater.currentVersion,
    });

    // Deployment strategy: Canary for prod (safety), AllAtOnce for dev/qa/uat (speed)
    // Canary: 10% traffic for 5 minutes, then 100% if no alarms
    // AllAtOnce: Immediate 100% deployment for fast iteration
    const deploymentConfig =
      stage === "prod"
        ? codedeploy.LambdaDeploymentConfig.CANARY_10PERCENT_5MINUTES
        : codedeploy.LambdaDeploymentConfig.ALL_AT_ONCE;

    // CodeDeploy deployment groups for canary releases
    new codedeploy.LambdaDeploymentGroup(this, "MatchingWorkerDeployment", {
      alias: this.matchingWorkerAlias,
      deploymentConfig,
      alarms: matchingWorkerAlarms
        ? [matchingWorkerAlarms.errorAlarm, matchingWorkerAlarms.durationAlarm]
        : [],
      autoRollback: {
        failedDeployment: true,
        stoppedDeployment: true,
        deploymentInAlarm: matchingWorkerAlarms !== undefined,
      },
    });

    new codedeploy.LambdaDeploymentGroup(this, "ProfileUpdaterDeployment", {
      alias: this.profileUpdaterAlias,
      deploymentConfig,
      alarms: profileUpdaterAlarms
        ? [profileUpdaterAlarms.errorAlarm, profileUpdaterAlarms.durationAlarm]
        : [],
      autoRollback: {
        failedDeployment: true,
        stoppedDeployment: true,
        deploymentInAlarm: profileUpdaterAlarms !== undefined,
      },
    });
  }

  private createWorkerAlarms(
    fn: lambda.NodejsFunction,
    prefix: string,
    alarmsTopic: sns.ITopic,
    reservedConcurrency: number,
    alarmConfig: {
      errorThreshold: number;
      throttleThreshold: number;
      durationThresholdMs: number;
      concurrencyPercent: number;
    },
  ): { errorAlarm: cloudwatch.Alarm; durationAlarm: cloudwatch.Alarm } {
    // Error count alarm
    const errorAlarm = new cloudwatch.Alarm(this, `${prefix}Errors`, {
      metric: fn.metricErrors({
        period: Duration.minutes(5),
        statistic: "Sum",
      }),
      threshold: alarmConfig.errorThreshold,
      evaluationPeriods: 2,
      alarmDescription: `Lambda ${fn.functionName} has > ${alarmConfig.errorThreshold} errors in 5 minutes`,
    });
    errorAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Throttle alarm
    const throttleAlarm = new cloudwatch.Alarm(this, `${prefix}Throttles`, {
      metric: fn.metricThrottles({
        period: Duration.minutes(5),
        statistic: "Sum",
      }),
      threshold: alarmConfig.throttleThreshold,
      evaluationPeriods: 1,
      alarmDescription: `Lambda ${fn.functionName} is throttled`,
    });
    throttleAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // High duration alarm (p95)
    const durationAlarm = new cloudwatch.Alarm(this, `${prefix}HighDuration`, {
      metric: fn.metricDuration({
        period: Duration.minutes(5),
        statistic: "p95",
      }),
      threshold: alarmConfig.durationThresholdMs,
      evaluationPeriods: 3,
      alarmDescription: `Lambda ${fn.functionName} p95 duration > ${alarmConfig.durationThresholdMs}ms`,
    });
    durationAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Concurrent executions alarm
    const concurrencyThreshold = Math.floor(
      reservedConcurrency * (alarmConfig.concurrencyPercent / 100),
    );
    const concurrencyAlarm = new cloudwatch.Alarm(
      this,
      `${prefix}HighConcurrency`,
      {
        metric: fn.metric("ConcurrentExecutions", {
          period: Duration.minutes(1),
          statistic: "Maximum",
        }),
        threshold: concurrencyThreshold,
        evaluationPeriods: 3,
        alarmDescription: `Lambda ${fn.functionName} at ${concurrencyThreshold}/${reservedConcurrency} concurrent executions (${alarmConfig.concurrencyPercent}% threshold)`,
      },
    );
    concurrencyAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    return { errorAlarm, durationAlarm };
  }

  /**
   * Create anomaly detection alarm for NEW_DEVICE_RATE metric
   * Alerts when new device creation rate exceeds normal baseline (potential fraud indicator)
   */
  private createNewDeviceAnomalyAlarm(
    stackName: string,
    alarmsTopic: sns.ITopic,
    stdDevThreshold: number,
  ): void {
    const metricNamespace = stackName;
    const metricName = "NEW_DEVICE_RATE";

    // Create anomaly detector for the NEW_DEVICE_RATE metric
    const anomalyDetector = new cloudwatch.CfnAnomalyDetector(
      this,
      "NewDeviceRateAnomalyDetector",
      {
        namespace: metricNamespace,
        metricName: metricName,
        stat: "Sum",
      },
    );

    // Create alarm using anomaly detection band
    // Alarm triggers when metric exceeds the upper band of the anomaly model
    const anomalyAlarm = new cloudwatch.CfnAlarm(
      this,
      "NewDeviceRateAnomalyAlarm",
      {
        alarmName: `${stackName}-new-device-rate-anomaly`,
        alarmDescription: `NEW_DEVICE_RATE exceeds ${stdDevThreshold} standard deviations from baseline - potential fraud attack`,
        comparisonOperator: "GreaterThanUpperThreshold",
        evaluationPeriods: 3,
        datapointsToAlarm: 2,
        thresholdMetricId: "ad1",
        metrics: [
          {
            id: "m1",
            metricStat: {
              metric: {
                namespace: metricNamespace,
                metricName: metricName,
              },
              period: 300, // 5 minutes
              stat: "Sum",
            },
            returnData: true,
          },
          {
            id: "ad1",
            expression: `ANOMALY_DETECTION_BAND(m1, ${stdDevThreshold})`,
            label: "NewDeviceRateAnomalyBand",
            returnData: true,
          },
        ],
        treatMissingData: "notBreaching",
        alarmActions: [alarmsTopic.topicArn],
        okActions: [alarmsTopic.topicArn],
      },
    );

    // Ensure alarm depends on the anomaly detector
    anomalyAlarm.addDependency(anomalyDetector);
  }

  /**
   * Create alarm for Firehose observation emit errors
   * Alerts when observation data fails to write to Firehose (data loss)
   */
  private createObservationEmitErrorAlarm(
    stackName: string,
    alarmsTopic: sns.ITopic,
  ): void {
    const alarm = new cloudwatch.Alarm(this, "ObservationEmitErrorAlarm", {
      alarmName: `${stackName}-observation-emit-error`,
      alarmDescription:
        "Firehose observation writes failing - analytics data loss",
      metric: new cloudwatch.Metric({
        namespace: stackName,
        metricName: "ObservationEmitError",
        statistic: "Sum",
        period: Duration.minutes(5),
      }),
      threshold: 0,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 2, // 10 minutes sustained
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    alarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }
}
