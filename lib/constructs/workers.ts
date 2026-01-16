// lib/constructs/workers.ts
// AR-52: Simplified - removed VPC/Redis, uses DynamoDB for all caching
import * as path from "path";
import { Construct } from "constructs";
import * as lambda from "aws-cdk-lib/aws-lambda-nodejs";
import { Runtime, Tracing, Architecture, Alias } from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { OutputFormat } from "aws-cdk-lib/aws-lambda-nodejs";
import * as iam from "aws-cdk-lib/aws-iam";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as codedeploy from "aws-cdk-lib/aws-codedeploy";
import * as sns from "aws-cdk-lib/aws-sns";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import { Duration } from "aws-cdk-lib";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import { getStageConfig } from "../config";

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
  sessionCacheTable: dynamodb.ITable; // AR-52: Replaces Redis
  observationsDeliveryStreamName: string; // AR-57: Firehose for observations
}

/**
 * Worker Lambdas for Argus async processing
 *
 * AR-52: Simplified architecture - no VPC required
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
  public readonly matchingWorkerAlias: Alias;
  public readonly profileUpdaterAlias: Alias;

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
      observationsDeliveryStreamName,
    } = props;

    // Secrets Manager reference
    const secret = secretsmanager.Secret.fromSecretNameV2(
      this,
      `WorkerSecret`,
      `${stage}/${projectName}`,
    );

    // Common Lambda configuration - AR-52: No VPC needed
    const commonConfig = {
      runtime: Runtime.NODEJS_20_X,
      architecture: Architecture.ARM_64,
      bundling: {
        minify: true,
        sourceMap: true,
        target: "node20",
        keepNames: true,
        format: OutputFormat.CJS,
        mainFields: ["module", "main"],
        environment: { NODE_ENV: "production" },
        // AR-52: No longer need ioredis - using DynamoDB for caching
      },
      tracing: Tracing.ACTIVE,
      // AR-52: No VPC - workers access DynamoDB/SQS via IAM
    };

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
    const config = getStageConfig(stage);

    this.matchingWorker = new lambda.NodejsFunction(this, "MatchingWorker", {
      ...commonConfig,
      entry: path.join(__dirname, "../../src/handlers/matching-worker.ts"),
      functionName: `${stackName}-matching-worker`,
      memorySize: config.lambda.matching.memorySize,
      timeout: config.lambda.matching.timeout,
      reservedConcurrentExecutions: config.lambda.matching.reservedConcurrency,
      environment: {
        AWS_NODEJS_CONNECTION_REUSE_ENABLED: "1",
        ENVIRONMENT: stage,
        POWERTOOLS_SERVICE_NAME: `${stackName}-matching`,
        POWERTOOLS_METRICS_NAMESPACE: stackName,
        LOG_LEVEL: "INFO",
        SECRET_KEY_ARN: secret.secretArn,
        // AR-52: DynamoDB session cache replaces Redis
        SESSION_CACHE_TABLE: sessionCacheTable.tableName,
        PROFILES_TABLE: profilesTable.tableName,
        TIER1_INDEX_TABLE: tier1IndexTable.tableName,
        TIER2_BUCKETS_TABLE: tier2BucketsTable.tableName,
        PROFILE_QUEUE_URL: profileQueue.queueUrl,
        // AR-57: Firehose for match observations
        OBSERVATIONS_STREAM_NAME: observationsDeliveryStreamName,
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
    sessionCacheTable.grantReadWriteData(this.matchingWorker); // AR-52
    profileQueue.grantSendMessages(this.matchingWorker);
    matchingQueue.grantConsumeMessages(this.matchingWorker);

    // AR-57: Firehose permission for observations
    this.matchingWorker.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["firehose:PutRecord", "firehose:PutRecordBatch"],
        resources: [
          `arn:aws:firehose:*:*:deliverystream/${observationsDeliveryStreamName}`,
        ],
      }),
    );

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
        AWS_NODEJS_CONNECTION_REUSE_ENABLED: "1",
        ENVIRONMENT: stage,
        POWERTOOLS_SERVICE_NAME: `${stackName}-profile-updater`,
        POWERTOOLS_METRICS_NAMESPACE: stackName,
        LOG_LEVEL: "INFO",
        SECRET_KEY_ARN: secret.secretArn,
        // AR-52: DynamoDB session cache replaces Redis
        SESSION_CACHE_TABLE: sessionCacheTable.tableName,
        PROFILES_TABLE: profilesTable.tableName,
        TIER1_INDEX_TABLE: tier1IndexTable.tableName,
        TIER2_BUCKETS_TABLE: tier2BucketsTable.tableName,
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
    sessionCacheTable.grantReadWriteData(this.profileUpdater); // AR-52
    profileQueue.grantConsumeMessages(this.profileUpdater);

    // Alarms
    const matchingWorkerAlarms = this.createWorkerAlarms(
      this.matchingWorker,
      "MatchingWorker",
      alarmsTopic,
      config.lambda.matching.reservedConcurrency,
      config.alarms.lambda,
    );
    const profileUpdaterAlarms = this.createWorkerAlarms(
      this.profileUpdater,
      "ProfileUpdater",
      alarmsTopic,
      config.lambda.profile.reservedConcurrency,
      config.alarms.lambda,
    );

    // =====================================
    // CANARY DEPLOYMENTS (AR-24)
    // =====================================
    this.matchingWorkerAlias = new Alias(this, "MatchingWorkerLive", {
      aliasName: "live",
      version: this.matchingWorker.currentVersion,
    });

    this.profileUpdaterAlias = new Alias(this, "ProfileUpdaterLive", {
      aliasName: "live",
      version: this.profileUpdater.currentVersion,
    });

    // CodeDeploy deployment groups for canary releases
    new codedeploy.LambdaDeploymentGroup(this, "MatchingWorkerDeployment", {
      alias: this.matchingWorkerAlias,
      deploymentConfig:
        codedeploy.LambdaDeploymentConfig.CANARY_10PERCENT_5MINUTES,
      alarms: [
        matchingWorkerAlarms.errorAlarm,
        matchingWorkerAlarms.durationAlarm,
      ],
      autoRollback: {
        failedDeployment: true,
        stoppedDeployment: true,
        deploymentInAlarm: true,
      },
    });

    new codedeploy.LambdaDeploymentGroup(this, "ProfileUpdaterDeployment", {
      alias: this.profileUpdaterAlias,
      deploymentConfig:
        codedeploy.LambdaDeploymentConfig.CANARY_10PERCENT_5MINUTES,
      alarms: [
        profileUpdaterAlarms.errorAlarm,
        profileUpdaterAlarms.durationAlarm,
      ],
      autoRollback: {
        failedDeployment: true,
        stoppedDeployment: true,
        deploymentInAlarm: true,
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
}
