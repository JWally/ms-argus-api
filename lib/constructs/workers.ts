// lib/constructs/workers.ts
// AR-52: Simplified - removed VPC/Redis, uses DynamoDB for all caching
// AR-130: Added cardinality recalculation Lambda with daily EventBridge rule
// AR-160: Centralized Lambda memory settings in stage config
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
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
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
  sessionCacheTable: dynamodb.ITable; // AR-52: Replaces Redis
  sessionPayloadTable: dynamodb.ITable; // AR-XXX: Full payload for gRPC stub
  observationsDeliveryStreamName: string; // AR-57: Firehose for observations
  /** Optional: Vector queue for Qdrant upserts. When provided, profile-updater queues embeddings. */
  vectorQueue?: sqs.IQueue;
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
  public readonly cardinalityRecalc: lambda.NodejsFunction; // AR-130
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
      sessionPayloadTable,
      observationsDeliveryStreamName,
      vectorQueue,
    } = props;

    // Secrets Manager reference
    const secret = secretsmanager.Secret.fromSecretNameV2(
      this,
      `WorkerSecret`,
      `${stage}/${projectName}`,
    );

    // AR-167: Use shared Lambda configuration
    // Common Lambda configuration - AR-52: No VPC needed
    const commonConfig = createBaseLambdaConfig({
      tracing: true,
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
    const config = getStageConfig(stage);

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
        // AR-52: DynamoDB session cache replaces Redis
        SESSION_CACHE_TABLE: sessionCacheTable.tableName,
        // AR-XXX: Full payload table for gRPC stub
        SESSION_PAYLOAD_TABLE: sessionPayloadTable.tableName,
        PROFILES_TABLE: profilesTable.tableName,
        TIER1_INDEX_TABLE: tier1IndexTable.tableName,
        TIER2_BUCKETS_TABLE: tier2BucketsTable.tableName,
        PROFILE_QUEUE_URL: profileQueue.queueUrl,
        // AR-57: Firehose for match observations
        OBSERVATIONS_STREAM_NAME: observationsDeliveryStreamName,
        // AR-XXX: SimHash LSH Tier 1.5 - same-browser drift detection
        SIMHASH_ENABLED: "true",
        SIMHASH_SHADOW: "false", // Set to "true" to log without affecting matching
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
    sessionPayloadTable.grantWriteData(this.matchingWorker); // AR-XXX: Full payload storage
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
        ...createWorkerEnv(stage, stackName, `${stackName}-profile-updater`),
        SECRET_KEY_ARN: secret.secretArn,
        // AR-52: DynamoDB session cache replaces Redis
        SESSION_CACHE_TABLE: sessionCacheTable.tableName,
        PROFILES_TABLE: profilesTable.tableName,
        TIER1_INDEX_TABLE: tier1IndexTable.tableName,
        TIER2_BUCKETS_TABLE: tier2BucketsTable.tableName,
        // AR-XXX: SimHash LSH Tier 1.5 - writes band entries when enabled
        SIMHASH_ENABLED: "true",
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
    sessionCacheTable.grantReadWriteData(this.profileUpdater); // AR-52
    profileQueue.grantConsumeMessages(this.profileUpdater);

    // Optional: Grant send permission to vector queue for Qdrant embeddings
    if (vectorQueue) {
      vectorQueue.grantSendMessages(this.profileUpdater);
    }

    // =====================================
    // AR-130: CARDINALITY RECALCULATION LAMBDA
    // =====================================
    // Daily Lambda to fix drift in Tier2 bucket cardinalities
    // Bucket cardinality counters use ADD which only increments.
    // When devices expire via TTL, cardinalities drift higher than reality.
    // This affects high-cardinality penalty calculations in fraud scoring.

    this.cardinalityRecalc = new lambda.NodejsFunction(
      this,
      "CardinalityRecalc",
      {
        ...commonConfig,
        entry: path.join(__dirname, "../../src/handlers/cardinality-recalc.ts"),
        functionName: `${stackName}-cardinality-recalc`,
        // AR-160: Use configurable memory from stage config
        memorySize: config.lambda.cardinalityRecalc.memorySize,
        timeout: Duration.minutes(15), // Max Lambda timeout for large tables
        environment: {
          ...createWorkerEnv(
            stage,
            stackName,
            `${stackName}-cardinality-recalc`,
          ),
          TIER2_BUCKETS_TABLE: tier2BucketsTable.tableName,
        },
      },
    );

    // Permissions - read/write to Tier2Buckets table
    this.cardinalityRecalc.addToRolePolicy(loggingPolicy);
    tier2BucketsTable.grantReadWriteData(this.cardinalityRecalc);

    // EventBridge rule - run daily at 3 AM UTC (low traffic time)
    const cardinalityRecalcRule = new events.Rule(
      this,
      "CardinalityRecalcRule",
      {
        ruleName: `${stackName}-cardinality-recalc-daily`,
        description: "AR-130: Daily cardinality recalculation to fix TTL drift",
        schedule: events.Schedule.cron({
          minute: "0",
          hour: "3",
          day: "*",
          month: "*",
          year: "*",
        }),
      },
    );

    cardinalityRecalcRule.addTarget(
      new targets.LambdaFunction(this.cardinalityRecalc),
    );

    // AR-152: Alarm for cardinality recalc partial failures
    // Silent failures in fraud-critical path - need immediate visibility
    this.createCardinalityRecalcAlarm(stackName, alarmsTopic);

    // AR-153: Alarm for Tier2 cardinality fetch failures
    // Affects fraud penalty scoring when cardinality data unavailable
    this.createTier2CardinalityFetchAlarm(stackName, alarmsTopic);

    // AR-154: Alarm for Firehose observation emit errors
    // Data loss in analytics pipeline when Firehose writes fail
    this.createObservationEmitErrorAlarm(stackName, alarmsTopic);

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

    // AR-123: New device rate anomaly detection alarm (fraud indicator)
    // Uses CloudWatch anomaly detection to alert on sudden spikes in new device creation
    this.createNewDeviceAnomalyAlarm(
      stackName,
      alarmsTopic,
      config.alarms.newDeviceAnomalyStdDev,
    );

    // AR-XXX: SimHash LSH Tier 1.5 alarms
    // Monitor performance and quality of same-browser drift matching
    this.createSimHashAlarms(stackName, alarmsTopic);

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
      deploymentConfig,
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

  /**
   * AR-123: Create anomaly detection alarm for NEW_DEVICE_RATE metric
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
   * AR-152: Create alarm for cardinality recalc partial failures
   * Alerts when ProcessingErrors > 0 to catch silent failures in fraud-critical path
   */
  private createCardinalityRecalcAlarm(
    stackName: string,
    alarmsTopic: sns.ITopic,
  ): void {
    const alarm = new cloudwatch.Alarm(
      this,
      "CardinalityRecalcPartialFailure",
      {
        alarmName: `${stackName}-cardinality-recalc-partial-failure`,
        alarmDescription:
          "Cardinality recalc had processing errors - fraud scoring may be affected",
        metric: new cloudwatch.Metric({
          namespace: stackName,
          metricName: "ProcessingErrors",
          dimensionsMap: {
            service: `${stackName}-cardinality-recalc`,
          },
          statistic: "Sum",
          period: Duration.hours(1), // Check hourly since it runs daily at 3 AM
        }),
        threshold: 0,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      },
    );
    alarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }

  /**
   * AR-153: Create alarm for Tier2 cardinality fetch failures
   * Alerts when cardinality fetch fails, affecting fraud penalty scoring
   */
  private createTier2CardinalityFetchAlarm(
    stackName: string,
    alarmsTopic: sns.ITopic,
  ): void {
    const alarm = new cloudwatch.Alarm(
      this,
      "Tier2CardinalityFetchFailedAlarm",
      {
        alarmName: `${stackName}-tier2-cardinality-fetch-failed`,
        alarmDescription:
          "Tier2 cardinality fetch failed - fraud penalty scoring disabled",
        metric: new cloudwatch.Metric({
          namespace: stackName,
          metricName: "Tier2CardinalityFetchFailed",
          statistic: "Sum",
          period: Duration.minutes(5),
        }),
        threshold: 0,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluationPeriods: 2, // 10 minutes sustained
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      },
    );
    alarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }

  /**
   * AR-154: Create alarm for Firehose observation emit errors
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

  /**
   * AR-XXX: Create alarms for SimHash LSH Tier 1.5 matching
   * Monitors performance and quality of same-browser drift detection
   */
  private createSimHashAlarms(
    stackName: string,
    alarmsTopic: sns.ITopic,
  ): void {
    const namespace = "Argus";

    // 1. SimHash Latency High - P99 > 100ms over 5 min
    // Indicates DynamoDB band query performance issues
    const latencyAlarm = new cloudwatch.Alarm(this, "SimHashLatencyHigh", {
      alarmName: `${stackName}-simhash-latency-high`,
      alarmDescription:
        "SimHash P99 latency > 100ms - check DynamoDB throttling or band distribution",
      metric: new cloudwatch.Metric({
        namespace,
        metricName: "SimHash.BandQueryLatencyMs",
        statistic: "p99",
        period: Duration.minutes(5),
      }),
      threshold: 100,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    latencyAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // 2. Candidate Explosion - Avg > 50 candidates over 5 min
    // Indicates hot bands or need to add more bands
    const candidateAlarm = new cloudwatch.Alarm(
      this,
      "SimHashCandidateExplosion",
      {
        alarmName: `${stackName}-simhash-candidate-explosion`,
        alarmDescription:
          "SimHash avg candidates > 50 - consider adding bands or tightening thresholds",
        metric: new cloudwatch.Metric({
          namespace,
          metricName: "SimHash.CandidatesPerQuery",
          statistic: "Average",
          period: Duration.minutes(5),
        }),
        threshold: 50,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      },
    );
    candidateAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // 3. Bypass Rate High - > 5% of requests bypassed over 15 min
    // Indicates consistent latency issues causing automatic bypass
    // Use math expression: bypass / (bypass + hits) > 0.05
    const bypassAlarm = new cloudwatch.Alarm(this, "SimHashBypassRateHigh", {
      alarmName: `${stackName}-simhash-bypass-rate-high`,
      alarmDescription:
        "SimHash bypass rate > 5% - tier is slow and failing open too often",
      metric: new cloudwatch.Metric({
        namespace,
        metricName: "SimHash.LatencyBypass",
        statistic: "Sum",
        period: Duration.minutes(15),
      }),
      // Alert if more than 50 bypasses in 15 minutes
      // (more pragmatic than percentage for initial deployment)
      threshold: 50,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    bypassAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // 4. SimHash Error Rate - any errors indicate bugs
    const errorAlarm = new cloudwatch.Alarm(this, "SimHashError", {
      alarmName: `${stackName}-simhash-error`,
      alarmDescription:
        "SimHash tier throwing errors - failing open but needs investigation",
      metric: new cloudwatch.Metric({
        namespace,
        metricName: "SimHash.Error",
        statistic: "Sum",
        period: Duration.minutes(5),
      }),
      threshold: 0,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    errorAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }
}
