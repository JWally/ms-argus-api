// lib/constructs/workers.ts
// AR-44: Uses centralized stage config for environment-specific values
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
import * as ec2 from "aws-cdk-lib/aws-ec2";
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
  redisEndpoint: string;
  redisPort: number;
  redisSecurityGroup: ec2.ISecurityGroup;
  vpc: ec2.IVpc;
}

/**
 * Worker Lambdas for Argus async processing
 * - Matching Worker: SQS -> tiered matching -> Redis
 * - Profile Updater: SQS -> mutation gate -> DynamoDB/Qdrant
 */
export class WorkersConstruct extends Construct {
  public readonly matchingWorker: lambda.NodejsFunction;
  public readonly profileUpdater: lambda.NodejsFunction;
  public readonly matchingWorkerAlias: Alias;
  public readonly profileUpdaterAlias: Alias;
  public readonly workerSecurityGroup: ec2.SecurityGroup;

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
      redisEndpoint,
      redisPort,
      redisSecurityGroup,
      vpc,
    } = props;

    // Security group for Lambda functions (to access Redis in VPC)
    this.workerSecurityGroup = new ec2.SecurityGroup(
      this,
      "WorkerSecurityGroup",
      {
        vpc,
        description: "Security group for Argus worker Lambdas",
        allowAllOutbound: true,
      },
    );

    // Allow workers to access Redis
    redisSecurityGroup.addIngressRule(
      this.workerSecurityGroup,
      ec2.Port.tcp(redisPort),
      "Allow Lambda workers to access Redis",
    );

    // Secrets Manager reference
    const secret = secretsmanager.Secret.fromSecretNameV2(
      this,
      `WorkerSecret`,
      `${stage}/${projectName}`,
    );

    // Common Lambda configuration
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
        // Include ioredis for Redis connectivity
        nodeModules: ["ioredis"],
        // Bundle all dependencies - don't rely on Lambda runtime SDK
        // This ensures version consistency
      },
      // Tracing disabled temporarily due to @smithy bundling issues with Powertools Tracer
      tracing: Tracing.DISABLED,
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [this.workerSecurityGroup],
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
    // AR-44: Use centralized stage config for all tunable values
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
        REDIS_ENDPOINT: redisEndpoint,
        REDIS_PORT: String(redisPort),
        PROFILES_TABLE: profilesTable.tableName,
        TIER1_INDEX_TABLE: tier1IndexTable.tableName,
        TIER2_BUCKETS_TABLE: tier2BucketsTable.tableName,
        PROFILE_QUEUE_URL: profileQueue.queueUrl,
      },
    });

    // SQS event source for matching worker
    // AR-42/AR-44: Batching window from stage config
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
    profileQueue.grantSendMessages(this.matchingWorker);
    matchingQueue.grantConsumeMessages(this.matchingWorker);

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
        REDIS_ENDPOINT: redisEndpoint,
        REDIS_PORT: String(redisPort),
        PROFILES_TABLE: profilesTable.tableName,
        TIER1_INDEX_TABLE: tier1IndexTable.tableName,
        TIER2_BUCKETS_TABLE: tier2BucketsTable.tableName,
        // QDRANT_ENDPOINT: will be added when Qdrant stack is deployed
      },
    });

    // SQS event source for profile updater
    // AR-42/AR-44: Batching window from stage config
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
    profileQueue.grantConsumeMessages(this.profileUpdater);

    // Alarms - AR-44: Use stage config for thresholds
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
    // Create aliases for blue/green deployments
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
    // Error count alarm - AR-44: threshold from config
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

    // Throttle alarm - AR-44: threshold from config
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

    // High duration alarm (p95) - AR-44: threshold from config
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

    // Concurrent executions alarm - AR-44: percentage from config
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

    // Return alarms needed for deployment groups
    return { errorAlarm, durationAlarm };
  }
}
