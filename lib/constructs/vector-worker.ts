// lib/constructs/vector-worker.ts
// Vector worker Lambda for QDrant integration
// Deploys in ms-argus-vector VPC to access internal ALB
import * as path from "path";
import { Construct } from "constructs";
import * as lambda from "aws-cdk-lib/aws-lambda-nodejs";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as iam from "aws-cdk-lib/aws-iam";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import { Duration, Fn } from "aws-cdk-lib";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import { getStageConfig, StageConfig } from "../config";
import { createBaseLambdaConfig, createWorkerEnv } from "./lambda-config";

interface VectorWorkerConstructProps {
  stackName: string;
  stage: string;
  alarmsTopic: sns.ITopic;
  /**
   * Name of the ms-argus-vector environment to connect to
   * Used to import VPC, ALB DNS, and secret ARN via CloudFormation exports
   * Typically matches the stage (e.g., 'dev', 'prod')
   */
  vectorEnvironment: string;
}

/**
 * Vector Worker Lambda for QDrant integration
 *
 * This Lambda runs in the ms-argus-vector VPC to access the internal ALB.
 * It processes vector operations (search, upsert) from an SQS queue.
 *
 * Cross-stack dependencies:
 * - VPC ID from: argus-vector-{env}-vpc-id
 * - ALB DNS from: argus-vector-{env}-alb-dns
 * - Secret ARN from: argus-vector-{env}-api-secret-arn
 */
export class VectorWorkerConstruct extends Construct {
  public readonly vectorWorker: lambda.NodejsFunction;
  public readonly vectorQueue: sqs.Queue;
  public readonly vectorDlq: sqs.Queue;

  constructor(scope: Construct, id: string, props: VectorWorkerConstructProps) {
    super(scope, id);

    const { stackName, stage, alarmsTopic, vectorEnvironment } = props;
    const config = getStageConfig(stage);

    // =========================================================================
    // CROSS-STACK IMPORTS FROM MS-ARGUS-VECTOR
    // =========================================================================

    // Import VPC from ms-argus-vector stack
    // Note: We use fromLookup with the exported VPC ID
    // Kept for reference - actual lookup uses tags below
    const _vectorVpcId = Fn.importValue(
      `argus-vector-${vectorEnvironment}-vpc-id`,
    );

    // For VPC lookup, we need to use a different approach since Fn.importValue
    // returns a token that can't be used directly with fromLookup
    // Instead, we'll use fromVpcAttributes with the imported values
    const vectorVpc = ec2.Vpc.fromLookup(this, "VectorVpc", {
      // In practice, you may need to hardcode this or use a context variable
      // because Fn.importValue tokens can't be used with fromLookup
      tags: {
        Service: "argus-vector",
        Environment: vectorEnvironment,
      },
    });

    // Import QDrant endpoint and secret ARN
    const qdrantRestEndpoint = Fn.importValue(
      `argus-vector-${vectorEnvironment}-rest-endpoint`,
    );
    const qdrantSecretArn = Fn.importValue(
      `argus-vector-${vectorEnvironment}-api-secret-arn`,
    );

    // Import the QDrant API secret for granting read access
    const qdrantSecret = secretsmanager.Secret.fromSecretCompleteArn(
      this,
      "QdrantSecret",
      qdrantSecretArn,
    );

    // =========================================================================
    // SQS QUEUES
    // =========================================================================

    // Dead letter queue for failed vector operations
    this.vectorDlq = new sqs.Queue(this, "VectorDLQ", {
      queueName: `${stackName}-vector-dlq`,
      retentionPeriod: Duration.days(14),
      encryption: sqs.QueueEncryption.SQS_MANAGED,
    });

    // Main vector operations queue
    this.vectorQueue = new sqs.Queue(this, "VectorQueue", {
      queueName: `${stackName}-vector-queue`,
      visibilityTimeout: Duration.seconds(60), // Must be > Lambda timeout
      retentionPeriod: Duration.days(7),
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      deadLetterQueue: {
        queue: this.vectorDlq,
        maxReceiveCount: 3,
      },
    });

    // =========================================================================
    // LAMBDA SECURITY GROUP
    // =========================================================================

    // Create security group for the Lambda in the vector VPC
    const lambdaSecurityGroup = new ec2.SecurityGroup(
      this,
      "VectorWorkerSecurityGroup",
      {
        vpc: vectorVpc,
        securityGroupName: `${stackName}-vector-worker-sg`,
        description: "Security group for vector worker Lambda",
        allowAllOutbound: true, // Lambda needs to reach QDrant ALB and AWS services
      },
    );

    // =========================================================================
    // VECTOR WORKER LAMBDA
    // =========================================================================

    const commonConfig = createBaseLambdaConfig({
      tracing: true,
      keepNames: true,
    });

    this.vectorWorker = new lambda.NodejsFunction(this, "VectorWorker", {
      ...commonConfig,
      entry: path.join(__dirname, "../../src/handlers/vector-worker.ts"),
      functionName: `${stackName}-vector-worker`,
      memorySize: config.lambda.vectorWorker.memorySize,
      timeout: config.lambda.vectorWorker.timeout,
      reservedConcurrentExecutions:
        config.lambda.vectorWorker.reservedConcurrency,
      // VPC configuration - run in ms-argus-vector VPC
      vpc: vectorVpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [lambdaSecurityGroup],
      environment: {
        ...createWorkerEnv(stage, stackName, `${stackName}-vector-worker`),
        QDRANT_URL: qdrantRestEndpoint,
        QDRANT_SECRET_ARN: qdrantSecretArn,
      },
    });

    // SQS event source
    this.vectorWorker.addEventSource(
      new lambdaEventSources.SqsEventSource(this.vectorQueue, {
        batchSize: 10,
        maxBatchingWindow: Duration.seconds(0), // Process immediately
        reportBatchItemFailures: true,
      }),
    );

    // =========================================================================
    // PERMISSIONS
    // =========================================================================

    // IAM Logging Policy
    this.vectorWorker.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ],
        resources: ["*"],
      }),
    );

    // Grant read access to QDrant API secret
    qdrantSecret.grantRead(this.vectorWorker);

    // Grant SQS permissions
    this.vectorQueue.grantConsumeMessages(this.vectorWorker);

    // =========================================================================
    // ALARMS
    // =========================================================================

    this.createAlarms(stackName, alarmsTopic, config);
  }

  private createAlarms(
    stackName: string,
    alarmsTopic: sns.ITopic,
    config: StageConfig,
  ): void {
    // Error alarm
    const errorAlarm = new cloudwatch.Alarm(this, "VectorWorkerErrors", {
      metric: this.vectorWorker.metricErrors({
        period: Duration.minutes(5),
        statistic: "Sum",
      }),
      threshold: config.alarms.lambda.errorThreshold,
      evaluationPeriods: 2,
      alarmDescription: `Vector worker Lambda errors > ${config.alarms.lambda.errorThreshold} in 5 minutes`,
    });
    errorAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Duration alarm (p95)
    const durationAlarm = new cloudwatch.Alarm(
      this,
      "VectorWorkerHighDuration",
      {
        metric: this.vectorWorker.metricDuration({
          period: Duration.minutes(5),
          statistic: "p95",
        }),
        threshold: config.alarms.lambda.durationThresholdMs,
        evaluationPeriods: 3,
        alarmDescription: `Vector worker p95 duration > ${config.alarms.lambda.durationThresholdMs}ms`,
      },
    );
    durationAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // DLQ alarm - any messages in DLQ indicates failures
    const dlqAlarm = new cloudwatch.Alarm(this, "VectorDLQNotEmpty", {
      metric: this.vectorDlq.metricApproximateNumberOfMessagesVisible({
        period: Duration.minutes(5),
        statistic: "Maximum",
      }),
      threshold: 0,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1,
      alarmDescription:
        "Vector worker DLQ has messages - vector operations failing",
    });
    dlqAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Queue backlog alarm
    const backlogAlarm = new cloudwatch.Alarm(this, "VectorQueueBacklog", {
      metric: this.vectorQueue.metricApproximateNumberOfMessagesVisible({
        period: Duration.minutes(5),
        statistic: "Maximum",
      }),
      threshold: config.alarms.queue.backlogThreshold,
      evaluationPeriods: 3,
      alarmDescription: `Vector queue backlog > ${config.alarms.queue.backlogThreshold}`,
    });
    backlogAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }
}
