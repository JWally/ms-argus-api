// lib/constructs/vector-worker.ts
// Vector worker Lambda for QDrant integration
// Deploys in ms-argus-vector VPC to access internal ALB
import * as path from "path";
import { Construct } from "constructs";
import * as lambda from "aws-cdk-lib/aws-lambda-nodejs";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import * as iam from "aws-cdk-lib/aws-iam";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as apigatewayv2 from "aws-cdk-lib/aws-apigatewayv2";
import * as integrations from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as logs from "aws-cdk-lib/aws-logs";
import { Duration, RemovalPolicy } from "aws-cdk-lib";
import * as ssm from "aws-cdk-lib/aws-ssm";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import { getStageConfig, StageConfig } from "../config";
import { createVectorLambdaConfig, createWorkerEnv } from "./lambda-config";

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
  /** Optional: SQS queue for vector results. When provided, publishes search results. */
  vectorResultsQueue?: sqs.IQueue;
}

/**
 * Vector Worker Lambda for QDrant integration
 *
 * This Lambda runs in the shared VPC (from ms-argus-infra) to access the
 * QDrant service internal ALB (deployed by ms-argus-vector).
 * It processes vector operations (search, upsert) from an SQS queue.
 *
 * Cross-stack dependencies (via SSM Parameter Store):
 * - VPC ID from ms-argus-infra: /argus/{env}/vpc-id
 * - Qdrant URL from ms-argus-vector: /argus-vector/{env}/qdrant-url
 * - Secret ARN from ms-argus-vector: /argus-vector/{env}/qdrant-secret-arn
 */
export class VectorWorkerConstruct extends Construct {
  public readonly vectorWorker: lambda.NodejsFunction;
  public readonly vectorQueue: sqs.Queue;
  public readonly vectorDlq: sqs.Queue;
  /** Test endpoint for direct vector operations (experimental) */
  public readonly vectorTestFunction?: lambda.NodejsFunction;
  /** HTTP API for vector test endpoint */
  public readonly vectorTestApi?: apigatewayv2.HttpApi;

  constructor(scope: Construct, id: string, props: VectorWorkerConstructProps) {
    super(scope, id);

    const {
      stackName,
      stage,
      alarmsTopic,
      vectorEnvironment,
      vectorResultsQueue,
    } = props;
    const config = getStageConfig(stage);

    // =========================================================================
    // CROSS-STACK IMPORTS (via SSM Parameter Store)
    // =========================================================================

    // VPC comes from ms-argus-infra (shared VPC)
    const infraSsmPrefix = `/argus/${vectorEnvironment}`;

    // Use valueFromLookup for synth-time resolution (needed for VPC lookup)
    const vectorVpcId = ssm.StringParameter.valueFromLookup(
      this,
      `${infraSsmPrefix}/vpc-id`,
    );

    // Import VPC using the ID from SSM
    // Note: valueFromLookup returns a token during initial synth, then actual value
    const vectorVpc = ec2.Vpc.fromLookup(this, "VectorVpc", {
      vpcId: vectorVpcId,
    });

    // QDrant connection info comes from ms-argus-vector
    const vectorSsmPrefix = `/argus-vector/${vectorEnvironment}`;

    // Read Qdrant URL and secret ARN from SSM
    // Use valueForStringParameter for deploy-time resolution (works with tokens)
    const qdrantRestEndpoint = ssm.StringParameter.valueForStringParameter(
      this,
      `${vectorSsmPrefix}/qdrant-url`,
    );
    const qdrantSecretArn = ssm.StringParameter.valueForStringParameter(
      this,
      `${vectorSsmPrefix}/qdrant-secret-arn`,
    );

    // Create IAM policy for Qdrant secret access
    // We use an explicit policy statement since the secret ARN is a token from SSM
    const qdrantSecretPolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ["secretsmanager:GetSecretValue"],
      // Allow access to secrets matching the pattern (covers the random suffix)
      resources: [`arn:aws:secretsmanager:*:*:secret:argus-vector/*`],
    });

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

    // Use CJS format for Qdrant client compatibility
    const commonConfig = createVectorLambdaConfig({
      tracing: config.lambda.tracingEnabled,
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
        // Vector results queue for publishing search results
        ...(vectorResultsQueue && {
          VECTOR_RESULTS_QUEUE_URL: vectorResultsQueue.queueUrl,
        }),
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
    this.vectorWorker.addToRolePolicy(qdrantSecretPolicy);

    // Grant SQS permissions
    this.vectorQueue.grantConsumeMessages(this.vectorWorker);

    // Grant permission to send to vector results queue (for publishing search results)
    if (vectorResultsQueue) {
      vectorResultsQueue.grantSendMessages(this.vectorWorker);
    }

    // =========================================================================
    // VECTOR TEST ENDPOINT (Experimental)
    // Direct HTTP access to Qdrant for testing and experimentation
    // =========================================================================

    const testLogGroup = new logs.LogGroup(this, "VectorTestLogGroup", {
      logGroupName: `/aws/lambda/${stackName}-vector-test`,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    this.vectorTestFunction = new lambda.NodejsFunction(this, "VectorTestFn", {
      ...commonConfig,
      entry: path.join(__dirname, "../../src/handlers/vector-test.ts"),
      functionName: `${stackName}-vector-test`,
      memorySize: config.lambda.vectorWorker.memorySize,
      timeout: Duration.seconds(30),
      logGroup: testLogGroup,
      // VPC configuration - run in ms-argus-vector VPC
      vpc: vectorVpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [lambdaSecurityGroup],
      environment: {
        ...createWorkerEnv(stage, stackName, `${stackName}-vector-test`),
        QDRANT_URL: qdrantRestEndpoint,
        QDRANT_SECRET_ARN: qdrantSecretArn,
      },
    });

    // Grant read access to QDrant API secret
    this.vectorTestFunction.addToRolePolicy(qdrantSecretPolicy);

    // Grant logging permissions
    this.vectorTestFunction.addToRolePolicy(
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

    // HTTP API Gateway for vector test endpoint
    this.vectorTestApi = new apigatewayv2.HttpApi(this, "VectorTestApi", {
      apiName: `${stackName}-vector-test-api`,
      description: "Experimental vector test API for Qdrant operations",
      corsPreflight: {
        allowOrigins: ["*"],
        allowMethods: [
          apigatewayv2.CorsHttpMethod.GET,
          apigatewayv2.CorsHttpMethod.POST,
          apigatewayv2.CorsHttpMethod.OPTIONS,
        ],
        allowHeaders: ["Content-Type"],
        maxAge: Duration.hours(1),
      },
    });

    const testIntegration = new integrations.HttpLambdaIntegration(
      "VectorTestIntegration",
      this.vectorTestFunction,
    );

    // Routes for vector test operations
    this.vectorTestApi.addRoutes({
      path: "/v1/vector/health",
      methods: [apigatewayv2.HttpMethod.GET],
      integration: testIntegration,
    });

    this.vectorTestApi.addRoutes({
      path: "/v1/vector/search",
      methods: [apigatewayv2.HttpMethod.POST],
      integration: testIntegration,
    });

    this.vectorTestApi.addRoutes({
      path: "/v1/vector/upsert",
      methods: [apigatewayv2.HttpMethod.POST],
      integration: testIntegration,
    });

    this.vectorTestApi.addRoutes({
      path: "/v1/vector/collection",
      methods: [apigatewayv2.HttpMethod.POST],
      integration: testIntegration,
    });

    // =========================================================================
    // ALARMS
    // =========================================================================

    if (config.alarms.enabled) {
      this.createAlarms(stackName, alarmsTopic, config);
    }
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
