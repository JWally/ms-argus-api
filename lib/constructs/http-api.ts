// lib/constructs/http-api.ts
// AR-52: HTTP API Gateway + Lambda for fingerprint ingestion
// AR-67: Added session retrieval endpoint
// AR-160: Added configurable Lambda memory settings
// Replaces ALB + ECS Fargate (Go) - ~90% cost reduction

import * as path from "path";
import { Construct } from "constructs";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaNode from "aws-cdk-lib/aws-lambda-nodejs";
import * as apigatewayv2 from "aws-cdk-lib/aws-apigatewayv2";
import * as integrations from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as logs from "aws-cdk-lib/aws-logs";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import { Duration, RemovalPolicy } from "aws-cdk-lib";
import { StageConfig } from "../config/stage-config";
import { createBaseLambdaConfig, createPowertoolsEnv } from "./lambda-config";

interface HttpApiConstructProps {
  stackName: string;
  stage: string;
  matchingQueue: sqs.IQueue;
  sessionCacheTable: dynamodb.ITable;
  /** AR-XXX: Full payload table for gRPC stub */
  sessionPayloadTable: dynamodb.ITable;
  alarmsTopic: sns.ITopic;
  /** AR-139: S3 bucket for payload archiving */
  payloadArchiveBucket: s3.IBucket;
  /** AR-160: Stage-specific configuration for Lambda memory tuning */
  config: StageConfig;
}

/**
 * HTTP API Gateway + Lambda for fingerprint ingestion
 *
 * Why HTTP API instead of REST API:
 * - $1/million vs $3.50/million requests (70% cheaper)
 * - Lower latency (no additional validation overhead)
 * - Native Lambda integration
 *
 * Why Lambda instead of Go/ECS:
 * - Zero idle cost (pay per invocation)
 * - No ALB (~$16/month), no Fargate (~$10-25/month)
 * - Simpler infrastructure (no VPC for ingestion)
 * - TypeScript consistency with rest of codebase
 */
export class HttpApiConstruct extends Construct {
  public readonly api: apigatewayv2.HttpApi;
  public readonly ingestionFunction: lambda.Function;
  public readonly sessionGetFunction: lambda.Function;
  public readonly apiEndpoint: string;

  constructor(scope: Construct, id: string, props: HttpApiConstructProps) {
    super(scope, id);

    const {
      stackName,
      stage,
      matchingQueue,
      sessionCacheTable,
      sessionPayloadTable,
      alarmsTopic,
      payloadArchiveBucket,
      config,
    } = props;

    // CloudWatch log group for Lambda
    const logGroup = new logs.LogGroup(this, "IngestionLogGroup", {
      logGroupName: `/aws/lambda/${stackName}-ingestion`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // Lambda function for ingestion
    // AR-71: Reverted to async (SQS) for scalability at 30B RPY
    // AR-167: Use shared Lambda configuration
    this.ingestionFunction = new lambdaNode.NodejsFunction(
      this,
      "IngestionFunction",
      {
        ...createBaseLambdaConfig(),
        functionName: `${stackName}-ingestion`,
        handler: "handler",
        entry: path.join(__dirname, "../../src/handlers/ingestion.ts"),
        // AR-160: Use configurable memory from stage config
        memorySize: config.lambda.ingestion.memorySize,
        timeout: Duration.seconds(10),
        logGroup,
        environment: {
          ...createPowertoolsEnv("argus-ingestion", `argus-${stage}`),
          SQS_QUEUE_URL: matchingQueue.queueUrl,
          // AR-139: Payload archiving configuration
          PAYLOAD_ARCHIVE_BUCKET: payloadArchiveBucket.bucketName,
          PAYLOAD_ARCHIVE_SAMPLE_RATE: stage.startsWith("dev") ? "1.0" : "0",
        },
      },
    );

    // Grant SQS permissions
    matchingQueue.grantSendMessages(this.ingestionFunction);

    // AR-139: Grant Lambda permission to write to payload archive bucket
    payloadArchiveBucket.grantWrite(this.ingestionFunction);

    // AR-67: Session retrieval Lambda
    const sessionGetLogGroup = new logs.LogGroup(this, "SessionGetLogGroup", {
      logGroupName: `/aws/lambda/${stackName}-session-get`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // AR-167: Use shared Lambda configuration
    this.sessionGetFunction = new lambdaNode.NodejsFunction(
      this,
      "SessionGetFunction",
      {
        ...createBaseLambdaConfig(),
        functionName: `${stackName}-session-get`,
        handler: "handler",
        entry: path.join(__dirname, "../../src/handlers/session-get.ts"),
        // AR-160: Use configurable memory from stage config
        memorySize: config.lambda.sessionGet.memorySize,
        timeout: Duration.seconds(10),
        logGroup: sessionGetLogGroup,
        environment: {
          ...createPowertoolsEnv("argus-session-get", `argus-${stage}`),
          SESSION_CACHE_TABLE: sessionCacheTable.tableName,
          // AR-XXX: Full payload table for gRPC stub
          SESSION_PAYLOAD_TABLE: sessionPayloadTable.tableName,
        },
      },
    );

    // Grant DynamoDB read permissions
    sessionCacheTable.grantReadData(this.sessionGetFunction);
    sessionPayloadTable.grantReadData(this.sessionGetFunction);

    // HTTP API Gateway
    this.api = new apigatewayv2.HttpApi(this, "HttpApi", {
      apiName: `${stackName}-api`,
      description: "Argus fingerprint ingestion API",
      corsPreflight: {
        allowOrigins: ["*"], // CloudFront handles real CORS
        allowMethods: [
          apigatewayv2.CorsHttpMethod.GET,
          apigatewayv2.CorsHttpMethod.POST,
          apigatewayv2.CorsHttpMethod.OPTIONS,
        ],
        // AR-91: Added Content-Encoding for binary gzip payloads
        // AR-188: Added X-Argus-Schema-Version for v2 payload versioning
        allowHeaders: [
          "Content-Type",
          "Content-Encoding",
          "X-Argus-Schema-Version",
        ],
        maxAge: Duration.hours(24),
      },
    });

    // Lambda integration
    const lambdaIntegration = new integrations.HttpLambdaIntegration(
      "IngestionIntegration",
      this.ingestionFunction,
    );

    // Routes
    this.api.addRoutes({
      path: "/v1/collect",
      methods: [apigatewayv2.HttpMethod.POST],
      integration: lambdaIntegration,
    });

    this.api.addRoutes({
      path: "/health",
      methods: [apigatewayv2.HttpMethod.GET],
      integration: lambdaIntegration,
    });

    // AR-67: Session retrieval route
    const sessionGetIntegration = new integrations.HttpLambdaIntegration(
      "SessionGetIntegration",
      this.sessionGetFunction,
    );

    this.api.addRoutes({
      path: "/v1/session/{session_id}",
      methods: [apigatewayv2.HttpMethod.GET],
      integration: sessionGetIntegration,
    });

    // Store endpoint URL (without trailing slash)
    this.apiEndpoint = this.api.apiEndpoint;

    // Alarms
    this.createAlarms(stackName, alarmsTopic);
  }

  private createAlarms(stackName: string, alarmsTopic: sns.ITopic): void {
    // Lambda errors alarm
    const errorsAlarm = new cloudwatch.Alarm(this, "IngestionErrorsAlarm", {
      metric: this.ingestionFunction.metricErrors({
        period: Duration.minutes(5),
        statistic: "Sum",
      }),
      threshold: 10,
      evaluationPeriods: 2,
      alarmDescription: `${stackName} ingestion Lambda errors > 10 in 5 min`,
    });
    errorsAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Lambda duration alarm (p99)
    const durationAlarm = new cloudwatch.Alarm(this, "IngestionDurationAlarm", {
      metric: this.ingestionFunction.metricDuration({
        period: Duration.minutes(5),
        statistic: "p99",
      }),
      threshold: 5000, // 5 seconds
      evaluationPeriods: 3,
      alarmDescription: `${stackName} ingestion Lambda p99 duration > 5s`,
    });
    durationAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Lambda throttles alarm
    const throttlesAlarm = new cloudwatch.Alarm(
      this,
      "IngestionThrottlesAlarm",
      {
        metric: this.ingestionFunction.metricThrottles({
          period: Duration.minutes(5),
          statistic: "Sum",
        }),
        threshold: 5,
        evaluationPeriods: 2,
        alarmDescription: `${stackName} ingestion Lambda throttled > 5 times`,
      },
    );
    throttlesAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }
}
