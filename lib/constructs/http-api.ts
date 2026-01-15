// lib/constructs/http-api.ts
// AR-52: HTTP API Gateway + Lambda for fingerprint ingestion
// AR-67: Added session retrieval endpoint
// Replaces ALB + ECS Fargate (Go) - ~90% cost reduction

import * as path from "path";
import { Construct } from "constructs";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaNode from "aws-cdk-lib/aws-lambda-nodejs";
import * as apigatewayv2 from "aws-cdk-lib/aws-apigatewayv2";
import * as integrations from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as logs from "aws-cdk-lib/aws-logs";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import { Duration, RemovalPolicy } from "aws-cdk-lib";

interface HttpApiConstructProps {
  stackName: string;
  stage: string;
  matchingQueue: sqs.IQueue;
  sessionCacheTable: dynamodb.ITable;
  alarmsTopic: sns.ITopic;
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

    const { stackName, stage, matchingQueue, sessionCacheTable, alarmsTopic } =
      props;

    // CloudWatch log group for Lambda
    const logGroup = new logs.LogGroup(this, "IngestionLogGroup", {
      logGroupName: `/aws/lambda/${stackName}-ingestion`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // Lambda function for ingestion
    // AR-71: Reverted to async (SQS) for scalability at 30B RPY
    this.ingestionFunction = new lambdaNode.NodejsFunction(
      this,
      "IngestionFunction",
      {
        functionName: `${stackName}-ingestion`,
        runtime: lambda.Runtime.NODEJS_20_X,
        architecture: lambda.Architecture.ARM_64,
        handler: "handler",
        entry: path.join(__dirname, "../../src/handlers/ingestion.ts"),
        memorySize: 256,
        timeout: Duration.seconds(10),
        logGroup,
        environment: {
          SQS_QUEUE_URL: matchingQueue.queueUrl,
          POWERTOOLS_SERVICE_NAME: "argus-ingestion",
          POWERTOOLS_METRICS_NAMESPACE: `argus-${stage}`,
          NODE_OPTIONS: "--enable-source-maps",
        },
        bundling: {
          minify: true,
          sourceMap: true,
          target: "node20",
          format: lambdaNode.OutputFormat.ESM,
          mainFields: ["module", "main"],
          esbuildArgs: {
            "--tree-shaking": "true",
          },
        },
      },
    );

    // Grant SQS permissions
    matchingQueue.grantSendMessages(this.ingestionFunction);

    // AR-67: Session retrieval Lambda
    const sessionGetLogGroup = new logs.LogGroup(this, "SessionGetLogGroup", {
      logGroupName: `/aws/lambda/${stackName}-session-get`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    this.sessionGetFunction = new lambdaNode.NodejsFunction(
      this,
      "SessionGetFunction",
      {
        functionName: `${stackName}-session-get`,
        runtime: lambda.Runtime.NODEJS_20_X,
        architecture: lambda.Architecture.ARM_64,
        handler: "handler",
        entry: path.join(__dirname, "../../src/handlers/session-get.ts"),
        memorySize: 256,
        timeout: Duration.seconds(10),
        logGroup: sessionGetLogGroup,
        environment: {
          SESSION_CACHE_TABLE: sessionCacheTable.tableName,
          POWERTOOLS_SERVICE_NAME: "argus-session-get",
          POWERTOOLS_METRICS_NAMESPACE: `argus-${stage}`,
          NODE_OPTIONS: "--enable-source-maps",
        },
        bundling: {
          minify: true,
          sourceMap: true,
          target: "node20",
          format: lambdaNode.OutputFormat.ESM,
          mainFields: ["module", "main"],
          esbuildArgs: {
            "--tree-shaking": "true",
          },
        },
      },
    );

    // Grant DynamoDB read permissions
    sessionCacheTable.grantReadData(this.sessionGetFunction);

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
        allowHeaders: [
          "Content-Type",
          "Content-Encoding",
          "X-Tenant-ID",
          "X-API-Key",
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
