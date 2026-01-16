// lib/stacks/app-stack.ts
// AR-52: Simplified architecture - removed VPC, ALB, ECS, Redis
// AR-57: Added analytics pipeline for match observations
// AR-71: Added SQS warmup rule to keep matching pipeline warm
import * as cdk from "aws-cdk-lib";
import * as sns from "aws-cdk-lib/aws-sns";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import { Construct } from "constructs";

import { SecretConstruct } from "../constructs/secrets";
import { QueuesConstruct } from "../constructs/queues";
import { DynamoDbConstruct } from "../constructs/dynamodb";
import { HttpApiConstruct } from "../constructs/http-api";
import { WorkersConstruct } from "../constructs/workers";
import { CloudFrontWafConstruct } from "../constructs/cloudfront";
import { AnalyticsConstruct } from "../constructs/analytics";
import { getStageConfig } from "../config";

interface ArgusApiStackProps extends cdk.StackProps {
  environment: string;
  stackName: string;
  rootDomain: string;
  stage: string;
  region: string;
  account: string;
}

/**
 * Argus API Stack - V5 Architecture (AR-52)
 *
 * Simplified serverless architecture:
 * Browser → CloudFront → HTTP API → Lambda (ingestion) → SQS → Lambda (workers) → DynamoDB
 *
 * What changed from V4:
 * - Removed: VPC, NAT Gateway, ALB, ECS Fargate, Redis
 * - Added: HTTP API Gateway, ingestion Lambda
 * - Result: ~$50-70/month savings, simpler infrastructure
 *
 * Why we removed Go/ECS:
 * - Go service was 200 lines doing: validate JSON → write SQS → return 204
 * - Lambda does the same for ~$1/month vs ~$30/month (ALB + Fargate)
 * - HTTP API is $1/million requests (vs REST API $3.50/million)
 * - TypeScript consistency (one language for entire backend)
 * - Easier to test, deploy, and debug
 *
 * Why we removed VPC:
 * - Only needed VPC for Redis (ElastiCache) and ECS
 * - DynamoDB and SQS accessible via IAM (no network path needed)
 * - Removes NAT Gateway (~$32/month) and VPC endpoint costs
 * - Faster Lambda cold starts (no ENI attachment)
 */
export class ArgusApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ArgusApiStackProps) {
    super(scope, id, props);
    const { environment, stackName, rootDomain, stage, region } = props;

    // =========================================================================
    // DNS & CERTIFICATES
    // =========================================================================

    const hostedZone = route53.HostedZone.fromLookup(this, "HostedZone", {
      domainName: rootDomain,
    });

    const apiSubdomain = stage === "prod" ? "api" : `api-${environment}`;
    const apiDomainName = `${apiSubdomain}.${rootDomain}`;

    const certificate = new acm.Certificate(this, "Certificate", {
      domainName: apiDomainName,
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    // =========================================================================
    // SHARED RESOURCES
    // =========================================================================

    const secrets = new SecretConstruct(this, "Secrets", {
      environment,
      stackName,
      stage,
      projectName: id,
    });

    const alarmsTopic = new sns.Topic(this, "AlarmsTopic", {
      displayName: `${stackName}-Alarms`,
      topicName: `${stackName}-AlarmsTopic-${region}`,
    });

    // =========================================================================
    // DATA LAYER
    // =========================================================================

    // AR-133: Pass stage to DynamoDB construct for conditional provisioned capacity
    const dynamodb = new DynamoDbConstruct(this, "DynamoDB", {
      stackName,
      alarmsTopic,
      stage,
    });

    const queues = new QueuesConstruct(this, "Queues", {
      stackName,
      stage,
      alarmsTopic,
    });

    // =========================================================================
    // ANALYTICS LAYER (AR-57)
    // =========================================================================

    const analytics = new AnalyticsConstruct(this, "Analytics", {
      stackName,
      stage,
    });

    // =========================================================================
    // COMPUTE LAYER
    // =========================================================================

    // HTTP API + Lambda for ingestion (replaces ALB + ECS)
    // AR-67: Added session retrieval endpoint
    // AR-71: Reverted to async (SQS) for scalability
    // AR-131: API keys from Secrets Manager
    const httpApi = new HttpApiConstruct(this, "HttpApi", {
      stackName,
      stage,
      matchingQueue: queues.matchingQueue,
      sessionCacheTable: dynamodb.sessionCacheTable,
      alarmsTopic,
      apiKeysSecret: secrets.apiKeysSecret,
    });

    // Worker Lambdas (no VPC - access DynamoDB/SQS via IAM)
    const workers = new WorkersConstruct(this, "Workers", {
      stackName,
      stage,
      projectName: id,
      alarmsTopic,
      matchingQueue: queues.matchingQueue,
      profileQueue: queues.profileQueue,
      profilesTable: dynamodb.profilesTable,
      tier1IndexTable: dynamodb.tier1IndexTable,
      tier2BucketsTable: dynamodb.tier2BucketsTable,
      sessionCacheTable: dynamodb.sessionCacheTable,
      observationsDeliveryStreamName:
        analytics.deliveryStream.deliveryStreamName!, // AR-57
    });

    // =========================================================================
    // AR-71: WARMUP RULE - Keep SQS polling pipeline warm
    // =========================================================================
    // Sends warmup message to matching queue every minute to keep:
    // - SQS pollers active (they process the warmup message)
    // - Lambda execution environment warm (recent invocation)
    // - DynamoDB connections warm
    // This eliminates the ~10 second cold-start latency when scaling from zero

    const warmupRule = new events.Rule(this, "MatchingWarmupRule", {
      ruleName: `${stackName}-matching-warmup`,
      description:
        "Keep matching pipeline warm by sending periodic warmup messages",
      schedule: events.Schedule.rate(cdk.Duration.minutes(1)),
    });

    warmupRule.addTarget(
      new targets.SqsQueue(queues.matchingQueue, {
        message: events.RuleTargetInput.fromObject({
          warmup: true,
          source: "warmup-rule",
          timestamp: events.EventField.time,
        }),
      }),
    );

    // =========================================================================
    // EDGE LAYER
    // =========================================================================

    const config = getStageConfig(stage);
    const cdn = new CloudFrontWafConstruct(this, "CDN", {
      environment,
      stackName,
      httpApiEndpoint: httpApi.apiEndpoint,
      rootDomain,
      apiSubdomain,
      hostedZone,
      certificate,
      stageConfig: config,
    });

    // =========================================================================
    // OUTPUTS
    // =========================================================================

    new cdk.CfnOutput(this, "AlarmsTopicArn", {
      value: alarmsTopic.topicArn,
      description: "ARN of the SNS topic for CloudWatch Alarms",
    });

    new cdk.CfnOutput(this, "ApiEndpoint", {
      value: `https://${apiDomainName}`,
      description: "API endpoint (CloudFront + custom domain)",
    });

    new cdk.CfnOutput(this, "CloudFrontDomain", {
      value: cdn.distribution.distributionDomainName,
      description: "CloudFront distribution domain",
    });

    new cdk.CfnOutput(this, "HttpApiEndpoint", {
      value: httpApi.apiEndpoint,
      description: "HTTP API Gateway endpoint (direct)",
    });

    new cdk.CfnOutput(this, "IngestionFunctionArn", {
      value: httpApi.ingestionFunction.functionArn,
      description: "Ingestion Lambda ARN",
    });

    // AR-67: Session retrieval Lambda output
    new cdk.CfnOutput(this, "SessionGetFunctionArn", {
      value: httpApi.sessionGetFunction.functionArn,
      description: "Session retrieval Lambda ARN",
    });

    new cdk.CfnOutput(this, "MatchingQueueUrl", {
      value: queues.matchingQueue.queueUrl,
      description: "SQS URL for matching queue",
    });

    new cdk.CfnOutput(this, "ProfileQueueUrl", {
      value: queues.profileQueue.queueUrl,
      description: "SQS URL for profile queue",
    });

    new cdk.CfnOutput(this, "ProfilesTableName", {
      value: dynamodb.profilesTable.tableName,
      description: "DynamoDB profiles table name",
    });

    new cdk.CfnOutput(this, "SessionCacheTableName", {
      value: dynamodb.sessionCacheTable.tableName,
      description: "DynamoDB session cache table name",
    });

    new cdk.CfnOutput(this, "MatchingWorkerArn", {
      value: workers.matchingWorker.functionArn,
      description: "Matching worker Lambda ARN",
    });

    new cdk.CfnOutput(this, "ProfileUpdaterArn", {
      value: workers.profileUpdater.functionArn,
      description: "Profile updater Lambda ARN",
    });

    // AR-130: Cardinality recalculation Lambda output
    new cdk.CfnOutput(this, "CardinalityRecalcArn", {
      value: workers.cardinalityRecalc.functionArn,
      description: "Cardinality recalculation Lambda ARN",
    });

    // AR-57: Analytics outputs
    new cdk.CfnOutput(this, "ObservationsBucketName", {
      value: analytics.observationsBucket.bucketName,
      description: "S3 bucket for match observations",
    });

    new cdk.CfnOutput(this, "ObservationsDeliveryStreamName", {
      value: analytics.deliveryStream.deliveryStreamName!,
      description: "Firehose delivery stream for observations",
    });
  }
}
