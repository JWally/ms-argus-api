// lib/stacks/app-stack.ts

import * as cdk from "aws-cdk-lib";
import * as sns from "aws-cdk-lib/aws-sns";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as ssm from "aws-cdk-lib/aws-ssm";
import { Construct } from "constructs";

import { SecretConstruct } from "../constructs/secrets";
import { QueuesConstruct } from "../constructs/queues";
import { DynamoDbConstruct } from "../constructs/dynamodb";
import { HttpApiConstruct } from "../constructs/http-api";
import { WorkersConstruct } from "../constructs/workers";
import { CloudFrontWafConstruct } from "../constructs/cloudfront";
import { AnalyticsConstruct } from "../constructs/analytics";
import { VectorWorkerConstruct } from "../constructs/vector-worker";
import { getStageConfig } from "../config";

interface ArgusApiStackProps extends cdk.StackProps {
  environment: string;
  stackName: string;
  rootDomain: string;
  stage: string;
  region: string;
  account: string;
  /**
   * Optional: Name of the ms-argus-vector environment to connect to.
   * If provided, deploys a vector worker Lambda in the vector VPC.
   * Typically matches the stage (e.g., 'dev', 'prod').
   */
  vectorEnvironment?: string;
  /**
   * Optional: Secrets Manager ARN for the AES-256 key used to decrypt encrypted
   * probe responses from ms-argus-sigint. Managed in ms-argus-platform.
   * The key is injected via CloudFormation dynamic reference — never in the template.
   * Prefer sigintPlatformEnvironment for automatic SSM lookup.
   */
  sigintAesKeySecretArn?: string;
  /**
   * ms-argus-platform environment name (e.g. "dev-jw") to auto-lookup the
   * sigint AES key ARN from SSM at synth time (cached in cdk.context.json).
   * Takes precedence over sigintAesKeySecretArn.
   * SSM path: /argus-platform/{sigintPlatformEnvironment}/sigint-aes-key-arn
   */
  sigintPlatformEnvironment?: string;
}

/**
 * Argus API Stack - V5 Architecture
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
function resolveSigintParams(
  scope: cdk.Stack,
  sigintPlatformEnvironment: string | undefined,
  sigintAesKeySecretArn: string | undefined,
): {
  sigintSecretArn: string | undefined;
  probeTokensTableName: string | undefined;
  probeTokensTableArn: string | undefined;
} {
  if (!sigintPlatformEnvironment) {
    return {
      sigintSecretArn: sigintAesKeySecretArn,
      probeTokensTableName: undefined,
      probeTokensTableArn: undefined,
    };
  }
  const base = `/argus-platform/${sigintPlatformEnvironment}`;
  return {
    sigintSecretArn: ssm.StringParameter.valueFromLookup(
      scope,
      `${base}/sigint-aes-key-arn`,
    ),
    probeTokensTableName: ssm.StringParameter.valueFromLookup(
      scope,
      `${base}/probe-tokens-table-name`,
    ),
    probeTokensTableArn: ssm.StringParameter.valueFromLookup(
      scope,
      `${base}/probe-tokens-table-arn`,
    ),
  };
}

export class ArgusApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ArgusApiStackProps) {
    super(scope, id, props);
    const {
      environment,
      stackName,
      rootDomain,
      stage,
      region,
      vectorEnvironment,
      sigintAesKeySecretArn,
      sigintPlatformEnvironment,
    } = props;

    const {
      sigintSecretArn: resolvedSigintSecretArn,
      probeTokensTableName,
      probeTokensTableArn,
    } = resolveSigintParams(
      this,
      sigintPlatformEnvironment,
      sigintAesKeySecretArn,
    );

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

    const _secrets = new SecretConstruct(this, "Secrets", {
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

    // =========================================================================

    const analytics = new AnalyticsConstruct(this, "Analytics", {
      stackName,
      stage,
    });

    // =========================================================================
    // VECTOR WORKER (Optional - for QDrant integration)
    // =========================================================================
    // Only deploy if vectorEnvironment is specified
    // Runs in ms-argus-vector VPC to access internal ALB
    // Created before WorkersConstruct so we can pass the vector queue

    let vectorWorker: VectorWorkerConstruct | undefined;
    if (vectorEnvironment) {
      vectorWorker = new VectorWorkerConstruct(this, "VectorWorker", {
        stackName,
        stage,
        alarmsTopic,
        vectorEnvironment,
        // Pass vector results queue for publishing search results
        vectorResultsQueue: queues.vectorResultsQueue,
      });
    }

    const deliveryStreamName = analytics.deliveryStream
      .deliveryStreamName as string;

    // =========================================================================
    // COMPUTE LAYER
    // =========================================================================

    const stageConfig = getStageConfig(stage);

    // HTTP API + Lambda for ingestion (replaces ALB + ECS)

    const httpApi = new HttpApiConstruct(this, "HttpApi", {
      stackName,
      stage,
      matchingQueue: queues.matchingQueue,
      sessionCacheTable: dynamodb.sessionCacheTable,
      sessionPayloadTable: dynamodb.sessionPayloadTable, // AR-XXX: Full payload for gRPC stub
      vectorResultsTable: dynamodb.vectorResultsTable, // Vector search results
      integrityResultsTable: dynamodb.integrityResultsTable,
      probeTokensTableName,
      probeTokensTableArn,
      sigintAesKeySecretArn: resolvedSigintSecretArn,
      alarmsTopic,
      config: stageConfig,
      ecdhKeyParamName: `/${stackName}/ecdh-keypair`,
      signalBaselinesTable: dynamodb.signalBaselinesTable,
    });

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
      sessionPayloadTable: dynamodb.sessionPayloadTable, // AR-XXX: Full payload for gRPC stub
      vectorResultsTable: dynamodb.vectorResultsTable, // Vector search results
      observationsDeliveryStreamName: deliveryStreamName,
      // Vector queue for Qdrant embeddings (enabled)
      vectorQueue: vectorWorker?.vectorQueue,
      // Vector results queue for search result writes
      vectorResultsQueue: queues.vectorResultsQueue,
      // Vector worker ARN for Tier 2 vector search (replaces compound buckets)
      vectorWorkerArn: vectorWorker?.vectorWorker.functionArn,
      vectorCollection: "fingerprints",

      payloadArchiveBucket: analytics.payloadArchiveBucket,
      integrityArchiveBucket: analytics.integrityArchiveBucket,
      integrityResultsTable: dynamodb.integrityResultsTable,
      sigintAesKeySecretArn: resolvedSigintSecretArn,
      probeTokensTableName,
      probeTokensTableArn,
      signalBaselinesTable: dynamodb.signalBaselinesTable,
    });

    // =========================================================================

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
    // Direct Lambda warmers for the integrity path.
    //
    // Each fires EventBridge → Lambda with `{ warmup: true, source: "warmup-rule" }`.
    // Handlers use @middy/warmup with `isWarmingUp` from helpers/middy-helpers,
    // which short-circuits before the real handler runs.
    //
    // Unlike MatchingWarmupRule (above) which warms matching-worker via SQS,
    // these fire the Lambda directly because ingestion/session-get are API
    // handlers, not SQS consumers.
    // =========================================================================

    const warmupPayload = events.RuleTargetInput.fromObject({
      warmup: true,
      source: "warmup-rule",
      timestamp: events.EventField.time,
    });

    new events.Rule(this, "IngestionWarmupRule", {
      ruleName: `${stackName}-ingestion-warmup`,
      description: "Keep integrity ingestion Lambda warm",
      schedule: events.Schedule.rate(cdk.Duration.minutes(1)),
      targets: [
        new targets.LambdaFunction(httpApi.ingestionFunction, {
          event: warmupPayload,
        }),
      ],
    });

    new events.Rule(this, "SessionGetWarmupRule", {
      ruleName: `${stackName}-session-get-warmup`,
      description: "Keep session-get Lambda warm",
      schedule: events.Schedule.rate(cdk.Duration.minutes(1)),
      targets: [
        new targets.LambdaFunction(httpApi.sessionGetFunction, {
          event: warmupPayload,
        }),
      ],
    });

    if (workers.integrityArchiver) {
      new events.Rule(this, "IntegrityArchiverWarmupRule", {
        ruleName: `${stackName}-integrity-archiver-warmup`,
        description: "Keep integrity-archiver Lambda warm",
        schedule: events.Schedule.rate(cdk.Duration.minutes(1)),
        targets: [
          new targets.LambdaFunction(workers.integrityArchiver, {
            event: warmupPayload,
          }),
        ],
      });
    }

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

    new cdk.CfnOutput(this, "VectorResultsTableName", {
      value: dynamodb.vectorResultsTable.tableName,
      description: "DynamoDB vector results table name",
    });

    new cdk.CfnOutput(this, "VectorResultsQueueUrl", {
      value: queues.vectorResultsQueue.queueUrl,
      description: "SQS URL for vector results queue",
    });

    new cdk.CfnOutput(this, "MatchingWorkerArn", {
      value: workers.matchingWorker.functionArn,
      description: "Matching worker Lambda ARN",
    });

    new cdk.CfnOutput(this, "ProfileUpdaterArn", {
      value: workers.profileUpdater.functionArn,
      description: "Profile updater Lambda ARN",
    });

    // Vector results writer Lambda output (if enabled)
    if (workers.vectorResultsWriter) {
      new cdk.CfnOutput(this, "VectorResultsWriterArn", {
        value: workers.vectorResultsWriter.functionArn,
        description: "Vector results writer Lambda ARN",
      });
    }

    new cdk.CfnOutput(this, "ObservationsBucketName", {
      value: analytics.observationsBucket.bucketName,
      description: "S3 bucket for match observations",
    });

    new cdk.CfnOutput(this, "ObservationsDeliveryStreamName", {
      value: deliveryStreamName,
      description: "Firehose delivery stream for observations",
    });

    new cdk.CfnOutput(this, "PayloadArchiveBucketName", {
      value: analytics.payloadArchiveBucket.bucketName,
      description: "S3 bucket for payload archives",
    });

    new cdk.CfnOutput(this, "IntegrityArchiveBucketName", {
      value: analytics.integrityArchiveBucket.bucketName,
      description: "S3 bucket for integrity result archives",
    });

    // Vector worker outputs (conditional)
    if (vectorWorker) {
      new cdk.CfnOutput(this, "VectorWorkerArn", {
        value: vectorWorker.vectorWorker.functionArn,
        description: "Vector worker Lambda ARN",
      });

      new cdk.CfnOutput(this, "VectorQueueUrl", {
        value: vectorWorker.vectorQueue.queueUrl,
        description: "SQS URL for vector operations queue",
      });

      new cdk.CfnOutput(this, "VectorQueueArn", {
        value: vectorWorker.vectorQueue.queueArn,
        description: "SQS ARN for vector operations queue",
        exportName: `${stackName}-vector-queue-arn`,
      });

      // Vector test API outputs (experimental)
      if (vectorWorker.vectorTestApi) {
        new cdk.CfnOutput(this, "VectorTestApiEndpoint", {
          value: vectorWorker.vectorTestApi.apiEndpoint,
          description: "Vector test API endpoint (experimental)",
        });
      }

      if (vectorWorker.vectorTestFunction) {
        new cdk.CfnOutput(this, "VectorTestFunctionArn", {
          value: vectorWorker.vectorTestFunction.functionArn,
          description: "Vector test Lambda ARN",
        });
      }
    }
  }
}
