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
import { DynamoDbConstruct } from "../constructs/dynamodb";
import { HttpApiConstruct } from "../constructs/http-api";
import { IpClassBuilderConstruct } from "../constructs/ip-class-builder";
import { IpClassDiscovererConstruct } from "../constructs/ip-class-discoverer";
import { WorkersConstruct } from "../constructs/workers";
import { CloudFrontWafConstruct } from "../constructs/cloudfront";
import { AnalyticsConstruct } from "../constructs/analytics";
import { IntegrityFirehoseConstruct } from "../constructs/integrity-firehose";
import { getStageConfig } from "../config";

interface ArgusApiStackProps extends cdk.StackProps {
  environment: string;
  stackName: string;
  rootDomain: string;
  stage: string;
  region: string;
  account: string;
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
 * Argus API Stack — integrity-only architecture.
 *
 * Browser → CloudFront → HTTP API → Lambda (ingestion) → DynamoDB
 *                                                    → EventBridge warmup
 * Simplified from the earlier V5 architecture: the /v1/collect fingerprint
 * pipeline (matching-worker, profile-updater, vector-worker, and their
 * SQS queues + DDB tables) was removed. Identity now comes from the
 * integrity record alone — crypto_device_id (ECDSA pubkey hash) and
 * tpc_id (CF-stamped third-party cookie) — which is strictly better for
 * authenticated browsers than the probabilistic hash matching it replaced.
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

    const analytics = new AnalyticsConstruct(this, "Analytics", {
      stackName,
      stage,
    });

    // Batched NDJSON archive — runs in parallel with the per-session
    // integrity-archiver Lambda during shadow mode. Both write into the
    // same bucket under different prefixes (`{sessionId}.json` vs
    // `firehose/year=.../...gz`).
    const integrityFirehose = new IntegrityFirehoseConstruct(
      this,
      "IntegrityFirehose",
      {
        stackName,
        stage,
        archiveBucket: analytics.integrityArchiveBucket,
      },
    );

    // =========================================================================
    // COMPUTE LAYER
    // =========================================================================

    const stageConfig = getStageConfig(stage);

    const httpApi = new HttpApiConstruct(this, "HttpApi", {
      stackName,
      stage,
      integrityResultsTable: dynamodb.integrityResultsTable,
      probeTokensTableName,
      probeTokensTableArn,
      sigintAesKeySecretArn: resolvedSigintSecretArn,
      alarmsTopic,
      config: stageConfig,
      ecdhKeyParamName: `/${stackName}/ecdh-keypair`,
      integrityFirehoseStreamName: integrityFirehose.deliveryStreamName,
    });

    integrityFirehose.grantPutRecord(httpApi.ingestionFunction);

    const workers = new WorkersConstruct(this, "Workers", {
      stackName,
      stage,
      projectName: id,
      alarmsTopic,
      integrityArchiveBucket: analytics.integrityArchiveBucket,
      integrityResultsTable: dynamodb.integrityResultsTable,
    });

    // ASN→category dataset: weekly cron pulls IPtoASN, regex-categorizes,
    // uploads to S3. Consumers (ingestion, integrity-archiver) read on cold
    // start via services/network/asn-classifier.ts.
    const ipClass = new IpClassBuilderConstruct(this, "IpClass", {
      stackName,
      stage,
    });
    ipClass.grantReadTo(httpApi.ingestionFunction);
    ipClass.grantReadTo(httpApi.sessionGetFunction);
    if (workers.integrityArchiver) {
      ipClass.grantReadTo(workers.integrityArchiver);
    }

    // Auto-overlay discoverer: nightly cron walks recent unmapped IPs,
    // RDAPs them, populates auto-overlay.json.gz alongside the ASN dict.
    // Runtime classifier consults the overlay between hand-curated CIDR
    // rules and the IPtoASN dict (see analyzeIpConsistency precedence).
    const ipClassDiscoverer = new IpClassDiscovererConstruct(
      this,
      "IpClassDiscoverer",
      {
        stackName,
        stage,
        overlayBucket: ipClass.bucket,
        archiveBucket: analytics.integrityArchiveBucket,
      },
    );
    ipClassDiscoverer.grantReadTo(httpApi.ingestionFunction);
    ipClassDiscoverer.grantReadTo(httpApi.sessionGetFunction);
    if (workers.integrityArchiver) {
      ipClassDiscoverer.grantReadTo(workers.integrityArchiver);
    }

    // =========================================================================
    // WARMERS — Keep ingestion + session-get + integrity-archiver hot
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

    new cdk.CfnOutput(this, "IntegrityArchiveBucketName", {
      value: analytics.integrityArchiveBucket.bucketName,
      description: "S3 bucket for integrity result archives",
    });

    new cdk.CfnOutput(this, "IpClassBucketName", {
      value: ipClass.bucket.bucketName,
      description: "S3 bucket for ASN→category dataset",
    });

    new cdk.CfnOutput(this, "IpClassBuilderFunctionArn", {
      value: ipClass.builderFunction.functionArn,
      description: "Weekly ASN dataset builder Lambda ARN",
    });
  }
}
