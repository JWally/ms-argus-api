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
import { RestApiConstruct } from "../constructs/rest-api";
import { IpClassBuilderConstruct } from "../constructs/ip-class-builder";
import { IpClassDiscovererConstruct } from "../constructs/ip-class-discoverer";
import { BrowserBaselineBuilderConstruct } from "../constructs/browser-baseline-builder";
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
  merchantsTableName: string | undefined;
  merchantsTableArn: string | undefined;
} {
  if (!sigintPlatformEnvironment) {
    return {
      sigintSecretArn: sigintAesKeySecretArn,
      probeTokensTableName: undefined,
      probeTokensTableArn: undefined,
      merchantsTableName: undefined,
      merchantsTableArn: undefined,
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
    merchantsTableName: ssm.StringParameter.valueFromLookup(
      scope,
      `${base}/merchants-table-name`,
    ),
    merchantsTableArn: ssm.StringParameter.valueFromLookup(
      scope,
      `${base}/merchants-table-arn`,
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
      merchantsTableName,
      merchantsTableArn,
    } = resolveSigintParams(
      this,
      sigintPlatformEnvironment,
      sigintAesKeySecretArn,
    );

    if (!merchantsTableName || !merchantsTableArn) {
      throw new Error(
        "merchants table SSM exports not found — ms-argus-platform must be deployed first to expose " +
          `/argus-platform/${sigintPlatformEnvironment}/merchants-table-{name,arn}`,
      );
    }

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

    // Export integrity-results table identity for cross-stack consumers
    // (ms-argus-platform's dashboard Lambda reads this for the recent
    // sessions feed). Out-of-band SSM keeps the dependency loose —
    // platform doesn't need a CFN export reference, just a parameter
    // name it resolves at synth time.
    new ssm.StringParameter(this, "IntegrityResultsTableNameParam", {
      parameterName: `/argus-api/${environment}/integrity-results-table-name`,
      stringValue: dynamodb.integrityResultsTable.tableName,
    });
    new ssm.StringParameter(this, "IntegrityResultsTableArnParam", {
      parameterName: `/argus-api/${environment}/integrity-results-table-arn`,
      stringValue: dynamodb.integrityResultsTable.tableArn,
    });

    const analytics = new AnalyticsConstruct(this, "Analytics", {
      stackName,
      stage,
    });

    // Batched NDJSON archive: ingestion Lambda PutRecords directly to
    // Firehose, which writes gzipped batches into the integrity-archive
    // bucket under `firehose/year=.../...gz`. Replaced the earlier
    // DDB-stream → integrity-archiver Lambda → per-session-JSON path.
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

    // SSM path for the platform's Ed25519 pubkey used to verify merchant
    // API tokens. Created out-of-band by ms-argus-platform's
    // scripts/generate-signing-key.ts (CDK-managed StringParameter would
    // overwrite the value on every deploy).
    const platformPubkeySsmPath = sigintPlatformEnvironment
      ? `/argus-platform/${sigintPlatformEnvironment}/api-signing-pubkey`
      : undefined;
    if (!platformPubkeySsmPath) {
      throw new Error(
        "sigintPlatformEnvironment is required so the api can locate the platform Ed25519 pubkey",
      );
    }

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
      platformPubkeySsmPath,
      merchantsTableName,
      merchantsTableArn,
    });

    // Merchant-facing REST API: native APIGW Keys + Usage Plans.
    // Wires the same session-get Lambda; route discrimination happens
    // inside the handler based on path shape (/v1/session/{cpi}/{sid}).
    const restApi = new RestApiConstruct(this, "RestApi", {
      stackName,
      environment,
      rootDomain,
      hostedZone,
      sessionGetFunction: httpApi.sessionGetFunction,
    });

    integrityFirehose.grantPutRecord(httpApi.ingestionFunction);

    // ASN→category dataset: weekly cron pulls IPtoASN, regex-categorizes,
    // uploads to S3. Read on cold start via services/network/asn-classifier.ts.
    const ipClass = new IpClassBuilderConstruct(this, "IpClass", {
      stackName,
      stage,
    });
    ipClass.grantReadTo(httpApi.ingestionFunction);
    ipClass.grantReadTo(httpApi.sessionGetFunction);

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

    // Browser-engine baseline aggregator: daily cron walks the integrity
    // archive, builds per-(browser, version, incognito) histograms of
    // engine-invariant fields, writes browser-baselines.json.gz next to
    // the ASN dict. Runtime ingestion analyzes claimed-vs-observed engine
    // consistency against these baselines (see analyzeBrowserEngine).
    const browserBaselines = new BrowserBaselineBuilderConstruct(
      this,
      "BrowserBaselines",
      {
        stackName,
        stage,
        outputBucket: ipClass.bucket,
        archiveBucket: analytics.integrityArchiveBucket,
      },
    );
    browserBaselines.grantReadTo(httpApi.ingestionFunction);
    browserBaselines.grantReadTo(httpApi.sessionGetFunction);

    // =========================================================================
    // WARMERS — Keep ingestion + session-get hot
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

    new cdk.CfnOutput(this, "MerchantApiUrl", {
      value: restApi.endpoint,
      description: "Merchant-facing REST API (native APIGW Keys + Usage Plans)",
    });
  }
}
