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
import { AnalyticsConstruct } from "../constructs/analytics";
import { IntegrityFirehoseConstruct } from "../constructs/integrity-firehose";
import { IpClassBuilderConstruct } from "../constructs/ip-class-builder";
import { LambdasConstruct } from "../constructs/lambdas";
import { HttpApiConstruct } from "../constructs/http-api";
import { RestApiConstruct } from "../constructs/rest-api";
import { CloudFrontWafConstruct } from "../constructs/cloudfront";
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
   * Prefer sigintPlatformEnvironment for automatic SSM lookup.
   */
  sigintAesKeySecretArn?: string;
  /**
   * ms-argus-platform environment name (e.g. "dev-jw") to auto-lookup the
   * sigint AES key ARN, probe-tokens table, and merchants table from SSM
   * at synth time (cached in cdk.context.json).
   * SSM path base: /argus-platform/{sigintPlatformEnvironment}
   */
  sigintPlatformEnvironment?: string;
}

/**
 * Argus API Stack — thin composition.
 *
 * Each AWS resource type has a single owner construct:
 *   - Tables → DynamoDbConstruct
 *   - Buckets → AnalyticsConstruct (3) + IpClassBuilderConstruct (1)
 *   - Secrets → SecretConstruct
 *   - Firehose → IntegrityFirehoseConstruct + AnalyticsConstruct
 *   - Lambdas → LambdasConstruct (all 6, with their cron rules + IAM grants)
 *   - APIs   → HttpApiConstruct + RestApiConstruct (Lambdas come in as props)
 *   - CDN    → CloudFrontWafConstruct
 *
 * Stack composition order: secrets/tables/buckets/firehose first (no
 * Lambda dependencies); then Lambdas; then the APIs that wire them; then
 * the CDN at the edge.
 */

interface ResolvedSigintParams {
  sigintSecretArn: string | undefined;
  probeTokensTableName: string | undefined;
  probeTokensTableArn: string | undefined;
  merchantsTableName: string | undefined;
  merchantsTableArn: string | undefined;
  merchantKeysTableName: string | undefined;
  merchantKeysTableArn: string | undefined;
}

function resolveSigintParams(
  scope: cdk.Stack,
  sigintPlatformEnvironment: string | undefined,
  sigintAesKeySecretArn: string | undefined,
): ResolvedSigintParams {
  if (!sigintPlatformEnvironment) {
    return {
      sigintSecretArn: sigintAesKeySecretArn,
      probeTokensTableName: undefined,
      probeTokensTableArn: undefined,
      merchantsTableName: undefined,
      merchantsTableArn: undefined,
      merchantKeysTableName: undefined,
      merchantKeysTableArn: undefined,
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
    merchantKeysTableName: ssm.StringParameter.valueFromLookup(
      scope,
      `${base}/merchant-keys-table-name`,
    ),
    merchantKeysTableArn: ssm.StringParameter.valueFromLookup(
      scope,
      `${base}/merchant-keys-table-arn`,
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

    const sigint = resolveSigintParams(
      this,
      sigintPlatformEnvironment,
      sigintAesKeySecretArn,
    );
    if (!sigint.merchantsTableName || !sigint.merchantsTableArn) {
      throw new Error(
        "merchants table SSM exports not found — ms-argus-platform must be deployed first to expose " +
          `/argus-platform/${sigintPlatformEnvironment}/merchants-table-{name,arn}`,
      );
    }

    const platformPubkeySsmPath = sigintPlatformEnvironment
      ? `/argus-platform/${sigintPlatformEnvironment}/api-signing-pubkey`
      : undefined;
    if (!platformPubkeySsmPath) {
      throw new Error(
        "sigintPlatformEnvironment is required so the api can locate the platform Ed25519 pubkey",
      );
    }

    // ── DNS + cert ────────────────────────────────────────────────────
    const hostedZone = route53.HostedZone.fromLookup(this, "HostedZone", {
      domainName: rootDomain,
    });
    const apiSubdomain = stage === "prod" ? "api" : `api-${environment}`;
    const apiDomainName = `${apiSubdomain}.${rootDomain}`;
    const certificate = new acm.Certificate(this, "Certificate", {
      domainName: apiDomainName,
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    // ── Shared resources ──────────────────────────────────────────────
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

    // ── Data layer ────────────────────────────────────────────────────
    const dynamodb = new DynamoDbConstruct(this, "DynamoDB", {
      stackName,
      alarmsTopic,
      stage,
    });

    // Cross-stack export: ms-argus-platform's dashboard Lambda reads
    // these to enumerate recent sessions across CPIs.
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

    const integrityFirehose = new IntegrityFirehoseConstruct(
      this,
      "IntegrityFirehose",
      {
        stackName,
        stage,
        archiveBucket: analytics.integrityArchiveBucket,
      },
    );

    const ipClass = new IpClassBuilderConstruct(this, "IpClass", {
      stackName,
      stage,
    });

    // ── Compute layer ─────────────────────────────────────────────────
    const stageConfig = getStageConfig(stage);

    const lambdas = new LambdasConstruct(this, "Lambdas", {
      stackName,
      stage,
      integrityResultsTable: dynamodb.integrityResultsTable,
      archiveBucket: analytics.integrityArchiveBucket,
      ipClassBucket: ipClass.bucket,
      probeTokensTableName: sigint.probeTokensTableName,
      probeTokensTableArn: sigint.probeTokensTableArn,
      merchantsTableName: sigint.merchantsTableName,
      merchantsTableArn: sigint.merchantsTableArn,
      merchantKeysTableName: sigint.merchantKeysTableName,
      merchantKeysTableArn: sigint.merchantKeysTableArn,
      sigintAesKeySecretArn: sigint.sigintSecretArn,
      ecdhKeyParamName: `/${stackName}/ecdh-keypair`,
      platformPubkeySsmPath,
      integrityFirehoseStreamName: integrityFirehose.deliveryStreamName,
      config: stageConfig,
    });

    // Bucket reads + env-var injection for the API Lambdas. The cron
    // Lambdas already have direct grants applied inside LambdasConstruct.
    ipClass.grantReadTo(lambdas.ingestion);
    ipClass.grantReadTo(lambdas.sessionGet);

    integrityFirehose.grantPutRecord(lambdas.ingestion);

    // ── API layer ─────────────────────────────────────────────────────
    const httpApi = new HttpApiConstruct(this, "HttpApi", {
      stackName,
      alarmsTopic,
      config: stageConfig,
      ingestionFunction: lambdas.ingestion,
      sessionGetFunction: lambdas.sessionGet,
      patAttestFunction: lambdas.patAttest,
    });

    const restApi = new RestApiConstruct(this, "RestApi", {
      stackName,
      environment,
      rootDomain,
      hostedZone,
      sessionGetFunction: lambdas.sessionGet,
    });

    // ── Warmers (1-min ping to keep the two API Lambdas hot) ──────────
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
        new targets.LambdaFunction(lambdas.ingestion, { event: warmupPayload }),
      ],
    });

    new events.Rule(this, "SessionGetWarmupRule", {
      ruleName: `${stackName}-session-get-warmup`,
      description: "Keep session-get Lambda warm",
      schedule: events.Schedule.rate(cdk.Duration.minutes(1)),
      targets: [
        new targets.LambdaFunction(lambdas.sessionGet, {
          event: warmupPayload,
        }),
      ],
    });

    // ── Edge layer ────────────────────────────────────────────────────
    const cdn = new CloudFrontWafConstruct(this, "CDN", {
      environment,
      stackName,
      httpApiEndpoint: httpApi.apiEndpoint,
      rootDomain,
      apiSubdomain,
      hostedZone,
      certificate,
      stageConfig,
    });

    // ── Outputs ───────────────────────────────────────────────────────
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
      value: lambdas.ingestion.functionArn,
      description: "Ingestion Lambda ARN",
    });
    new cdk.CfnOutput(this, "SessionGetFunctionArn", {
      value: lambdas.sessionGet.functionArn,
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
      value: lambdas.ipClassBuilder.functionArn,
      description: "Weekly ASN dataset builder Lambda ARN",
    });
    new cdk.CfnOutput(this, "MerchantApiUrl", {
      value: restApi.endpoint,
      description: "Merchant-facing REST API (native APIGW Keys + Usage Plans)",
    });
  }
}
