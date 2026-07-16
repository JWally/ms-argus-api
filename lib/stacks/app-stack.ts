// lib/stacks/app-stack.ts

import * as cdk from "aws-cdk-lib";
import * as sns from "aws-cdk-lib/aws-sns";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as ssm from "aws-cdk-lib/aws-ssm";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ddb from "aws-cdk-lib/aws-dynamodb";
import { Construct } from "constructs";

import { SecretConstruct } from "../constructs/secrets";
import { DynamoDbConstruct } from "../constructs/dynamodb";
import { AnalyticsConstruct } from "../constructs/analytics";
import { IntegrityFirehoseConstruct } from "../constructs/integrity-firehose";
import { IpClassBuilderConstruct } from "../constructs/ip-class-builder";
import { LambdasConstruct } from "../constructs/lambdas";
import { HttpApiConstruct } from "../constructs/http-api";
import { RestApiConstruct } from "../constructs/rest-api";
import { PostDeployWarmer } from "../constructs/post-deploy-warmer";
import { addApiAliasHeaters } from "../constructs/api-alias-heaters";
import { CloudFrontWafConstruct } from "../constructs/cloudfront";
import { getStageConfig } from "../config";
import { resolveSharedDataContracts } from "../config/shared-data-contracts";

interface ArgusApiStackProps extends cdk.StackProps {
  environment: string;
  stackName: string;
  rootDomain: string;
  stage: string;
  region: string;
  account: string;
  /** Shared data contract environment published by ms-argus-infra. */
  sharedDataEnvironment: string;
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

export class ArgusApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ArgusApiStackProps) {
    super(scope, id, props);
    const {
      environment,
      stackName,
      rootDomain,
      stage,
      region,
      sharedDataEnvironment,
    } = props;

    const sharedData = resolveSharedDataContracts(this, sharedDataEnvironment);
    const platformPubkeySsmPath = `/argus-platform/${sharedDataEnvironment}/api-signing-pubkey`;

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
      stage,
    });
    // Consumer wiring uses the infra-owned contract even while the physical
    // table is still retained in this stack. That makes the later ownership
    // removal an infrastructure-only change.
    const sharedIntegrityResultsTable = ddb.Table.fromTableAttributes(
      this,
      "SharedIntegrityResultsTable",
      {
        tableName: sharedData.integrityResultsTableName,
        grantIndexPermissions: true,
      },
    );

    // Cross-stack export: ms-argus-platform's dashboard Lambda reads
    // these to enumerate recent sessions across CPIs.
    new ssm.StringParameter(this, "IntegrityResultsTableNameParam", {
      parameterName: `/argus-api/${environment}/integrity-results-table-name`,
      stringValue: sharedIntegrityResultsTable.tableName,
    });
    new ssm.StringParameter(this, "IntegrityResultsTableArnParam", {
      parameterName: `/argus-api/${environment}/integrity-results-table-arn`,
      stringValue: sharedIntegrityResultsTable.tableArn,
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

    // ── Shared infra (VPC + Valkey) from ms-argus-infra via SSM ───────
    // Optional — only wired when ms-argus-infra is deployed in the same
    // environment. When all three lookups succeed, the ingestion Lambda
    // gets VPC-attached and routes IP velocity through Valkey instead
    // of DDB. Stage derived from the api stack's `environment` (the
    // same string ms-argus-infra exports under /argus/{stage}/...).
    const sharedInfraSsmBase = `/argus/${environment}`;
    let sharedVpc: ec2.IVpc | undefined;
    let sharedLambdaSg: ec2.ISecurityGroup | undefined;
    let valkeyEndpoint: string | undefined;
    try {
      const vpcId = ssm.StringParameter.valueFromLookup(
        this,
        `${sharedInfraSsmBase}/vpc-id`,
      );
      // valueFromLookup returns a dummy "dummy-value-for-..." string if
      // the param doesn't exist yet (CDK lookup placeholder). Guard so
      // we don't try to attach to a non-existent VPC.
      if (vpcId && !vpcId.startsWith("dummy-value-for-")) {
        sharedVpc = ec2.Vpc.fromLookup(this, "SharedVpc", { vpcId });
        const sgId = ssm.StringParameter.valueForStringParameter(
          this,
          `${sharedInfraSsmBase}/lambda-security-group-id`,
        );
        sharedLambdaSg = ec2.SecurityGroup.fromSecurityGroupId(
          this,
          "SharedLambdaSg",
          sgId,
        );
        valkeyEndpoint = ssm.StringParameter.valueForStringParameter(
          this,
          `${sharedInfraSsmBase}/valkey-endpoint`,
        );
      }
    } catch {
      // ms-argus-infra not deployed in this env; ingestion stays on DDB
      // for IP velocity. Non-fatal.
    }

    // ── Compute layer ─────────────────────────────────────────────────
    const stageConfig = getStageConfig(stage);

    const lambdas = new LambdasConstruct(this, "Lambdas", {
      stackName,
      stage,
      integrityResultsTable: sharedIntegrityResultsTable,
      ipVelocityTable: dynamodb.ipVelocityTable,
      archiveBucket: analytics.integrityArchiveBucket,
      ipClassBucket: ipClass.bucket,
      probeTokensTableName: sharedData.probeTokensTableName,
      probeTokensTableArn: sharedData.probeTokensTableArn,
      merchantsTableName: sharedData.merchantsTableName,
      merchantsTableArn: sharedData.merchantsTableArn,
      merchantKeysTableName: sharedData.merchantKeysTableName,
      merchantKeysTableArn: sharedData.merchantKeysTableArn,
      sigintAesKeySecretId: sharedData.sigintSecretId,
      sigintAesKeySecretArn: sharedData.sigintSecretArn,
      ecdhKeyParamName: `/${stackName}/ecdh-keypair`,
      platformPubkeySsmPath,
      integrityFirehoseStreamName: integrityFirehose.deliveryStreamName,
      config: stageConfig,
      sharedVpc,
      sharedLambdaSecurityGroup: sharedLambdaSg,
      valkeyEndpoint,
    });

    // Bucket reads + env-var injection for the API Lambdas. The cron
    // Lambdas already have direct grants applied inside LambdasConstruct.
    ipClass.grantReadTo(lambdas.ingestion);
    ipClass.grantReadTo(lambdas.sessionGet);

    integrityFirehose.grantPutRecord(lambdas.ingestion);
    integrityFirehose.grantDescribe(lambdas.ingestion);

    // ── API layer ─────────────────────────────────────────────────────
    // Integrations route to the heated `live` aliases, not the raw $LATEST
    // functions. The raw function refs still ride through for IAM grants and
    // CloudWatch alarms.
    const httpApi = new HttpApiConstruct(this, "HttpApi", {
      stackName,
      alarmsTopic,
      config: stageConfig,
      ingestionFunction: lambdas.ingestion,
      sessionGetFunction: lambdas.sessionGet,
      patAttestFunction: lambdas.patAttest,
      ingestionAlias: lambdas.ingestionAlias,
      patAttestAlias: lambdas.patAttestAlias,
    });

    const restApi = new RestApiConstruct(this, "RestApi", {
      stackName,
      environment,
      rootDomain,
      hostedZone,
      sessionGetFunction: lambdas.sessionGetAlias,
    });

    // Wake each request-path alias immediately after deployment instead of
    // waiting for the first recurring heater tick.
    new PostDeployWarmer(this, "PostDeployWarmer", {
      targets: [
        lambdas.ingestionAlias,
        lambdas.sessionGetAlias,
        ...(lambdas.patAttestAlias ? [lambdas.patAttestAlias] : []),
      ],
      deployId: Date.now().toString(),
    });

    // EventBridge has one-minute resolution; each helper spaces six synthetic
    // alias invokes across that minute. Keep this list centralized so a new
    // request-path Lambda cannot silently end up with different warm coverage.
    addApiAliasHeaters(this, {
      stackName,
      ingestion: lambdas.ingestionAlias,
      sessionGet: lambdas.sessionGetAlias,
      patAttest: lambdas.patAttestAlias,
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
