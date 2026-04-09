// lib/constructs/analytics.ts

import { Construct } from "constructs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as kinesisfirehose from "aws-cdk-lib/aws-kinesisfirehose";
import * as glue from "aws-cdk-lib/aws-glue";
import * as iam from "aws-cdk-lib/aws-iam";
import * as logs from "aws-cdk-lib/aws-logs";
import { Duration, RemovalPolicy, Stack } from "aws-cdk-lib";

interface AnalyticsConstructProps {
  stackName: string;
  stage: string;
}

/**
 * Analytics pipeline for match observations
 *
 * Provides observability into matching decisions for:
 * - Model evaluation and tuning
 * - False-positive investigations
 * - Backfills and replays
 * - Tenant support
 *
 * Architecture:
 * Matching Worker -> Firehose -> S3 (Parquet) -> Glue Catalog -> Athena
 */
export class AnalyticsConstruct extends Construct {
  public readonly observationsBucket: s3.Bucket;
  public readonly payloadArchiveBucket: s3.Bucket;
  public readonly integrityArchiveBucket: s3.Bucket;
  public readonly deliveryStream: kinesisfirehose.CfnDeliveryStream;
  public readonly deliveryStreamArn: string;
  public readonly glueDatabase: glue.CfnDatabase;
  public readonly glueTable: glue.CfnTable;

  constructor(scope: Construct, id: string, props: AnalyticsConstructProps) {
    super(scope, id);

    const { stackName, stage } = props;

    // =====================================
    // S3 BUCKET FOR OBSERVATIONS

    // =====================================
    const accountId = Stack.of(this).account;
    const region = Stack.of(this).region;

    this.observationsBucket = new s3.Bucket(this, "ObservationsBucket", {
      bucketName: `${stackName}-observations-${accountId}-${region}`,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      lifecycleRules: [
        {
          id: "TransitionToIA",
          transitions: [
            {
              storageClass: s3.StorageClass.INTELLIGENT_TIERING,
              transitionAfter: Duration.days(30),
            },
          ],
        },
        {
          id: "ExpireOldData",
          expiration: Duration.days(365),
          noncurrentVersionExpiration: Duration.days(7),
        },
      ],
      versioned: true,
      removalPolicy:
        stage === "prod" ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
      autoDeleteObjects: stage !== "prod",
    });

    // =====================================

    // Raw fingerprint payloads for debugging and ML training
    // =====================================
    this.payloadArchiveBucket = new s3.Bucket(this, "PayloadArchiveBucket", {
      bucketName: `${stackName}-payload-archive-${accountId}-${region}`,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      lifecycleRules: [
        {
          id: "TransitionToIntelligentTiering",
          transitions: [
            {
              storageClass: s3.StorageClass.INTELLIGENT_TIERING,
              transitionAfter: Duration.days(30),
            },
          ],
        },
        {
          id: "ExpireHighQualityAfter90Days",
          expiration: Duration.days(90),
          tagFilters: {
            quality: "high",
          },
        },
        {
          // Low-quality payloads (skinny test payloads) expire after 7 days
          id: "ExpireLowQualityAfter7Days",
          expiration: Duration.days(7),
          tagFilters: {
            quality: "low",
          },
        },
        {
          // Fallback: untagged payloads expire after 90 days
          id: "ExpireUntaggedAfter90Days",
          expiration: Duration.days(90),
        },
      ],
      removalPolicy:
        stage === "prod" ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
      autoDeleteObjects: stage !== "prod",
    });

    // =====================================
    // S3 BUCKET FOR INTEGRITY ARCHIVE
    // =====================================
    // Individual JSON files per session for inspection and later bulk analysis
    // Key format: integrity/{YYYY}/{MM}/{DD}/{sessionId}.json

    this.integrityArchiveBucket = new s3.Bucket(
      this,
      "IntegrityArchiveBucket",
      {
        bucketName: `${stackName}-integrity-archive-${accountId}-${region}`,
        encryption: s3.BucketEncryption.S3_MANAGED,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        lifecycleRules: [
          {
            id: "ExpireAfter14Days",
            expiration: Duration.days(14),
          },
        ],
        removalPolicy:
          stage === "prod" ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
        autoDeleteObjects: stage !== "prod",
      },
    );

    // =====================================
    // IAM ROLE FOR FIREHOSE
    // =====================================
    const glueDbName = `${stackName.replace(/-/g, "_")}_analytics`;

    // Create role with inline policies to ensure all permissions are ready
    // before Firehose is created (avoids race conditions with separate Policy resources)
    const firehoseRole = new iam.Role(this, "FirehoseRole", {
      assumedBy: new iam.ServicePrincipal("firehose.amazonaws.com"),
      inlinePolicies: {
        FirehosePolicy: new iam.PolicyDocument({
          statements: [
            // S3 permissions
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                "s3:AbortMultipartUpload",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:PutObject",
              ],
              resources: [
                this.observationsBucket.bucketArn,
                `${this.observationsBucket.bucketArn}/*`,
              ],
            }),
            // CloudWatch Logs permissions
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ["logs:PutLogEvents"],
              resources: ["*"],
            }),
            // Glue permissions for schema conversion
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                "glue:GetTable",
                "glue:GetTableVersion",
                "glue:GetTableVersions",
              ],
              resources: [
                `arn:aws:glue:${region}:${accountId}:catalog`,
                `arn:aws:glue:${region}:${accountId}:database/${glueDbName}`,
                `arn:aws:glue:${region}:${accountId}:table/${glueDbName}/*`,
              ],
            }),
          ],
        }),
      },
    });

    // =====================================
    // CLOUDWATCH LOG GROUP FOR FIREHOSE
    // =====================================
    const logGroup = new logs.LogGroup(this, "FirehoseLogGroup", {
      logGroupName: `/aws/kinesisfirehose/${stackName}-observations`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy:
        stage === "prod" ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
    });

    const logStream = new logs.LogStream(this, "FirehoseLogStream", {
      logGroup,
      logStreamName: "delivery-errors",
      removalPolicy:
        stage === "prod" ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
    });

    // =====================================
    // GLUE DATABASE AND TABLE
    // =====================================
    this.glueDatabase = new glue.CfnDatabase(this, "GlueDatabase", {
      catalogId: Stack.of(this).account,
      databaseInput: {
        name: `${stackName.replace(/-/g, "_")}_analytics`,
        description: "Argus analytics database for match observations",
      },
    });

    // Observation record schema for Parquet conversion
    this.glueTable = new glue.CfnTable(this, "ObservationsTable", {
      catalogId: Stack.of(this).account,
      databaseName: this.glueDatabase.ref,
      tableInput: {
        name: "observations",
        description: "Match observation records from Argus matching worker",
        tableType: "EXTERNAL_TABLE",
        parameters: {
          classification: "parquet",
          "parquet.compression": "SNAPPY",
        },
        storageDescriptor: {
          columns: [
            { name: "timestamp", type: "bigint" },
            { name: "session_id", type: "string" },
            { name: "device_id", type: "string" },
            { name: "match_tier", type: "double" },
            { name: "confidence", type: "double" },
            { name: "is_new_device", type: "boolean" },
            { name: "risk_score", type: "double" },
            { name: "evidence_codes", type: "array<string>" },
            { name: "tier2_timed_out", type: "boolean" },
            { name: "processing_duration_ms", type: "int" },
          ],
          location: `s3://${this.observationsBucket.bucketName}/observations/`,
          inputFormat:
            "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
          outputFormat:
            "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat",
          serdeInfo: {
            serializationLibrary:
              "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe",
          },
        },
        partitionKeys: [
          { name: "year", type: "string" },
          { name: "month", type: "string" },
          { name: "day", type: "string" },
        ],
      },
    });

    // =====================================
    // KINESIS FIREHOSE DELIVERY STREAM
    // =====================================
    this.deliveryStream = new kinesisfirehose.CfnDeliveryStream(
      this,
      "ObservationsStream",
      {
        deliveryStreamName: `${stackName}-observations`,
        deliveryStreamType: "DirectPut",
        extendedS3DestinationConfiguration: {
          bucketArn: this.observationsBucket.bucketArn,
          roleArn: firehoseRole.roleArn,
          prefix:
            "observations/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/",
          errorOutputPrefix:
            "errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/",
          bufferingHints: {
            intervalInSeconds: 300, // 5 minutes - balance between latency and cost
            sizeInMBs: 64, // Batch up to 64MB before writing
          },
          compressionFormat: "UNCOMPRESSED", // Parquet handles compression
          dataFormatConversionConfiguration: {
            enabled: true,
            inputFormatConfiguration: {
              deserializer: {
                openXJsonSerDe: {},
              },
            },
            outputFormatConfiguration: {
              serializer: {
                parquetSerDe: {
                  compression: "SNAPPY",
                },
              },
            },
            schemaConfiguration: {
              catalogId: Stack.of(this).account,
              databaseName: this.glueDatabase.ref,
              tableName: "observations",
              region: Stack.of(this).region,
              versionId: "LATEST",
              roleArn: firehoseRole.roleArn,
            },
          },
          cloudWatchLoggingOptions: {
            enabled: true,
            logGroupName: logGroup.logGroupName,
            logStreamName: logStream.logStreamName,
          },
        },
      },
    );

    // Ensure Glue table is created before Firehose
    this.deliveryStream.addDependency(this.glueTable);

    this.deliveryStreamArn = this.deliveryStream.attrArn;
  }
}
