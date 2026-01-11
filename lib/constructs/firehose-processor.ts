// lib/constructs/firehose-processor.ts
import { Construct } from "constructs";
import * as sns from "aws-cdk-lib/aws-sns";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as firehose from "aws-cdk-lib/aws-kinesisfirehose";
import * as iam from "aws-cdk-lib/aws-iam";
import * as logs from "aws-cdk-lib/aws-logs";
import { Duration, RemovalPolicy } from "aws-cdk-lib";
import * as cdk from "aws-cdk-lib";

interface FirehoseProcessorProps {
  stackName: string;
  inputTopic: sns.ITopic;
  modelName: string;
  stage: string;
  glueDbName: string;
  glueTableName: string;
  glueCatalogId?: string;
}

/**
 * Firehose Processor for Argus API
 * Writes fingerprint data to S3 in Parquet format with JSON backup
 */
export class FirehoseProcessor extends Construct {
  public readonly bucket: s3.Bucket;
  public readonly firehoseDeliveryStream: firehose.CfnDeliveryStream;

  constructor(scope: Construct, id: string, props: FirehoseProcessorProps) {
    super(scope, id);

    const {
      stackName,
      inputTopic,
      modelName,
      stage,
      glueDbName,
      glueTableName,
      glueCatalogId,
    } = props;

    // S3 bucket with lifecycle rules
    this.bucket = new s3.Bucket(this, `${stackName}-${modelName}`, {
      removalPolicy: RemovalPolicy.DESTROY,
      lifecycleRules: [
        {
          id: "expire-raw-data-after-5-days",
          enabled: true,
          prefix: "data/",
          expiration: Duration.days(5),
          abortIncompleteMultipartUploadAfter: Duration.days(1),
        },
        {
          id: "expire-errors-after-14-days",
          enabled: true,
          prefix: "errors/",
          expiration: Duration.days(14),
          abortIncompleteMultipartUploadAfter: Duration.days(1),
        },
        {
          id: "expire-parquet-after-90-days",
          enabled: true,
          prefix: "parquet/",
          expiration: Duration.days(90),
        },
      ],
    });

    // Firehose logging
    const logGroup = new logs.LogGroup(
      this,
      `${stage}-${modelName}-firehose-log-group`,
      {
        logGroupName: `/aws/kinesisfirehose/${stage}-${stackName}-${modelName}-firehose`,
        retention: logs.RetentionDays.ONE_WEEK,
        removalPolicy: RemovalPolicy.DESTROY,
      },
    );

    const logStream = new logs.LogStream(
      this,
      `${stage}-${modelName}-firehose-log-stream`,
      {
        logGroup,
        logStreamName: "delivery-stream-logs",
      },
    );

    // Firehose role
    const region = cdk.Stack.of(this).region;
    const acct = cdk.Stack.of(this).account;

    const firehoseRole = new iam.Role(
      this,
      `${stage}-${modelName}-firehose-role`,
      {
        assumedBy: new iam.ServicePrincipal("firehose.amazonaws.com"),
        inlinePolicies: {
          S3LogsGlue: new iam.PolicyDocument({
            statements: [
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
                  this.bucket.bucketArn,
                  `${this.bucket.bucketArn}/*`,
                ],
              }),
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: ["logs:PutLogEvents"],
                resources: [logGroup.logGroupArn, `${logGroup.logGroupArn}:*`],
              }),
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                  "glue:GetDatabase",
                  "glue:GetTable",
                  "glue:GetTableVersion",
                  "glue:GetTableVersions",
                  "glue:GetPartitions",
                ],
                resources: [
                  `arn:aws:glue:${region}:${acct}:catalog`,
                  `arn:aws:glue:${region}:${acct}:database/${glueDbName}`,
                  `arn:aws:glue:${region}:${acct}:table/${glueDbName}/${glueTableName}`,
                  `arn:aws:glue:${region}:${acct}:tableVersion/${glueDbName}/${glueTableName}/*`,
                ],
              }),
            ],
          }),
        },
      },
    );

    // Extended S3 destination with Parquet conversion
    const extendedS3: firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty =
      {
        bucketArn: this.bucket.bucketArn,
        roleArn: firehoseRole.roleArn,
        prefix:
          "parquet/" +
          "year=!{timestamp:yyyy}/" +
          "month=!{timestamp:MM}/" +
          "day=!{timestamp:dd}/" +
          "hour=!{timestamp:HH}/",
        errorOutputPrefix:
          "errors/converted/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd}/",
        bufferingHints: {
          sizeInMBs: stage === "prod" ? 128 : 64,
          intervalInSeconds: stage === "prod" ? 300 : 60,
        },
        cloudWatchLoggingOptions: {
          enabled: true,
          logGroupName: logGroup.logGroupName,
          logStreamName: logStream.logStreamName,
        },
        processingConfiguration: {
          enabled: true,
          processors: [
            {
              type: "AppendDelimiterToRecord",
              parameters: [
                { parameterName: "Delimiter", parameterValue: "\\n" },
              ],
            },
          ],
        },
        dataFormatConversionConfiguration: {
          enabled: true,
          schemaConfiguration: {
            databaseName: glueDbName,
            tableName: glueTableName,
            roleArn: firehoseRole.roleArn,
            catalogId: glueCatalogId,
          },
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
        },
        s3BackupMode: "Enabled",
        s3BackupConfiguration: {
          bucketArn: this.bucket.bucketArn,
          roleArn: firehoseRole.roleArn,
          prefix:
            "data/" +
            "year=!{timestamp:yyyy}/" +
            "month=!{timestamp:MM}/" +
            "day=!{timestamp:dd}/" +
            "hour=!{timestamp:HH}/",
          errorOutputPrefix:
            "errors/raw/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd}/",
          bufferingHints: {
            sizeInMBs: stage === "prod" ? 128 : 64,
            intervalInSeconds: stage === "prod" ? 300 : 60,
          },
          compressionFormat: "GZIP",
          cloudWatchLoggingOptions: {
            enabled: true,
            logGroupName: logGroup.logGroupName,
            logStreamName: logStream.logStreamName,
          },
        },
      };

    this.firehoseDeliveryStream = new firehose.CfnDeliveryStream(
      this,
      `${modelName}-firehose`,
      {
        deliveryStreamName: `${stage}-${stackName}-${modelName}-firehose`,
        deliveryStreamType: "DirectPut",
        extendedS3DestinationConfiguration: extendedS3,
      },
    );
    this.firehoseDeliveryStream.node.addDependency(logGroup, logStream);

    // SNS to Firehose subscription
    const snsToFirehoseRole = new iam.Role(
      this,
      `${stage}-${modelName}-sns-firehose-role`,
      {
        assumedBy: new iam.ServicePrincipal("sns.amazonaws.com"),
        inlinePolicies: {
          FirehosePut: new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: ["firehose:PutRecord", "firehose:PutRecordBatch"],
                resources: [this.firehoseDeliveryStream.attrArn],
              }),
            ],
          }),
        },
      },
    );

    new sns.CfnSubscription(this, `${stage}-${modelName}-sns-firehose`, {
      topicArn: inputTopic.topicArn,
      protocol: "firehose",
      endpoint: this.firehoseDeliveryStream.attrArn,
      subscriptionRoleArn: snsToFirehoseRole.roleArn,
      rawMessageDelivery: true,
    });
  }
}
