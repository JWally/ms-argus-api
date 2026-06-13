// lib/constructs/integrity-firehose.ts

import { Construct } from "constructs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as kinesisfirehose from "aws-cdk-lib/aws-kinesisfirehose";
import * as iam from "aws-cdk-lib/aws-iam";
import * as logs from "aws-cdk-lib/aws-logs";
import { RemovalPolicy, Stack } from "aws-cdk-lib";

interface IntegrityFirehoseConstructProps {
  stackName: string;
  stage: string;
  /**
   * Bucket where Firehose lands batched gzipped NDJSON. Reuses the existing
   * integrity-archive bucket; new data lives under the `firehose/` prefix.
   */
  archiveBucket: s3.IBucket;
}

/**
 * Batched NDJSON archiver via Kinesis Data Firehose.
 *
 * Replaces the per-session DynamoDB Stream → Lambda → S3 PUT path with a
 * direct PutRecord from the ingestion Lambda into Firehose. Firehose
 * batches records by time (60s) or size (5MB) and writes one gzipped
 * NDJSON file per batch — at 1B req/mo this drops S3 PUT cost from
 * ~$5K/mo to ~$5/mo.
 *
 * Output keys (Hive-partitioned for Athena):
 *   firehose/year=YYYY/month=MM/day=DD/hour=HH/<timestamp>-<uuid>.gz
 *
 * Failed deliveries land at:
 *   firehose-errors/<error-type>/year=YYYY/month=MM/day=DD/<file>
 */
export class IntegrityFirehoseConstruct extends Construct {
  public readonly deliveryStream: kinesisfirehose.CfnDeliveryStream;
  public readonly deliveryStreamName: string;

  constructor(
    scope: Construct,
    id: string,
    props: IntegrityFirehoseConstructProps,
  ) {
    super(scope, id);

    const { stackName, stage, archiveBucket } = props;
    const streamName = `${stackName}-integrity-archive`;

    const firehoseRole = new iam.Role(this, "FirehoseRole", {
      assumedBy: new iam.ServicePrincipal("firehose.amazonaws.com"),
      inlinePolicies: {
        FirehosePolicy: new iam.PolicyDocument({
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
                archiveBucket.bucketArn,
                `${archiveBucket.bucketArn}/*`,
              ],
            }),
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ["logs:PutLogEvents"],
              resources: ["*"],
            }),
          ],
        }),
      },
    });

    const logGroup = new logs.LogGroup(this, "FirehoseLogGroup", {
      logGroupName: `/aws/kinesisfirehose/${streamName}`,
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

    this.deliveryStream = new kinesisfirehose.CfnDeliveryStream(
      this,
      "Stream",
      {
        deliveryStreamName: streamName,
        deliveryStreamType: "DirectPut",
        extendedS3DestinationConfiguration: {
          bucketArn: archiveBucket.bucketArn,
          roleArn: firehoseRole.roleArn,
          prefix:
            "firehose/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/",
          errorOutputPrefix:
            "firehose-errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/",
          bufferingHints: {
            intervalInSeconds: 60,
            sizeInMBs: 5,
          },
          compressionFormat: "GZIP",
          cloudWatchLoggingOptions: {
            enabled: true,
            logGroupName: logGroup.logGroupName,
            logStreamName: logStream.logStreamName,
          },
        },
      },
    );

    this.deliveryStreamName = streamName;
  }

  /** Grant a Lambda (or any IGrantable) PutRecord on this stream. */
  public grantPutRecord(grantee: iam.IGrantable): void {
    grantee.grantPrincipal.addToPrincipalPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["firehose:PutRecord", "firehose:PutRecordBatch"],
        resources: [
          `arn:aws:firehose:${Stack.of(this).region}:${Stack.of(this).account}:deliverystream/${this.deliveryStreamName}`,
        ],
      }),
    );
  }

  /**
   * Read-only DescribeDeliveryStream — used by the integrity-collect deep
   * warmup to keep the Firehose keep-alive socket fresh without writing.
   */
  public grantDescribe(grantee: iam.IGrantable): void {
    grantee.grantPrincipal.addToPrincipalPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["firehose:DescribeDeliveryStream"],
        resources: [
          `arn:aws:firehose:${Stack.of(this).region}:${Stack.of(this).account}:deliverystream/${this.deliveryStreamName}`,
        ],
      }),
    );
  }
}
