// lib/stacks/app-stack.ts
import * as cdk from 'aws-cdk-lib';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as glue from 'aws-cdk-lib/aws-glue';
import { Construct } from 'constructs';

import { LambdaConstruct } from '../constructs/lambda';
import { HttpApiConstruct } from '../constructs/api';
import { DomainHttpConstruct } from '../constructs/domain';
import { SecretConstruct } from '../constructs/secrets';
import { FirehoseProcessor } from '../constructs/firehose-processor';
import { CloudFrontWafConstruct } from '../constructs/cloudfront';

import { WARMUP_EVENT } from '../../src/helpers/constants';
import { makeJsonTable, makeParquetProjectionTable } from '../helpers/make-glue-table';
import { ARGUS_COLUMNS } from '../../src/helpers/constants';

interface ArgusApiStackProps extends cdk.StackProps {
  environment: string;
  stackName: string;
  rootDomain: string;
  stage: string;
  region: string;
  account: string;
}

export class ArgusApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ArgusApiStackProps) {
    super(scope, id, props);
    const { environment, stackName, rootDomain, stage, region, account } = props;

    // Secrets construct
    new SecretConstruct(this, 'Secrets', {
      environment,
      stackName,
      stage,
      projectName: id,
    });

    // Alarms SNS topic
    const alarmsTopic = new sns.Topic(this, 'AlarmsTopic', {
      displayName: `${stackName}-Alarms`,
      topicName: `${stackName}-AlarmsTopic-${region}`,
    });

    // Lambda construct
    const lambdaConstruct = new LambdaConstruct(this, 'Lambda', {
      environment,
      stackName,
      stage,
      projectName: id,
      alarmsTopic,
    });

    // HTTP API Gateway
    const httpGateway = new HttpApiConstruct(
      this,
      'HttpApi',
      lambdaConstruct,
      stackName,
      alarmsTopic,
    );

    // CloudFront + WAF
    const wafAndCloudfront = new CloudFrontWafConstruct(this, 'Waf', {
      environment,
      httpApi: httpGateway.api,
      stage: httpGateway.stage,
    });

    // Custom domain (comment out if not using custom domain)
    // new DomainHttpConstruct(this, 'Domain', {
    //   stackName,
    //   rootDomain,
    //   httpApi: httpGateway.api,
    //   region,
    //   stage,
    //   httpApiStage: httpGateway.stage,
    // });

    // Warmup rule - keep Lambda warm
    const warmupRule = new events.Rule(this, 'WarmupRule', {
      schedule: events.Schedule.rate(cdk.Duration.minutes(1)),
    });
    warmupRule.addTarget(
      new targets.LambdaFunction(lambdaConstruct.collectFunction, {
        event: events.RuleTargetInput.fromObject(WARMUP_EVENT),
      }),
    );

    // Fingerprint data topic
    const fingerprintTopic = new sns.Topic(this, `${stackName}-fingerprint-topic`, {
      displayName: `${stackName}-fingerprint-topic`,
    });
    lambdaConstruct.collectFunction.addEnvironment('FINGERPRINT_TOPIC_ARN', fingerprintTopic.topicArn);
    lambdaConstruct.collectFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['sns:Publish'],
        resources: [fingerprintTopic.topicArn],
      }),
    );

    // Glue database for fingerprint schema
    const glueDbName = `${stage}_${stackName}_events_db`.toLowerCase().replace(/[^a-z0-9_]/g, '_');

    const glueDb = new glue.CfnDatabase(this, 'EventsGlueDb', {
      catalogId: account,
      databaseInput: {
        name: glueDbName,
        description: 'Argus fingerprint events schema for Firehose JSON->Parquet conversion',
      },
    });

    // Glue JSON table for Firehose schema reference
    const fingerprintTableName = 'fingerprint_events_json';
    const fingerprintGlueTable = makeJsonTable(
      this,
      'FingerprintEventsGlueTable',
      fingerprintTableName,
      account,
      glueDbName,
      ARGUS_COLUMNS,
      glueDb,
    );

    // Firehose processor for fingerprint data
    const fingerprintFirehose = new FirehoseProcessor(this, 'firehose-processor-fingerprint', {
      stackName,
      modelName: 'firehose-processor-fingerprint',
      stage,
      inputTopic: fingerprintTopic,
      glueDbName,
      glueTableName: fingerprintTableName,
      glueCatalogId: account,
    });
    fingerprintFirehose.node.addDependency(fingerprintGlueTable);

    // Parquet table for Athena queries
    makeParquetProjectionTable(
      this,
      'FingerprintEventsParquetTable',
      'fingerprint_events_parquet',
      account,
      glueDbName,
      ARGUS_COLUMNS,
      glueDb,
      fingerprintFirehose.bucket.bucketName,
      'parquet/',
    );

    // Outputs
    new cdk.CfnOutput(this, 'AlarmsTopicArn', {
      value: alarmsTopic.topicArn,
      description: 'ARN of the SNS topic for CloudWatch Alarms',
    });

    new cdk.CfnOutput(this, 'ApiEndpoint', {
      value: httpGateway.api.apiEndpoint,
      description: 'HTTP API endpoint URL',
    });

    new cdk.CfnOutput(this, 'CloudFrontDomain', {
      value: wafAndCloudfront.distribution.distributionDomainName,
      description: 'CloudFront distribution domain',
    });

    new cdk.CfnOutput(this, 'FingerprintBucket', {
      value: fingerprintFirehose.bucket.bucketName,
      description: 'S3 bucket for fingerprint data',
    });
  }
}
