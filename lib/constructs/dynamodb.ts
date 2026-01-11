// lib/constructs/dynamodb.ts
import { Construct } from "constructs";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import { Duration, RemovalPolicy } from "aws-cdk-lib";

interface DynamoDbConstructProps {
  stackName: string;
  alarmsTopic: sns.ITopic;
}

/**
 * DynamoDB tables for Argus device profiles and indexes
 * - Profiles: (tenant, device_id) -> profile blob
 * - Tier1Index: (tenant, hash_type#hash_value) -> device_id (for O(1) lookups)
 * - Tier2Buckets: (bucket_key) -> [device_ids] (for compound filter matching)
 */
export class DynamoDbConstruct extends Construct {
  public readonly profilesTable: dynamodb.Table;
  public readonly tier1IndexTable: dynamodb.Table;
  public readonly tier2BucketsTable: dynamodb.Table;

  constructor(scope: Construct, id: string, props: DynamoDbConstructProps) {
    super(scope, id);

    const { stackName, alarmsTopic } = props;

    // Profiles table - main device profile storage
    // PK: tenant_id, SK: device_id
    this.profilesTable = new dynamodb.Table(this, "ProfilesTable", {
      tableName: `${stackName}-profiles`,
      partitionKey: { name: "tenant_id", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "device_id", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      timeToLiveAttribute: "ttl",
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // GSI for looking up by device_id across tenants (admin queries)
    this.profilesTable.addGlobalSecondaryIndex({
      indexName: "device-index",
      partitionKey: { name: "device_id", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    });

    // Tier 1 Index table - O(1) hash lookups
    // PK: tenant_id, SK: hash_type#hash_value (e.g., "stable_hash#abc123")
    this.tier1IndexTable = new dynamodb.Table(this, "Tier1IndexTable", {
      tableName: `${stackName}-tier1-index`,
      partitionKey: { name: "tenant_id", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "hash_key", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: "ttl",
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // Tier 2 Buckets table - compound filter matching
    // Uses adjacency list pattern to avoid 400KB item size limit
    // PK: bucket_key (e.g., "tenant#ip_ja4#192.168.1.1#ja4_hash")
    // SK: device_id - allows unlimited devices per bucket via Query
    // Note: table name has -v2 suffix due to schema change (added sort key)
    this.tier2BucketsTable = new dynamodb.Table(this, "Tier2BucketsTableV2", {
      tableName: `${stackName}-tier2-buckets-v2`,
      partitionKey: { name: "bucket_key", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "device_id", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: "ttl",
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // Alarms
    this.createTableAlarms(this.profilesTable, "Profiles", alarmsTopic);
    this.createTableAlarms(this.tier1IndexTable, "Tier1Index", alarmsTopic);
    this.createTableAlarms(this.tier2BucketsTable, "Tier2Buckets", alarmsTopic);
  }

  private createTableAlarms(
    table: dynamodb.Table,
    prefix: string,
    alarmsTopic: sns.ITopic,
  ) {
    // Throttled requests alarm
    const throttleAlarm = new cloudwatch.Alarm(this, `${prefix}ThrottleAlarm`, {
      metric: table.metricThrottledRequestsForOperations({
        operations: [
          dynamodb.Operation.GET_ITEM,
          dynamodb.Operation.PUT_ITEM,
          dynamodb.Operation.QUERY,
        ],
        period: Duration.minutes(5),
        statistic: "Sum",
      }),
      threshold: 10,
      evaluationPeriods: 2,
      alarmDescription: `DynamoDB ${prefix} table throttled > 10 times`,
    });
    throttleAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // System errors alarm
    const errorAlarm = new cloudwatch.Alarm(this, `${prefix}ErrorAlarm`, {
      metric: table.metricSystemErrorsForOperations({
        operations: [
          dynamodb.Operation.GET_ITEM,
          dynamodb.Operation.PUT_ITEM,
          dynamodb.Operation.QUERY,
        ],
        period: Duration.minutes(5),
        statistic: "Sum",
      }),
      threshold: 5,
      evaluationPeriods: 2,
      alarmDescription: `DynamoDB ${prefix} table system errors > 5`,
    });
    errorAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }
}
