// lib/constructs/dynamodb.ts
// AR-133: Added stage-conditional provisioned capacity with auto-scaling
import { Construct } from "constructs";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import { Duration, RemovalPolicy } from "aws-cdk-lib";
import { getStageConfig } from "../config";

interface DynamoDbConstructProps {
  stackName: string;
  alarmsTopic: sns.ITopic;
  stage: string;
}

/**
 * DynamoDB tables for Argus device profiles and indexes
 * AR-134: Removed tenant concept - device identity is global across Signifyd network
 * - Profiles: (device_id) -> profile blob
 * - Tier1Index: (hash_key) -> device_id (for O(1) lookups)
 * - Tier2Buckets: (bucket_key, device_id) -> metadata (for compound filter matching)
 */
export class DynamoDbConstruct extends Construct {
  public readonly profilesTable: dynamodb.Table;
  public readonly tier1IndexTable: dynamodb.Table;
  public readonly tier2BucketsTable: dynamodb.Table;
  public readonly sessionCacheTable: dynamodb.Table; // AR-52: Session cache (replaces Redis)
  public readonly sessionPayloadTable: dynamodb.Table; // AR-XXX: Full payload for gRPC stub

  constructor(scope: Construct, id: string, props: DynamoDbConstructProps) {
    super(scope, id);

    const { stackName, alarmsTopic, stage } = props;

    // AR-133: Get stage config for DynamoDB billing mode
    const config = getStageConfig(stage);
    const dbConfig = config.dynamodb;

    // AR-133: Determine billing mode based on stage config
    // Dev: provisioned capacity with auto-scaling (for testing the infrastructure)
    // Prod: PAY_PER_REQUEST until capacity analysis is done
    const billingMode = dbConfig.useProvisionedCapacity
      ? dynamodb.BillingMode.PROVISIONED
      : dynamodb.BillingMode.PAY_PER_REQUEST;

    // AR-134: Profiles table - main device profile storage
    // PK: device_id (no tenant - device identity is global)
    this.profilesTable = new dynamodb.Table(this, "ProfilesTable", {
      tableName: `${stackName}-profiles`,
      partitionKey: { name: "device_id", type: dynamodb.AttributeType.STRING },
      billingMode,
      ...(dbConfig.useProvisionedCapacity && {
        readCapacity: dbConfig.baseReadCapacity,
        writeCapacity: dbConfig.baseWriteCapacity,
      }),
      pointInTimeRecovery: true,
      timeToLiveAttribute: "ttl",
      removalPolicy: RemovalPolicy.DESTROY, // Allow destruction for schema changes
    });

    // GSI for looking up profiles by stable_hash (for test cleanup and debugging)
    this.profilesTable.addGlobalSecondaryIndex({
      indexName: "stable-hash-index",
      partitionKey: {
        name: "stable_hash",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    });

    // AR-134: Tier 1 Index table - O(1) hash lookups
    // PK: hash_key (e.g., "stable_hash#abc123" or "evercookie#xyz789")
    this.tier1IndexTable = new dynamodb.Table(this, "Tier1IndexTable", {
      tableName: `${stackName}-tier1-index`,
      partitionKey: { name: "hash_key", type: dynamodb.AttributeType.STRING },
      billingMode,
      ...(dbConfig.useProvisionedCapacity && {
        readCapacity: dbConfig.baseReadCapacity,
        writeCapacity: dbConfig.baseWriteCapacity,
      }),
      timeToLiveAttribute: "ttl",
      removalPolicy: RemovalPolicy.DESTROY, // Allow destruction for schema changes
    });

    // AR-134: Tier 2 Buckets table - compound filter matching
    // Uses adjacency list pattern to avoid 400KB item size limit
    // PK: bucket_key (e.g., "ip_ja4#192.168.1.1#ja4_hash" - no tenant prefix)
    // SK: device_id - allows unlimited devices per bucket via Query
    // Note: table name has -v2 suffix due to schema change (added sort key)
    this.tier2BucketsTable = new dynamodb.Table(this, "Tier2BucketsTableV2", {
      tableName: `${stackName}-tier2-buckets-v2`,
      partitionKey: { name: "bucket_key", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "device_id", type: dynamodb.AttributeType.STRING },
      billingMode,
      ...(dbConfig.useProvisionedCapacity && {
        readCapacity: dbConfig.baseReadCapacity,
        writeCapacity: dbConfig.baseWriteCapacity,
      }),
      timeToLiveAttribute: "ttl",
      removalPolicy: RemovalPolicy.DESTROY, // Allow destruction for schema changes
    });

    // AR-52: Session cache table - replaces Redis for session caching
    // PK: cache_key (e.g., "session:abc123" or "gate:device123")
    // Uses DynamoDB TTL for automatic expiration (vs Redis EXPIRE)
    // Benefits: Zero idle cost, no VPC required, simpler infrastructure
    this.sessionCacheTable = new dynamodb.Table(this, "SessionCacheTable", {
      tableName: `${stackName}-session-cache`,
      partitionKey: { name: "cache_key", type: dynamodb.AttributeType.STRING },
      billingMode,
      ...(dbConfig.useProvisionedCapacity && {
        readCapacity: dbConfig.baseReadCapacity,
        writeCapacity: dbConfig.baseWriteCapacity,
      }),
      timeToLiveAttribute: "ttl",
      removalPolicy: RemovalPolicy.DESTROY, // Cache data is ephemeral
    });

    // AR-XXX: Session payload table - stores full fingerprint payload for retrieval
    // PK: session_id
    // Short TTL (30 min) - stub for future gRPC endpoint
    // Stores the complete payload for debugging and future real-time integrations
    this.sessionPayloadTable = new dynamodb.Table(this, "SessionPayloadTable", {
      tableName: `${stackName}-session-payload`,
      partitionKey: { name: "session_id", type: dynamodb.AttributeType.STRING },
      billingMode,
      ...(dbConfig.useProvisionedCapacity && {
        readCapacity: dbConfig.baseReadCapacity,
        writeCapacity: dbConfig.baseWriteCapacity,
      }),
      timeToLiveAttribute: "ttl",
      removalPolicy: RemovalPolicy.DESTROY, // Ephemeral data with short TTL
    });

    // AR-133: Configure auto-scaling for provisioned capacity tables
    if (dbConfig.useProvisionedCapacity) {
      const maxCapacity = Math.ceil(
        dbConfig.baseReadCapacity * dbConfig.autoScaling.maxCapacityMultiplier,
      );
      const targetUtilization = dbConfig.autoScaling.targetUtilizationPercent;

      // Enable auto-scaling for all tables
      this.enableAutoScaling(
        this.profilesTable,
        "Profiles",
        dbConfig.baseReadCapacity,
        dbConfig.baseWriteCapacity,
        maxCapacity,
        targetUtilization,
      );
      this.enableAutoScaling(
        this.tier1IndexTable,
        "Tier1Index",
        dbConfig.baseReadCapacity,
        dbConfig.baseWriteCapacity,
        maxCapacity,
        targetUtilization,
      );
      this.enableAutoScaling(
        this.tier2BucketsTable,
        "Tier2Buckets",
        dbConfig.baseReadCapacity,
        dbConfig.baseWriteCapacity,
        maxCapacity,
        targetUtilization,
      );
      this.enableAutoScaling(
        this.sessionCacheTable,
        "SessionCache",
        dbConfig.baseReadCapacity,
        dbConfig.baseWriteCapacity,
        maxCapacity,
        targetUtilization,
      );
      this.enableAutoScaling(
        this.sessionPayloadTable,
        "SessionPayload",
        dbConfig.baseReadCapacity,
        dbConfig.baseWriteCapacity,
        maxCapacity,
        targetUtilization,
      );
    }

    // Alarms
    this.createTableAlarms(this.profilesTable, "Profiles", alarmsTopic);
    this.createTableAlarms(this.tier1IndexTable, "Tier1Index", alarmsTopic);
    this.createTableAlarms(this.tier2BucketsTable, "Tier2Buckets", alarmsTopic);
    this.createTableAlarms(this.sessionCacheTable, "SessionCache", alarmsTopic);
    this.createTableAlarms(
      this.sessionPayloadTable,
      "SessionPayload",
      alarmsTopic,
    );
  }

  /**
   * AR-133: Enable auto-scaling for a DynamoDB table
   * Configures both read and write capacity auto-scaling with the specified parameters
   */
  private enableAutoScaling(
    table: dynamodb.Table,
    prefix: string,
    minReadCapacity: number,
    minWriteCapacity: number,
    maxCapacity: number,
    targetUtilizationPercent: number,
  ) {
    // Auto-scale read capacity
    const readScaling = table.autoScaleReadCapacity({
      minCapacity: minReadCapacity,
      maxCapacity,
    });
    readScaling.scaleOnUtilization({
      targetUtilizationPercent,
    });

    // Auto-scale write capacity
    const writeScaling = table.autoScaleWriteCapacity({
      minCapacity: minWriteCapacity,
      maxCapacity,
    });
    writeScaling.scaleOnUtilization({
      targetUtilizationPercent,
    });
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
