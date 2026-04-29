// lib/constructs/dynamodb.ts

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
 * DynamoDB tables for the integrity-only pipeline.
 *
 *  - integrityResultsTable: per-session integrity record. Composite key
 *    `(cpi, session_id)` so reads tied to a merchant's public client-id
 *    are partitioned at the storage layer — cross-tenant scans cannot
 *    succeed even on a stolen key for a different cpi. 1-hour TTL.
 *    Archive to S3 happens at write time via Firehose (ingestion handler
 *    dual-writes); no DDB stream needed.
 *
 *    GSI `legacySessionIdIndex` exists temporarily so the deprecated
 *    `GET /v1/integrity-session/{session_id}` route (single shared-secret
 *    auth, internal callers only) can still resolve a session by id alone
 *    during migration. Drop the GSI when ENABLE_LEGACY_SHARED_SECRET is
 *    flipped to false everywhere — search for LEGACY_SHARED_SECRET_AUTH.
 *
 * Profiles / tier1-index / tier2-buckets / session-cache / session-payload /
 * vector-results were removed along with the fingerprint matching pipeline.
 */
export class DynamoDbConstruct extends Construct {
  public readonly integrityResultsTable: dynamodb.Table;

  constructor(scope: Construct, id: string, props: DynamoDbConstructProps) {
    super(scope, id);

    const { stackName, alarmsTopic, stage } = props;

    const config = getStageConfig(stage);
    const dbConfig = config.dynamodb;

    const billingMode = dbConfig.useProvisionedCapacity
      ? dynamodb.BillingMode.PROVISIONED
      : dynamodb.BillingMode.PAY_PER_REQUEST;

    const capacityProps = dbConfig.useProvisionedCapacity
      ? {
          readCapacity: dbConfig.baseReadCapacity,
          writeCapacity: dbConfig.baseWriteCapacity,
        }
      : {};

    // `-v2` suffix: the schema change from PK `session_id` → composite
    // (cpi, session_id) requires CFN replacement, which custom-named
    // resources can't do in place. The old `${stackName}-integrity-results`
    // table is dropped on first v2 deploy.
    this.integrityResultsTable = new dynamodb.Table(
      this,
      "IntegrityResultsTable",
      {
        tableName: `${stackName}-integrity-results-v2`,
        partitionKey: {
          name: "cpi",
          type: dynamodb.AttributeType.STRING,
        },
        sortKey: {
          name: "session_id",
          type: dynamodb.AttributeType.STRING,
        },
        billingMode,
        ...capacityProps,
        timeToLiveAttribute: "ttl",
        removalPolicy: RemovalPolicy.DESTROY,
      },
    );

    // LEGACY_SHARED_SECRET_AUTH: drop alongside the deprecated route.
    this.integrityResultsTable.addGlobalSecondaryIndex({
      indexName: "legacySessionIdIndex",
      partitionKey: {
        name: "session_id",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    if (dbConfig.useProvisionedCapacity) {
      const maxCapacity = Math.ceil(
        dbConfig.baseReadCapacity * dbConfig.autoScaling.maxCapacityMultiplier,
      );
      const targetUtilization = dbConfig.autoScaling.targetUtilizationPercent;
      this.enableAutoScaling(
        this.integrityResultsTable,
        dbConfig.baseReadCapacity,
        dbConfig.baseWriteCapacity,
        maxCapacity,
        targetUtilization,
      );
    }

    if (config.alarms.enabled) {
      this.createTableAlarms(
        this.integrityResultsTable,
        "IntegrityResults",
        alarmsTopic,
      );
    }
  }

  private enableAutoScaling(
    table: dynamodb.Table,
    minReadCapacity: number,
    minWriteCapacity: number,
    maxCapacity: number,
    targetUtilizationPercent: number,
  ) {
    const readScaling = table.autoScaleReadCapacity({
      minCapacity: minReadCapacity,
      maxCapacity,
    });
    readScaling.scaleOnUtilization({ targetUtilizationPercent });

    const writeScaling = table.autoScaleWriteCapacity({
      minCapacity: minWriteCapacity,
      maxCapacity,
    });
    writeScaling.scaleOnUtilization({ targetUtilizationPercent });
  }

  private createTableAlarms(
    table: dynamodb.Table,
    prefix: string,
    alarmsTopic: sns.ITopic,
  ) {
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
