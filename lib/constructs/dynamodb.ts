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
 *  - integrityResultsTable: per-session integrity record (PK: session_id),
 *    stream-enabled for archiving to S3. 1-hour TTL.
 *  - signalBaselinesTable: learned population frequencies per browser version
 *    (PK: browser_key, SK: module). No TTL — permanent ground truth.
 *
 * Profiles / tier1-index / tier2-buckets / session-cache / session-payload /
 * vector-results were removed along with the fingerprint matching pipeline.
 */
export class DynamoDbConstruct extends Construct {
  public readonly integrityResultsTable: dynamodb.Table;
  public readonly signalBaselinesTable: dynamodb.Table;

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

    this.integrityResultsTable = new dynamodb.Table(
      this,
      "IntegrityResultsTable",
      {
        tableName: `${stackName}-integrity-results`,
        partitionKey: {
          name: "session_id",
          type: dynamodb.AttributeType.STRING,
        },
        billingMode,
        ...capacityProps,
        timeToLiveAttribute: "ttl",
        removalPolicy: RemovalPolicy.DESTROY,
        stream: dynamodb.StreamViewType.NEW_IMAGE,
      },
    );

    this.signalBaselinesTable = new dynamodb.Table(
      this,
      "SignalBaselinesTable",
      {
        tableName: `${stackName}-signal-baselines`,
        partitionKey: {
          name: "browser_key",
          type: dynamodb.AttributeType.STRING,
        },
        sortKey: {
          name: "module",
          type: dynamodb.AttributeType.STRING,
        },
        billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
        pointInTimeRecovery: true,
        removalPolicy: RemovalPolicy.DESTROY,
      },
    );

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
      this.createTableAlarms(
        this.signalBaselinesTable,
        "SignalBaselines",
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
