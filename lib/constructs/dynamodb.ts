// lib/constructs/dynamodb.ts

import { Construct } from "constructs";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import { RemovalPolicy } from "aws-cdk-lib";
import { getStageConfig } from "../config";

interface DynamoDbConstructProps {
  stackName: string;
  stage: string;
}

/**
 * API-owned DynamoDB tables.
 *
 * Shared integrity results are owned by ms-argus-data and imported by the
 * application stack. Only API-private operational state belongs here.
 */
export class DynamoDbConstruct extends Construct {
  public readonly ipVelocityTable: dynamodb.Table;

  constructor(scope: Construct, id: string, props: DynamoDbConstructProps) {
    super(scope, id);

    const { stackName, stage } = props;

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

    // IP velocity table — hourly buckets per IP. Each row holds a
    // running counter (hits, blocked) + an HLL of device pubkeys seen
    // on that IP in that hour. PK is `ip`, SK is `bucket` ("1h:YYYYMMDDHH").
    // Bucket rows expire after 7 days via TTL so the table self-prunes.
    // Reads at dashboard time: stamp the ALL_NEW return from the per-
    // session UpdateItem onto the integrity row, so the recent-sessions
    // list shows IP context without an extra GetItem per row.
    this.ipVelocityTable = new dynamodb.Table(this, "IpVelocityTable", {
      tableName: `${stackName}-ip-velocity`,
      partitionKey: { name: "ip", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "bucket", type: dynamodb.AttributeType.STRING },
      billingMode,
      ...capacityProps,
      timeToLiveAttribute: "ttl",
      removalPolicy: RemovalPolicy.DESTROY,
    });

    if (dbConfig.useProvisionedCapacity) {
      const maxCapacity = Math.ceil(
        dbConfig.baseReadCapacity * dbConfig.autoScaling.maxCapacityMultiplier,
      );
      this.enableAutoScaling(
        this.ipVelocityTable,
        dbConfig.baseReadCapacity,
        dbConfig.baseWriteCapacity,
        maxCapacity,
        dbConfig.autoScaling.targetUtilizationPercent,
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
}
