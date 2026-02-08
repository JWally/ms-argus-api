// lib/constructs/postgres.ts
// RDS PostgreSQL for SimHash-based T1/T1.5 matching
// Collapses ~19 DynamoDB round-trips into a single SQL query using bit_count(hash1 # hash2)
import { Construct } from "constructs";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as rds from "aws-cdk-lib/aws-rds";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { Duration, CfnOutput, RemovalPolicy } from "aws-cdk-lib";
import { StageConfig, isProdStage } from "../config";

interface PostgresConstructProps {
  stackName: string;
  stage: string;
  stageConfig: StageConfig;
  alarmsTopic: sns.ITopic;
  /** VPC where PostgreSQL will be deployed */
  vpc: ec2.IVpc;
  /** Security group for Lambda functions that need PostgreSQL access */
  lambdaSecurityGroup: ec2.ISecurityGroup;
}

/**
 * RDS PostgreSQL instance for SimHash-based fingerprint matching
 *
 * Enables efficient T1/T1.5 matching by storing SimHash values in PostgreSQL
 * and using native bit_count(hash1 # hash2) for Hamming distance computation.
 * Band columns serve as index-backed pre-filters for LSH queries.
 */
export class PostgresConstruct extends Construct {
  public readonly endpoint: string;
  public readonly port: string;
  public readonly databaseName: string;
  public readonly secret: secretsmanager.ISecret;
  public readonly securityGroup: ec2.SecurityGroup;

  constructor(scope: Construct, id: string, props: PostgresConstructProps) {
    super(scope, id);

    const {
      stackName,
      stage,
      stageConfig,
      alarmsTopic,
      vpc,
      lambdaSecurityGroup,
    } = props;

    const isProd = isProdStage(stage);

    // =========================================================================
    // SECURITY GROUP
    // =========================================================================

    this.securityGroup = new ec2.SecurityGroup(this, "PostgresSecurityGroup", {
      vpc,
      securityGroupName: `${stackName}-postgres-sg`,
      description: "Security group for RDS PostgreSQL",
      allowAllOutbound: false, // RDS doesn't need outbound
    });

    // Allow Lambda to connect to PostgreSQL on port 5432
    this.securityGroup.addIngressRule(
      lambdaSecurityGroup,
      ec2.Port.tcp(5432),
      "Allow Lambda access to PostgreSQL",
    );

    // =========================================================================
    // SUBNET GROUP
    // =========================================================================

    const subnetGroup = new rds.SubnetGroup(this, "PostgresSubnetGroup", {
      vpc,
      description: `Subnet group for ${stackName} PostgreSQL`,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      },
    });

    // =========================================================================
    // RDS POSTGRESQL INSTANCE
    // =========================================================================

    this.databaseName = "argus";

    const instance = new rds.DatabaseInstance(this, "PostgresInstance", {
      engine: rds.DatabaseInstanceEngine.postgres({
        version: rds.PostgresEngineVersion.VER_16,
      }),
      instanceIdentifier: `${stackName}-postgres`,
      instanceType: ec2.InstanceType.of(
        ec2.InstanceClass.T4G,
        stageConfig.rds.instanceClass,
      ),
      vpc,
      subnetGroup,
      securityGroups: [this.securityGroup],
      databaseName: this.databaseName,
      // Credentials auto-generated and stored in Secrets Manager
      credentials: rds.Credentials.fromGeneratedSecret("argus_admin"),
      // Storage
      allocatedStorage: stageConfig.rds.allocatedStorageGb,
      maxAllocatedStorage: stageConfig.rds.maxAllocatedStorageGb,
      storageEncrypted: true,
      // Availability & durability
      multiAz: stageConfig.rds.multiAz,
      deletionProtection: stageConfig.rds.deletionProtection,
      backupRetention: Duration.days(stageConfig.rds.backupRetentionDays),
      removalPolicy: isProd ? RemovalPolicy.RETAIN : RemovalPolicy.SNAPSHOT,
    });

    this.endpoint = instance.dbInstanceEndpointAddress;
    this.port = instance.dbInstanceEndpointPort;
    const secret = instance.secret;
    if (!secret) throw new Error("RDS instance missing auto-generated secret");
    this.secret = secret;

    // =========================================================================
    // CLOUDWATCH ALARMS
    // =========================================================================

    this.createAlarms(stackName, instance, alarmsTopic);

    // =========================================================================
    // OUTPUTS
    // =========================================================================

    new CfnOutput(this, "PostgresEndpoint", {
      value: this.endpoint,
      description: "RDS PostgreSQL endpoint",
    });

    new CfnOutput(this, "PostgresSecretArn", {
      value: this.secret.secretArn,
      description: "RDS PostgreSQL credentials secret ARN",
    });
  }

  private createAlarms(
    stackName: string,
    instance: rds.DatabaseInstance,
    alarmsTopic: sns.ITopic,
  ): void {
    // 1. CPU > 80%
    const cpuAlarm = new cloudwatch.Alarm(this, "PostgresCpuHigh", {
      alarmName: `${stackName}-postgres-cpu-high`,
      alarmDescription: "PostgreSQL CPU utilization > 80%",
      metric: instance.metricCPUUtilization({
        statistic: "Average",
        period: Duration.minutes(5),
      }),
      threshold: 80,
      evaluationPeriods: 3,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    cpuAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // 2. Freeable memory < 200MB
    const memoryAlarm = new cloudwatch.Alarm(this, "PostgresMemoryLow", {
      alarmName: `${stackName}-postgres-memory-low`,
      alarmDescription: "PostgreSQL freeable memory < 200MB",
      metric: instance.metricFreeableMemory({
        statistic: "Average",
        period: Duration.minutes(5),
      }),
      // 200MB in bytes
      threshold: 200 * 1024 * 1024,
      evaluationPeriods: 3,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    memoryAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // 3. Free storage < 2GB
    const storageAlarm = new cloudwatch.Alarm(this, "PostgresStorageLow", {
      alarmName: `${stackName}-postgres-storage-low`,
      alarmDescription: "PostgreSQL free storage < 2GB",
      metric: instance.metricFreeStorageSpace({
        statistic: "Average",
        period: Duration.minutes(5),
      }),
      // 2GB in bytes
      threshold: 2 * 1024 * 1024 * 1024,
      evaluationPeriods: 3,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    storageAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // 4. Database connections > 70
    const connectionAlarm = new cloudwatch.Alarm(
      this,
      "PostgresConnectionsHigh",
      {
        alarmName: `${stackName}-postgres-connections-high`,
        alarmDescription: "PostgreSQL database connections > 70",
        metric: instance.metric("DatabaseConnections", {
          statistic: "Average",
          period: Duration.minutes(5),
        }),
        threshold: 70,
        evaluationPeriods: 3,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      },
    );
    connectionAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }
}
