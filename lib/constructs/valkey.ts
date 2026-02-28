// lib/constructs/valkey.ts
// ElastiCache Serverless (Valkey mode) for statistical anomaly detection
// Tracks ua_family::ja4 combo frequencies using HyperLogLog
import { Construct } from "constructs";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as elasticache from "aws-cdk-lib/aws-elasticache";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import { Duration, CfnOutput } from "aws-cdk-lib";
import { StageConfig } from "../config";

interface ValkeyConstructProps {
  stackName: string;
  stage: string;
  stageConfig: StageConfig;
  alarmsTopic: sns.ITopic;
  /** VPC where Valkey will be deployed */
  vpc: ec2.IVpc;
  /** Security group for Lambda functions that need Valkey access */
  lambdaSecurityGroup: ec2.ISecurityGroup;
}

/**
 * ElastiCache Serverless (Valkey mode) for statistical anomaly detection
 *
 * Provides a Redis-compatible cache for tracking fingerprint combo frequencies.
 * Uses HyperLogLog for cardinality estimation and atomic counters for frequency tracking.
 *
 * Key schema:
 * - ua:{ua_family}:total - Total requests for UA family
 * - ua:{ua_family}:ja4:{ja4} - Requests for specific UA+JA4 combo
 * - ua:{ua_family}:distinct - HyperLogLog of distinct JA4 values for UA family
 */
export class ValkeyConstruct extends Construct {
  public readonly endpoint: string;
  public readonly securityGroup: ec2.SecurityGroup;

  constructor(scope: Construct, id: string, props: ValkeyConstructProps) {
    super(scope, id);

    const {
      stackName,
      stage,
      stageConfig,
      alarmsTopic,
      vpc,
      lambdaSecurityGroup,
    } = props;

    // =========================================================================
    // SECURITY GROUP
    // =========================================================================

    // Security group for ElastiCache Serverless
    this.securityGroup = new ec2.SecurityGroup(this, "ValkeySecurityGroup", {
      vpc,
      securityGroupName: `${stackName}-valkey-sg`,
      description: "Security group for ElastiCache Serverless (Valkey)",
      allowAllOutbound: false, // ElastiCache doesn't need outbound
    });

    // Allow Lambda to connect to Valkey on port 6379
    this.securityGroup.addIngressRule(
      lambdaSecurityGroup,
      ec2.Port.tcp(6379),
      "Allow Lambda access to Valkey",
    );

    // =========================================================================
    // SUBNET GROUP
    // =========================================================================

    // Get private subnet IDs for ElastiCache
    const privateSubnets = vpc.selectSubnets({
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    });

    // =========================================================================
    // ELASTICACHE SERVERLESS (VALKEY)
    // =========================================================================

    // ElastiCache Serverless with Valkey engine
    const serverlessCache = new elasticache.CfnServerlessCache(
      this,
      "ValkeyServerless",
      {
        serverlessCacheName: `${stackName}-valkey`,
        engine: "valkey",
        // Major version for Valkey (Redis-compatible)
        majorEngineVersion: "7",
        // Capacity limits (billing is based on actual usage within these limits)
        cacheUsageLimits: {
          dataStorage: {
            maximum: stageConfig.valkey.maxDataStorageGiB,
            unit: "GB",
          },
          ecpuPerSecond: {
            // ECPU limits: dev gets lower, prod gets higher
            // 1000 ECPU/s is roughly enough for 1000 simple commands/s
            maximum: stage === "prod" ? 5000 : 1000,
          },
        },
        // Security configuration
        securityGroupIds: [this.securityGroup.securityGroupId],
        subnetIds: privateSubnets.subnetIds,
        // No snapshot for cost savings (data is ephemeral statistics)
        dailySnapshotTime: undefined,
        snapshotRetentionLimit: 0,
        description: `Valkey cache for ${stackName} statistical anomaly detection`,
      },
    );

    // Extract endpoint from the serverless cache
    // ElastiCache Serverless provides a single endpoint for all operations
    this.endpoint = serverlessCache.attrEndpointAddress;

    // =========================================================================
    // CLOUDWATCH ALARMS
    // =========================================================================

    const cacheName = serverlessCache.serverlessCacheName;
    if (!cacheName) throw new Error("Serverless cache missing name");
    if (stageConfig.alarms.enabled) {
      this.createAlarms(stackName, cacheName, alarmsTopic);
    }

    // =========================================================================
    // OUTPUTS
    // =========================================================================

    new CfnOutput(this, "ValkeyEndpoint", {
      value: this.endpoint,
      description: "ElastiCache Serverless (Valkey) endpoint",
    });
  }

  private createAlarms(
    stackName: string,
    cacheName: string,
    alarmsTopic: sns.ITopic,
  ): void {
    const ELASTICACHE_NS = "AWS/ElastiCache";

    // 1. High CPU utilization alarm
    const cpuAlarm = new cloudwatch.Alarm(this, "ValkeyCpuHigh", {
      alarmName: `${stackName}-valkey-cpu-high`,
      alarmDescription: "Valkey CPU utilization > 80%",
      metric: new cloudwatch.Metric({
        namespace: ELASTICACHE_NS,
        metricName: "CPUUtilization",
        dimensionsMap: {
          CacheClusterId: cacheName,
        },
        statistic: "Average",
        period: Duration.minutes(5),
      }),
      threshold: 80,
      evaluationPeriods: 3,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    cpuAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // 2. Memory utilization alarm (approaching limit)
    const memoryAlarm = new cloudwatch.Alarm(this, "ValkeyMemoryHigh", {
      alarmName: `${stackName}-valkey-memory-high`,
      alarmDescription: "Valkey memory utilization > 80%",
      metric: new cloudwatch.Metric({
        namespace: ELASTICACHE_NS,
        metricName: "DatabaseMemoryUsagePercentage",
        dimensionsMap: {
          CacheClusterId: cacheName,
        },
        statistic: "Average",
        period: Duration.minutes(5),
      }),
      threshold: 80,
      evaluationPeriods: 3,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    memoryAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // 3. Connection errors alarm
    const connectionErrorAlarm = new cloudwatch.Alarm(
      this,
      "ValkeyConnectionErrors",
      {
        alarmName: `${stackName}-valkey-connection-errors`,
        alarmDescription: "Valkey connection errors detected",
        metric: new cloudwatch.Metric({
          namespace: ELASTICACHE_NS,
          metricName: "CurrConnections",
          dimensionsMap: {
            CacheClusterId: cacheName,
          },
          statistic: "Sum",
          period: Duration.minutes(5),
        }),
        // Alert if connections drop to 0 (indicates connectivity issues)
        threshold: 0,
        evaluationPeriods: 2,
        comparisonOperator:
          cloudwatch.ComparisonOperator.LESS_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.BREACHING,
      },
    );
    connectionErrorAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // 4. ECPU throttling alarm (hitting capacity limits)
    const throttleAlarm = new cloudwatch.Alarm(this, "ValkeyThrottled", {
      alarmName: `${stackName}-valkey-throttled`,
      alarmDescription:
        "Valkey ECPU throttling detected - consider increasing limits",
      metric: new cloudwatch.Metric({
        namespace: ELASTICACHE_NS,
        metricName: "ThrottledCmds",
        dimensionsMap: {
          CacheClusterId: cacheName,
        },
        statistic: "Sum",
        period: Duration.minutes(5),
      }),
      threshold: 0,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    throttleAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }
}
