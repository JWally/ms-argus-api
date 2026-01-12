// lib/constructs/redis.ts
// AR-44: Uses centralized stage config for environment-specific values
import { Construct } from "constructs";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as elasticache from "aws-cdk-lib/aws-elasticache";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import { Duration, RemovalPolicy } from "aws-cdk-lib";
import { getStageConfig } from "../config";

interface RedisConstructProps {
  stackName: string;
  vpc: ec2.IVpc;
  alarmsTopic: sns.ITopic;
  stage: string; // 'dev', 'staging', 'prod' - affects instance size
}

/**
 * Redis ElastiCache cluster for session cache
 * Provisioned r6g.large with 2 nodes for HA
 */
export class RedisConstruct extends Construct {
  public readonly cluster: elasticache.CfnReplicationGroup;
  public readonly securityGroup: ec2.SecurityGroup;
  public readonly endpoint: string;
  public readonly port: number = 6379;

  constructor(scope: Construct, id: string, props: RedisConstructProps) {
    super(scope, id);

    const { stackName, vpc, alarmsTopic, stage } = props;

    // AR-44: Use centralized stage config for all tunable values
    const config = getStageConfig(stage);
    const { nodeType, numNodes, multiAz, snapshotRetentionDays } = config.redis;

    // AR-46: Custom parameter group with volatile-lru eviction policy
    // Default policy may be noeviction which causes OOM errors instead of evicting
    const parameterGroup = new elasticache.CfnParameterGroup(
      this,
      "RedisParameterGroup",
      {
        cacheParameterGroupFamily: "redis7",
        description: `Argus Redis parameters (${stage})`,
        properties: {
          // Evict least-recently-used keys that have TTL when memory is full
          // All our keys have TTL, so this ensures graceful degradation under load
          "maxmemory-policy": "volatile-lru",
        },
      },
    );

    // Security group for Redis
    this.securityGroup = new ec2.SecurityGroup(this, "RedisSecurityGroup", {
      vpc,
      description: "Security group for Argus Redis cluster",
      allowAllOutbound: false,
    });

    // Subnet group for Redis (use private subnets)
    const subnetGroup = new elasticache.CfnSubnetGroup(
      this,
      "RedisSubnetGroup",
      {
        description: "Subnet group for Argus Redis",
        subnetIds: vpc.privateSubnets.map((subnet) => subnet.subnetId),
        cacheSubnetGroupName: `${stackName}-redis-subnets`,
      },
    );

    // Redis replication group
    // Dev/staging: single node with 1GB (fast spin up/down, adequate for testing)
    // Prod: 2 nodes with HA
    this.cluster = new elasticache.CfnReplicationGroup(this, "RedisCluster", {
      replicationGroupDescription: `Argus session cache (${stage})`,
      replicationGroupId: `${stackName}-redis`,
      engine: "redis",
      engineVersion: "7.1",
      cacheNodeType: nodeType,
      numCacheClusters: numNodes,
      automaticFailoverEnabled: multiAz,
      multiAzEnabled: multiAz,
      cacheSubnetGroupName: subnetGroup.cacheSubnetGroupName,
      securityGroupIds: [this.securityGroup.securityGroupId],
      // AR-46: Use custom parameter group with volatile-lru eviction
      cacheParameterGroupName: parameterGroup.ref,
      atRestEncryptionEnabled: true,
      transitEncryptionEnabled: true,
      port: this.port,
      // Snapshot for recovery - AR-44: retention from config
      snapshotRetentionLimit: snapshotRetentionDays,
      snapshotWindow: "03:00-04:00",
      preferredMaintenanceWindow: "sun:04:00-sun:05:00",
    });

    this.cluster.node.addDependency(subnetGroup);
    this.cluster.node.addDependency(parameterGroup);
    this.cluster.applyRemovalPolicy(RemovalPolicy.RETAIN);

    // Primary endpoint
    this.endpoint = this.cluster.attrPrimaryEndPointAddress;

    // Alarms - AR-44: Pass config for thresholds
    this.createRedisAlarms(stackName, alarmsTopic, config.alarms.redis);
  }

  private createRedisAlarms(
    stackName: string,
    alarmsTopic: sns.ITopic,
    alarmConfig: {
      memoryWarningPercent: number;
      memoryCriticalPercent: number;
      cpuThreshold: number;
      evictionsThreshold: number;
    },
  ) {
    // CPU utilization alarm - AR-44: threshold from config
    const cpuAlarm = new cloudwatch.Alarm(this, "RedisCPUAlarm", {
      metric: new cloudwatch.Metric({
        namespace: "AWS/ElastiCache",
        metricName: "CPUUtilization",
        dimensionsMap: {
          ReplicationGroupId: `${stackName}-redis`,
        },
        period: Duration.minutes(5),
        statistic: "Average",
      }),
      threshold: alarmConfig.cpuThreshold,
      evaluationPeriods: 3,
      alarmDescription: `Redis CPU > ${alarmConfig.cpuThreshold}% for 15 minutes`,
    });
    cpuAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Early warning memory alarm - AR-44: threshold from config
    const memoryWarningAlarm = new cloudwatch.Alarm(
      this,
      "RedisMemoryWarningAlarm",
      {
        metric: new cloudwatch.Metric({
          namespace: "AWS/ElastiCache",
          metricName: "DatabaseMemoryUsagePercentage",
          dimensionsMap: {
            ReplicationGroupId: `${stackName}-redis`,
          },
          period: Duration.minutes(5),
          statistic: "Average",
        }),
        threshold: alarmConfig.memoryWarningPercent,
        evaluationPeriods: 2,
        alarmDescription: `Redis memory > ${alarmConfig.memoryWarningPercent}% for 10 minutes - consider scaling or investigating`,
      },
    );
    memoryWarningAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Critical memory alarm - AR-44: threshold from config
    const memoryAlarm = new cloudwatch.Alarm(this, "RedisMemoryAlarm", {
      metric: new cloudwatch.Metric({
        namespace: "AWS/ElastiCache",
        metricName: "DatabaseMemoryUsagePercentage",
        dimensionsMap: {
          ReplicationGroupId: `${stackName}-redis`,
        },
        period: Duration.minutes(5),
        statistic: "Average",
      }),
      threshold: alarmConfig.memoryCriticalPercent,
      evaluationPeriods: 3,
      alarmDescription: `Redis memory > ${alarmConfig.memoryCriticalPercent}% for 15 minutes - critical`,
    });
    memoryAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Evictions alarm - AR-44: threshold from config
    const evictionsAlarm = new cloudwatch.Alarm(this, "RedisEvictionsAlarm", {
      metric: new cloudwatch.Metric({
        namespace: "AWS/ElastiCache",
        metricName: "Evictions",
        dimensionsMap: {
          ReplicationGroupId: `${stackName}-redis`,
        },
        period: Duration.minutes(5),
        statistic: "Sum",
      }),
      threshold: alarmConfig.evictionsThreshold,
      evaluationPeriods: 2,
      alarmDescription: `Redis evicting > ${alarmConfig.evictionsThreshold} keys - memory pressure`,
    });
    evictionsAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }

  /**
   * Allow inbound Redis connections from a security group
   */
  public allowFrom(securityGroup: ec2.ISecurityGroup, description: string) {
    this.securityGroup.addIngressRule(
      securityGroup,
      ec2.Port.tcp(this.port),
      description,
    );
  }
}
