// lib/constructs/redis.ts
import { Construct } from "constructs";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as elasticache from "aws-cdk-lib/aws-elasticache";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import { Duration, RemovalPolicy } from "aws-cdk-lib";

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

    // AR-46: Use t4g.small for dev (1GB) - t4g.micro (512MB) is too small
    // Production gets medium instances with HA (AR-38: right-sized from large)
    const isProd = stage === "prod";
    const nodeType = isProd ? "cache.r6g.medium" : "cache.t4g.small";
    const numNodes = isProd ? 2 : 1; // No HA for dev/staging
    const multiAz = isProd;

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
      // Snapshot for recovery
      snapshotRetentionLimit: 7,
      snapshotWindow: "03:00-04:00",
      preferredMaintenanceWindow: "sun:04:00-sun:05:00",
    });

    this.cluster.node.addDependency(subnetGroup);
    this.cluster.node.addDependency(parameterGroup);
    this.cluster.applyRemovalPolicy(RemovalPolicy.RETAIN);

    // Primary endpoint
    this.endpoint = this.cluster.attrPrimaryEndPointAddress;

    // Alarms
    this.createRedisAlarms(stackName, alarmsTopic);
  }

  private createRedisAlarms(stackName: string, alarmsTopic: sns.ITopic) {
    // CPU utilization alarm
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
      threshold: 80,
      evaluationPeriods: 3,
      alarmDescription: "Redis CPU > 80% for 15 minutes",
    });
    cpuAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // AR-46: Early warning memory alarm at 70%
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
        threshold: 70,
        evaluationPeriods: 2,
        alarmDescription:
          "Redis memory > 70% for 10 minutes - consider scaling or investigating",
      },
    );
    memoryWarningAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Critical memory alarm at 80%
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
      threshold: 80,
      evaluationPeriods: 3,
      alarmDescription: "Redis memory > 80% for 15 minutes - critical",
    });
    memoryAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Evictions alarm (indicates memory pressure)
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
      threshold: 100,
      evaluationPeriods: 2,
      alarmDescription: "Redis evicting keys - memory pressure",
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
