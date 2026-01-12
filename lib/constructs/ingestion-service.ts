// lib/constructs/ingestion-service.ts
// AR-44: Uses centralized stage config for environment-specific values
import * as path from "path";
import { Construct } from "constructs";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecs from "aws-cdk-lib/aws-ecs";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as logs from "aws-cdk-lib/aws-logs";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { Duration, RemovalPolicy } from "aws-cdk-lib";
import { getStageConfig } from "../config";

interface IngestionServiceProps {
  stackName: string;
  vpc: ec2.IVpc;
  matchingQueue: sqs.IQueue;
  alarmsTopic: sns.ITopic;
  stage: string;
  secret: secretsmanager.ISecret;
}

/**
 * Go Ingestion Service on ECS Fargate behind ALB
 * Ultra-thin handler: validate -> SQS -> 204
 */
export class IngestionServiceConstruct extends Construct {
  public readonly cluster: ecs.Cluster;
  public readonly service: ecs.FargateService;
  public readonly loadBalancer: elbv2.ApplicationLoadBalancer;
  public readonly securityGroup: ec2.SecurityGroup;
  public readonly listener: elbv2.ApplicationListener;

  constructor(scope: Construct, id: string, props: IngestionServiceProps) {
    super(scope, id);

    const { stackName, vpc, matchingQueue, alarmsTopic, stage, secret } = props;

    // AR-44: Use centralized stage config for all tunable values
    const config = getStageConfig(stage);

    // Security group for the service
    this.securityGroup = new ec2.SecurityGroup(this, "ServiceSecurityGroup", {
      vpc,
      description: "Security group for Argus ingestion service",
      allowAllOutbound: true,
    });

    // ECS Cluster - let CDK generate name to avoid collisions
    this.cluster = new ecs.Cluster(this, "Cluster", {
      vpc,
      containerInsights: true,
    });

    // CloudWatch log group
    const logGroup = new logs.LogGroup(this, "LogGroup", {
      logGroupName: `/ecs/${stackName}-ingestion`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // Task definition - AR-44: Use stage config for sizing
    const taskDefinition = new ecs.FargateTaskDefinition(this, "TaskDef", {
      memoryLimitMiB: config.ecs.memoryMiB,
      cpu: config.ecs.cpu,
      runtimePlatform: {
        cpuArchitecture: ecs.CpuArchitecture.ARM64,
        operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
      },
    });

    // Build container image from local Dockerfile
    // CDK will build and push to ECR automatically
    const ingestionImage = ecs.ContainerImage.fromAsset(
      path.join(__dirname, "../../cmd/ingestion"),
    );

    // Container definition with built image
    taskDefinition.addContainer("ingestion", {
      image: ingestionImage,
      containerName: "ingestion",
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: "ingestion",
        logGroup,
      }),
      environment: {
        ENVIRONMENT: stage,
        SQS_QUEUE_URL: matchingQueue.queueUrl,
        LOG_LEVEL: "info",
      },
      secrets: {
        HMAC_KEY: ecs.Secret.fromSecretsManager(secret, "HMAC_KEY"),
      },
      portMappings: [
        {
          containerPort: 8080,
          protocol: ecs.Protocol.TCP,
        },
      ],
      // NOTE: Removed container-level healthCheck.
      // Relying ONLY on ALB target group health checks.
      // Container health checks cause tasks to be marked unhealthy
      // even when ALB health checks pass (ARM64 wget timing issue).
    });

    // Grant SQS send permissions
    matchingQueue.grantSendMessages(taskDefinition.taskRole);

    // Grant secrets read
    secret.grantRead(taskDefinition.taskRole);

    // Application Load Balancer (create first for target group)
    // ALB names max 32 chars, so use abbreviated name
    const albName = `${stackName.slice(0, 20)}-ingest-alb`;
    // ALB Security group - allow HTTP inbound, allow outbound to targets
    const albSecurityGroup = new ec2.SecurityGroup(this, "ALBSecurityGroup", {
      vpc,
      description: "Security group for ingestion ALB",
      allowAllOutbound: true, // Required for health checks to reach targets
    });

    // Allow HTTP traffic ONLY from CloudFront edge locations
    // Using AWS-managed prefix list to prevent WAF bypass via direct ALB access
    // Prefix list com.amazonaws.global.cloudfront.origin-facing contains all CF edge IPs
    const cloudfrontPrefixList = ec2.Peer.prefixList(
      ec2.PrefixList.fromLookup(this, "CloudFrontPrefixList", {
        prefixListName: "com.amazonaws.global.cloudfront.origin-facing",
      }).prefixListId,
    );
    albSecurityGroup.addIngressRule(
      cloudfrontPrefixList,
      ec2.Port.tcp(80),
      "Allow HTTP only from CloudFront edge locations",
    );

    this.loadBalancer = new elbv2.ApplicationLoadBalancer(this, "ALB", {
      vpc,
      internetFacing: true,
      loadBalancerName: albName,
      securityGroup: albSecurityGroup,
    });

    // HTTP listener (HTTPS terminated at CloudFront)
    // open: false prevents CDK from auto-adding 0.0.0.0/0 ingress rule
    // We use CloudFront prefix list instead (see above) to prevent WAF bypass
    this.listener = this.loadBalancer.addListener("HttpListener", {
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
      open: false,
    });

    // Fargate service - AR-44: Use stage config for desired count
    this.service = new ecs.FargateService(this, "Service", {
      cluster: this.cluster,
      taskDefinition,
      desiredCount: config.ecs.desiredCount,
      minHealthyPercent: 100,
      maxHealthyPercent: 200,
      // Let CDK generate service name to avoid collisions on redeploy
      securityGroups: [this.securityGroup],
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      circuitBreaker: { rollback: true },
      enableExecuteCommand: true, // For debugging
      healthCheckGracePeriod: Duration.seconds(120), // Allow time for ALB target registration
    });

    // Allow ALB to reach the service
    this.securityGroup.addIngressRule(
      this.loadBalancer.connections.securityGroups[0],
      ec2.Port.tcp(8080),
      "Allow ALB to reach service",
    );

    // Add service to ALB target group
    const targetGroup = this.listener.addTargets("ServiceTarget", {
      port: 8080,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targets: [this.service],
      healthCheck: {
        path: "/health",
        interval: Duration.seconds(30),
        timeout: Duration.seconds(5),
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 3,
        healthyHttpCodes: "200",
      },
      deregistrationDelay: Duration.seconds(30),
    });

    // Auto-scaling - AR-44: Use stage config for capacity limits
    const scaling = this.service.autoScaleTaskCount({
      minCapacity: config.ecs.minCapacity,
      maxCapacity: config.ecs.maxCapacity,
    });

    scaling.scaleOnCpuUtilization("CpuScaling", {
      targetUtilizationPercent: config.ecs.cpuScalingThreshold,
      scaleInCooldown: Duration.seconds(60),
      scaleOutCooldown: Duration.seconds(30),
    });

    scaling.scaleOnRequestCount("RequestScaling", {
      targetGroup,
      requestsPerTarget: config.ecs.requestsPerTarget,
      scaleInCooldown: Duration.seconds(60),
      scaleOutCooldown: Duration.seconds(30),
    });

    // Alarms - AR-44: Pass config for thresholds
    this.createServiceAlarms(
      stackName,
      alarmsTopic,
      targetGroup,
      config.alarms.ecs,
    );
  }

  private createServiceAlarms(
    stackName: string,
    alarmsTopic: sns.ITopic,
    targetGroup: elbv2.ApplicationTargetGroup,
    alarmConfig: {
      cpuThreshold: number;
      latencyThresholdMs: number;
      errorThreshold: number;
    },
  ) {
    // High latency alarm - AR-44: threshold from config (convert ms to seconds)
    const latencyThresholdSec = alarmConfig.latencyThresholdMs / 1000;
    const latencyAlarm = new cloudwatch.Alarm(this, "HighLatencyAlarm", {
      metric: targetGroup.metrics.targetResponseTime({
        period: Duration.minutes(5),
        statistic: "p99",
      }),
      threshold: latencyThresholdSec,
      evaluationPeriods: 3,
      alarmDescription: `Ingestion service p99 latency > ${alarmConfig.latencyThresholdMs}ms`,
    });
    latencyAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // 5xx errors alarm - AR-44: threshold from config
    const errorAlarm = new cloudwatch.Alarm(this, "ErrorAlarm", {
      metric: targetGroup.metrics.httpCodeTarget(
        elbv2.HttpCodeTarget.TARGET_5XX_COUNT,
        {
          period: Duration.minutes(5),
          statistic: "Sum",
        },
      ),
      threshold: alarmConfig.errorThreshold,
      evaluationPeriods: 2,
      alarmDescription: `Ingestion service 5xx errors > ${alarmConfig.errorThreshold}`,
    });
    errorAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Unhealthy hosts alarm
    const unhealthyAlarm = new cloudwatch.Alarm(this, "UnhealthyHostsAlarm", {
      metric: targetGroup.metrics.unhealthyHostCount({
        period: Duration.minutes(1),
        statistic: "Maximum",
      }),
      threshold: 1,
      evaluationPeriods: 3,
      alarmDescription: "Ingestion service has unhealthy hosts",
    });
    unhealthyAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // CPU utilization alarm - AR-44: threshold from config
    const cpuAlarm = new cloudwatch.Alarm(this, "HighCPUAlarm", {
      metric: this.service.metricCpuUtilization({
        period: Duration.minutes(5),
        statistic: "Average",
      }),
      threshold: alarmConfig.cpuThreshold,
      evaluationPeriods: 3,
      alarmDescription: `Ingestion service CPU > ${alarmConfig.cpuThreshold}%`,
    });
    cpuAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }
}
