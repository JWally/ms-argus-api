// lib/constructs/ingestion-service.ts
import * as path from 'path';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as actions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Duration, RemovalPolicy } from 'aws-cdk-lib';

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

    // Security group for the service
    this.securityGroup = new ec2.SecurityGroup(this, 'ServiceSecurityGroup', {
      vpc,
      description: 'Security group for Argus ingestion service',
      allowAllOutbound: true,
    });

    // ECS Cluster - let CDK generate name to avoid collisions
    this.cluster = new ecs.Cluster(this, 'Cluster', {
      vpc,
      containerInsights: true,
    });

    // CloudWatch log group
    const logGroup = new logs.LogGroup(this, 'LogGroup', {
      logGroupName: `/ecs/${stackName}-ingestion`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // Task definition
    const taskDefinition = new ecs.FargateTaskDefinition(this, 'TaskDef', {
      memoryLimitMiB: 1024,
      cpu: 512, // 0.5 vCPU
      runtimePlatform: {
        cpuArchitecture: ecs.CpuArchitecture.ARM64,
        operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
      },
    });

    // Build container image from local Dockerfile
    // CDK will build and push to ECR automatically
    const ingestionImage = ecs.ContainerImage.fromAsset(
      path.join(__dirname, '../../cmd/ingestion'),
    );

    // Container definition with built image
    const container = taskDefinition.addContainer('ingestion', {
      image: ingestionImage,
      containerName: 'ingestion',
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'ingestion',
        logGroup,
      }),
      environment: {
        ENVIRONMENT: stage,
        SQS_QUEUE_URL: matchingQueue.queueUrl,
        LOG_LEVEL: 'info',
      },
      secrets: {
        HMAC_KEY: ecs.Secret.fromSecretsManager(secret, 'HMAC_KEY'),
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
    const albSecurityGroup = new ec2.SecurityGroup(this, 'ALBSecurityGroup', {
      vpc,
      description: 'Security group for ingestion ALB',
      allowAllOutbound: true, // Required for health checks to reach targets
    });

    // Allow HTTP traffic from anywhere to ALB (CloudFront will front this)
    albSecurityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(80),
      'Allow HTTP from anywhere',
    );

    this.loadBalancer = new elbv2.ApplicationLoadBalancer(this, 'ALB', {
      vpc,
      internetFacing: true,
      loadBalancerName: albName,
      securityGroup: albSecurityGroup,
    });

    // HTTP listener (HTTPS terminated at CloudFront)
    this.listener = this.loadBalancer.addListener('HttpListener', {
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
    });

    // Fargate service
    this.service = new ecs.FargateService(this, 'Service', {
      cluster: this.cluster,
      taskDefinition,
      desiredCount: 2,
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
      'Allow ALB to reach service',
    );

    // Add service to ALB target group
    const targetGroup = this.listener.addTargets('ServiceTarget', {
      port: 8080,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targets: [this.service],
      healthCheck: {
        path: '/health',
        interval: Duration.seconds(30),
        timeout: Duration.seconds(5),
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 3,
        healthyHttpCodes: '200',
      },
      deregistrationDelay: Duration.seconds(30),
    });

    // Auto-scaling (after target group is attached)
    const scaling = this.service.autoScaleTaskCount({
      minCapacity: 2,
      maxCapacity: 8,
    });

    scaling.scaleOnCpuUtilization('CpuScaling', {
      targetUtilizationPercent: 70,
      scaleInCooldown: Duration.seconds(60),
      scaleOutCooldown: Duration.seconds(30),
    });

    scaling.scaleOnRequestCount('RequestScaling', {
      targetGroup,
      requestsPerTarget: 5000, // Scale out above 5k req/target
      scaleInCooldown: Duration.seconds(60),
      scaleOutCooldown: Duration.seconds(30),
    });

    // Alarms
    this.createServiceAlarms(stackName, alarmsTopic, targetGroup);
  }

  private createServiceAlarms(
    stackName: string,
    alarmsTopic: sns.ITopic,
    targetGroup: elbv2.ApplicationTargetGroup,
  ) {
    // High latency alarm
    const latencyAlarm = new cloudwatch.Alarm(this, 'HighLatencyAlarm', {
      metric: targetGroup.metrics.targetResponseTime({
        period: Duration.minutes(5),
        statistic: 'p99',
      }),
      threshold: 0.01, // 10ms - should be <5ms normally
      evaluationPeriods: 3,
      alarmDescription: 'Ingestion service p99 latency > 10ms',
    });
    latencyAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // 5xx errors alarm
    const errorAlarm = new cloudwatch.Alarm(this, 'ErrorAlarm', {
      metric: targetGroup.metrics.httpCodeTarget(
        elbv2.HttpCodeTarget.TARGET_5XX_COUNT,
        {
          period: Duration.minutes(5),
          statistic: 'Sum',
        },
      ),
      threshold: 10,
      evaluationPeriods: 2,
      alarmDescription: 'Ingestion service 5xx errors > 10',
    });
    errorAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // Unhealthy hosts alarm
    const unhealthyAlarm = new cloudwatch.Alarm(this, 'UnhealthyHostsAlarm', {
      metric: targetGroup.metrics.unhealthyHostCount({
        period: Duration.minutes(1),
        statistic: 'Maximum',
      }),
      threshold: 1,
      evaluationPeriods: 3,
      alarmDescription: 'Ingestion service has unhealthy hosts',
    });
    unhealthyAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // CPU utilization alarm
    const cpuAlarm = new cloudwatch.Alarm(this, 'HighCPUAlarm', {
      metric: this.service.metricCpuUtilization({
        period: Duration.minutes(5),
        statistic: 'Average',
      }),
      threshold: 85,
      evaluationPeriods: 3,
      alarmDescription: 'Ingestion service CPU > 85%',
    });
    cpuAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }
}
