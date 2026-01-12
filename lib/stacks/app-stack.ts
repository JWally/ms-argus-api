// lib/stacks/app-stack.ts
import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as sns from "aws-cdk-lib/aws-sns";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import { Construct } from "constructs";

import { SecretConstruct } from "../constructs/secrets";
import { QueuesConstruct } from "../constructs/queues";
import { RedisConstruct } from "../constructs/redis";
import { DynamoDbConstruct } from "../constructs/dynamodb";
import { IngestionServiceConstruct } from "../constructs/ingestion-service";
import { WorkersConstruct } from "../constructs/workers";
import { CloudFrontWafConstruct } from "../constructs/cloudfront";
import { getStageConfig } from "../config";

interface ArgusApiStackProps extends cdk.StackProps {
  environment: string;
  stackName: string;
  rootDomain: string;
  stage: string;
  region: string;
  account: string;
}

/**
 * Argus API Stack - V4 Architecture
 *
 * Ultra-thin Go ingestion handler -> SQS -> Node.js Lambda workers -> Redis/DynamoDB
 *
 * Components:
 * - VPC with private subnets
 * - ALB + ECS Fargate (Go ingestion handler)
 * - SQS queues (matching, profile)
 * - Node.js Lambda workers (matching, profile updater)
 * - Redis ElastiCache (session cache)
 * - DynamoDB (profiles, tier1 index, tier2 buckets)
 * - CloudFront + WAF (edge protection)
 * - Route53 + ACM (custom domain)
 */
export class ArgusApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ArgusApiStackProps) {
    super(scope, id, props);
    const { environment, stackName, rootDomain, stage, region } = props;

    // =========================================================================
    // NETWORKING
    // =========================================================================

    const vpc = new ec2.Vpc(this, "Vpc", {
      vpcName: `${stackName}-vpc`,
      maxAzs: 2,
      natGateways: stage === "prod" ? 2 : 1, // Cost optimization: 1 NAT in dev
      subnetConfiguration: [
        {
          name: "Public",
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 24,
        },
        {
          name: "Private",
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask: 24,
        },
      ],
    });

    // VPC Endpoints (AR-30) - Reduce NAT Gateway traffic and costs
    // Gateway endpoint for DynamoDB (free, routes traffic through VPC)
    vpc.addGatewayEndpoint("DynamoDbEndpoint", {
      service: ec2.GatewayVpcEndpointAwsService.DYNAMODB,
    });

    // Interface endpoint for SQS (reduces NAT traffic for Lambda->SQS)
    vpc.addInterfaceEndpoint("SqsEndpoint", {
      service: ec2.InterfaceVpcEndpointAwsService.SQS,
      privateDnsEnabled: true,
    });

    // Interface endpoint for Secrets Manager (reduces NAT traffic for key fetching)
    vpc.addInterfaceEndpoint("SecretsManagerEndpoint", {
      service: ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
      privateDnsEnabled: true,
    });

    // =========================================================================
    // DNS & CERTIFICATES
    // =========================================================================

    // Look up existing hosted zone
    const hostedZone = route53.HostedZone.fromLookup(this, "HostedZone", {
      domainName: rootDomain,
    });

    // Stage-aware subdomain: prod uses "api", others use "api-{environment}"
    const apiSubdomain = stage === "prod" ? "api" : `api-${environment}`;
    const apiDomainName = `${apiSubdomain}.${rootDomain}`;

    // Certificate for CloudFront (must be in us-east-1)
    const certificate = new acm.Certificate(this, "Certificate", {
      domainName: apiDomainName,
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    // =========================================================================
    // SHARED RESOURCES
    // =========================================================================

    // Secrets construct (encryption keys)
    const secrets = new SecretConstruct(this, "Secrets", {
      environment,
      stackName,
      stage,
      projectName: id,
    });

    // Alarms SNS topic
    const alarmsTopic = new sns.Topic(this, "AlarmsTopic", {
      displayName: `${stackName}-Alarms`,
      topicName: `${stackName}-AlarmsTopic-${region}`,
    });

    // =========================================================================
    // DATA LAYER
    // =========================================================================

    // Redis for session cache
    // Uses tiny instances for non-prod (faster spin up/down)
    const redis = new RedisConstruct(this, "Redis", {
      stackName,
      vpc,
      alarmsTopic,
      stage,
    });

    // DynamoDB tables
    const dynamodb = new DynamoDbConstruct(this, "DynamoDB", {
      stackName,
      alarmsTopic,
    });

    // SQS queues - AR-44: Pass stage for config-based values
    const queues = new QueuesConstruct(this, "Queues", {
      stackName,
      stage,
      alarmsTopic,
    });

    // =========================================================================
    // COMPUTE LAYER
    // =========================================================================

    // Go ingestion service (ALB + ECS Fargate)
    const ingestionService = new IngestionServiceConstruct(
      this,
      "IngestionService",
      {
        stackName,
        vpc,
        matchingQueue: queues.matchingQueue,
        alarmsTopic,
        stage,
        secret: secrets.secret,
      },
    );

    // Allow ingestion service to access Redis
    redis.allowFrom(ingestionService.securityGroup, "Allow ingestion service");

    // Worker Lambdas
    const workers = new WorkersConstruct(this, "Workers", {
      stackName,
      stage,
      projectName: id,
      alarmsTopic,
      matchingQueue: queues.matchingQueue,
      profileQueue: queues.profileQueue,
      profilesTable: dynamodb.profilesTable,
      tier1IndexTable: dynamodb.tier1IndexTable,
      tier2BucketsTable: dynamodb.tier2BucketsTable,
      redisEndpoint: redis.endpoint,
      redisPort: redis.port,
      redisSecurityGroup: redis.securityGroup,
      vpc,
    });

    // =========================================================================
    // EDGE LAYER
    // =========================================================================

    // CloudFront + WAF (AR-51: WAF disabled in non-prod to reduce costs)
    const config = getStageConfig(stage);
    const cdn = new CloudFrontWafConstruct(this, "CDN", {
      environment,
      stackName,
      loadBalancer: ingestionService.loadBalancer,
      rootDomain,
      apiSubdomain,
      hostedZone,
      certificate,
      stageConfig: config,
    });

    // =========================================================================
    // OUTPUTS
    // =========================================================================

    new cdk.CfnOutput(this, "VpcId", {
      value: vpc.vpcId,
      description: "VPC ID",
    });

    new cdk.CfnOutput(this, "AlarmsTopicArn", {
      value: alarmsTopic.topicArn,
      description: "ARN of the SNS topic for CloudWatch Alarms",
    });

    new cdk.CfnOutput(this, "ApiEndpoint", {
      value: `https://${apiDomainName}`,
      description: "API endpoint (CloudFront + custom domain)",
    });

    new cdk.CfnOutput(this, "CloudFrontDomain", {
      value: cdn.distribution.distributionDomainName,
      description: "CloudFront distribution domain",
    });

    new cdk.CfnOutput(this, "ALBEndpoint", {
      value: ingestionService.loadBalancer.loadBalancerDnsName,
      description: "ALB DNS name (internal)",
    });

    new cdk.CfnOutput(this, "MatchingQueueUrl", {
      value: queues.matchingQueue.queueUrl,
      description: "SQS URL for matching queue",
    });

    new cdk.CfnOutput(this, "ProfileQueueUrl", {
      value: queues.profileQueue.queueUrl,
      description: "SQS URL for profile queue",
    });

    new cdk.CfnOutput(this, "RedisEndpoint", {
      value: redis.endpoint,
      description: "Redis primary endpoint",
    });

    new cdk.CfnOutput(this, "ProfilesTableName", {
      value: dynamodb.profilesTable.tableName,
      description: "DynamoDB profiles table name",
    });

    new cdk.CfnOutput(this, "MatchingWorkerArn", {
      value: workers.matchingWorker.functionArn,
      description: "Matching worker Lambda ARN",
    });

    new cdk.CfnOutput(this, "ProfileUpdaterArn", {
      value: workers.profileUpdater.functionArn,
      description: "Profile updater Lambda ARN",
    });
  }
}
