// lib/constructs/vpc.ts
// Shared VPC import construct for ms-argus-api
// Imports VPC from ms-argus-infra via SSM Parameter Store

import { Construct } from "constructs";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ssm from "aws-cdk-lib/aws-ssm";
import * as cdk from "aws-cdk-lib";

export interface ArgusVpcProps {
  /**
   * Environment name for SSM parameter lookup (e.g., "dev-jw", "qa", "prod")
   */
  environment: string;
}

/**
 * VPC construct for Argus API infrastructure.
 *
 * Imports the shared VPC from ms-argus-infra via SSM Parameter Store.
 * Creates service-specific security groups for Lambda functions.
 *
 * Required SSM parameters (created by ms-argus-infra):
 *   /argus/{environment}/vpc-id
 */
export class ArgusVpc extends Construct {
  public readonly vpc: ec2.IVpc;
  public readonly lambdaSecurityGroup: ec2.ISecurityGroup;

  constructor(scope: Construct, id: string, props: ArgusVpcProps) {
    super(scope, id);

    const { environment } = props;

    // =========================================================================
    // IMPORT SHARED VPC FROM MS-ARGUS-INFRA
    // =========================================================================

    const ssmPrefix = `/argus/${environment}`;

    // Use valueFromLookup for synth-time resolution (required for VPC lookup)
    const vpcId = ssm.StringParameter.valueFromLookup(
      this,
      `${ssmPrefix}/vpc-id`,
    );

    // Import VPC - this requires the VPC to already exist
    this.vpc = ec2.Vpc.fromLookup(this, "SharedVpc", {
      vpcId,
    });

    // =========================================================================
    // SECURITY GROUPS (service-specific, created here)
    // =========================================================================

    // Security group for Lambda functions that need VPC access
    this.lambdaSecurityGroup = new ec2.SecurityGroup(
      this,
      "LambdaSecurityGroup",
      {
        vpc: this.vpc,
        securityGroupName: `argus-api-${environment}-lambda-sg`,
        description: "Security group for Lambda functions in shared VPC",
        allowAllOutbound: true,
      },
    );

    // =========================================================================
    // TAGS
    // =========================================================================

    cdk.Tags.of(this).add("Environment", environment);
    cdk.Tags.of(this).add("Service", "argus-api");
  }
}
