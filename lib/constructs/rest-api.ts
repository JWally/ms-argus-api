// lib/constructs/rest-api.ts

import { Construct } from "constructs";
import * as cdk from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as targets from "aws-cdk-lib/aws-route53-targets";
import * as ssm from "aws-cdk-lib/aws-ssm";

export interface RestApiConstructProps {
  stackName: string;
  environment: string;
  rootDomain: string;
  hostedZone: route53.IHostedZone;
  /**
   * Lambda that handles `GET /v1/session/{cpi}/{session_id}`. Auth (token
   * signature verification, path/claim binding) is performed inside the
   * handler — no Lambda authorizer needed.
   */
  sessionGetFunction: lambda.IFunction;
  /**
   * Free-tier per-key throttle. Conservative defaults — bump when paid plans
   * arrive (or split into separate usage plans per tier).
   */
  freeTier?: {
    rateLimit?: number; // requests/second
    burstLimit?: number; // bucket size
    quotaLimit?: number; // requests per period
    quotaPeriod?: apigateway.Period; // DAY | WEEK | MONTH
  };
}

/**
 * Public REST API for merchant-facing reads. Lives alongside the existing
 * HTTP API (which remains the ingest path). REST API is required here because
 * it's the only flavor that supports native APIGW Keys + Usage Plans, which
 * is how we get gateway-level throttling, quotas, and instant revocation
 * without rolling our own.
 *
 * The merchant credential ships as `<keyId>.<signedToken>`; the SDK splits
 * at the dot and sends two headers: `x-api-key` (gateway match) and
 * `x-argus-token` (handler verify).
 */
export class RestApiConstruct extends Construct {
  public readonly api: apigateway.RestApi;
  public readonly freeUsagePlan: apigateway.UsagePlan;
  public readonly endpoint: string;

  constructor(scope: Construct, id: string, props: RestApiConstructProps) {
    super(scope, id);

    const {
      stackName,
      environment,
      rootDomain,
      hostedZone,
      sessionGetFunction,
    } = props;

    const apiSubdomain =
      environment === "prod" ? "merchant" : `merchant-${environment}`;
    const apiDomainName = `${apiSubdomain}.${rootDomain}`;

    const certificate = new acm.Certificate(this, "Certificate", {
      domainName: apiDomainName,
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    this.api = new apigateway.RestApi(this, "MerchantApi", {
      restApiName: `${stackName}-merchant-api`,
      description: "Merchant-facing REST API (native APIGW Keys + Usage Plans)",
      deployOptions: {
        stageName: "v1",
        // Per-stage throttle ceiling — usage plans give per-key throttle
        // below this, which is what we actually rely on for fair-share.
        throttlingRateLimit: 1000,
        throttlingBurstLimit: 2000,
        metricsEnabled: true,
      },
      domainName: {
        domainName: apiDomainName,
        certificate,
        endpointType: apigateway.EndpointType.REGIONAL,
        securityPolicy: apigateway.SecurityPolicy.TLS_1_2,
      },
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: ["GET", "OPTIONS"],
        allowHeaders: ["Content-Type", "x-api-key", "x-argus-token"],
        maxAge: cdk.Duration.hours(1),
      },
    });

    // Custom domain + DNS
    new route53.ARecord(this, "ARecord", {
      zone: hostedZone,
      recordName: apiDomainName,
      target: route53.RecordTarget.fromAlias(new targets.ApiGateway(this.api)),
    });

    // Routes: /v1/session/{cpi}/{session_id} → session-get Lambda
    const v1 = this.api.root.addResource("v1");
    const session = v1.addResource("session");
    const cpi = session.addResource("{cpi}");
    const sessionId = cpi.addResource("{session_id}");
    sessionId.addMethod(
      "GET",
      new apigateway.LambdaIntegration(sessionGetFunction, { proxy: true }),
      {
        // CRITICAL: gateway-level API-key gate. Caller must send
        // `x-api-key: <keyId>` matching a registered (and not-yet-revoked) key
        // associated with the free usage plan.
        apiKeyRequired: true,
      },
    );

    // Free-tier usage plan — every issued key joins this for now. When paid
    // tiers ship, mint additional plans (pro, enterprise) and have the
    // platform's mintKey associate based on merchant.plan.
    const freeTier = {
      rateLimit: props.freeTier?.rateLimit ?? 5,
      burstLimit: props.freeTier?.burstLimit ?? 10,
      quotaLimit: props.freeTier?.quotaLimit ?? 10_000,
      quotaPeriod: props.freeTier?.quotaPeriod ?? apigateway.Period.DAY,
    };

    this.freeUsagePlan = this.api.addUsagePlan("FreeUsagePlan", {
      name: `${stackName}-free`,
      description: "Free tier — generous limits, suitable for pilot/dev",
      throttle: {
        rateLimit: freeTier.rateLimit,
        burstLimit: freeTier.burstLimit,
      },
      quota: {
        limit: freeTier.quotaLimit,
        period: freeTier.quotaPeriod,
      },
      apiStages: [{ api: this.api, stage: this.api.deploymentStage }],
    });

    // Export the usage plan id so ms-argus-platform's mint endpoint can
    // associate newly minted keys at runtime.
    new ssm.StringParameter(this, "FreeUsagePlanIdParam", {
      parameterName: `/argus-api/${environment}/usage-plan-id-free`,
      stringValue: this.freeUsagePlan.usagePlanId,
      description: `Free-tier usage plan id, consumed by ms-argus-platform mint endpoint (${environment})`,
    });

    this.endpoint = `https://${apiDomainName}`;

    new cdk.CfnOutput(this, "MerchantApiEndpoint", {
      value: this.endpoint,
      description: "Merchant-facing REST API endpoint",
    });
    new cdk.CfnOutput(this, "FreeUsagePlanId", {
      value: this.freeUsagePlan.usagePlanId,
      description: "Free-tier usage plan id (also exported via SSM)",
    });
  }
}
