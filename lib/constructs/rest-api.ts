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
}

/**
 * Per-tier throttle limits. Subscription tier sets the per-second rate +
 * burst ceiling on a single key — that's the MRR product. Volume comes
 * from prepaid credits (Dynamo, decremented per session-get in the Lambda),
 * not from the APIGW quota counter, so no `quota` field here.
 *
 *   Free    $0   / 5 rps  · 10 burst
 *   Starter $99  / 20 rps · 50 burst
 *   Pro     $299 / 100 rps · 200 burst
 *
 * APIGW returns 429 above burstLimit. Out-of-credits returns 402 from the
 * session-get Lambda (after the conditional decrement fails).
 */
const TIER_LIMITS = {
  free: { rateLimit: 5, burstLimit: 10 },
  starter: { rateLimit: 20, burstLimit: 50 },
  pro: { rateLimit: 100, burstLimit: 200 },
} as const;

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
// nosemgrep: no-trivial-class-wrapper -- makeUsagePlan/exportUsagePlanId shape config to collapse repeated blocks; not pure delegation
export class RestApiConstruct extends Construct {
  public readonly api: apigateway.RestApi;
  public readonly freeUsagePlan: apigateway.UsagePlan;
  public readonly starterUsagePlan: apigateway.UsagePlan;
  public readonly proUsagePlan: apigateway.UsagePlan;
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

    // Three usage plans, one per pricing tier. Every minted key starts on
    // free; the Stripe subscription webhook on the platform side moves the
    // key between plans on subscription create/update/cancel events.
    this.freeUsagePlan = this.makeUsagePlan(
      "Free",
      `${stackName}-free`,
      "Free tier — 5 rps, 10 burst",
      TIER_LIMITS.free,
    );
    this.starterUsagePlan = this.makeUsagePlan(
      "Starter",
      `${stackName}-starter`,
      "Starter tier — $99/mo, 20 rps, 50 burst",
      TIER_LIMITS.starter,
    );
    this.proUsagePlan = this.makeUsagePlan(
      "Pro",
      `${stackName}-pro`,
      "Pro tier — $299/mo, 100 rps, 200 burst",
      TIER_LIMITS.pro,
    );

    // Export each plan's id to SSM so ms-argus-platform can attach + move
    // keys based on the merchant's current subscriptionPlan field.
    this.exportUsagePlanId("Free", "free", environment, this.freeUsagePlan);
    this.exportUsagePlanId(
      "Starter",
      "starter",
      environment,
      this.starterUsagePlan,
    );
    this.exportUsagePlanId("Pro", "pro", environment, this.proUsagePlan);

    this.endpoint = `https://${apiDomainName}`;

    new cdk.CfnOutput(this, "MerchantApiEndpoint", {
      value: this.endpoint,
      description: "Merchant-facing REST API endpoint",
    });
    new cdk.CfnOutput(this, "FreeUsagePlanId", {
      value: this.freeUsagePlan.usagePlanId,
      description: "Free-tier usage plan id (also exported via SSM)",
    });
    new cdk.CfnOutput(this, "StarterUsagePlanId", {
      value: this.starterUsagePlan.usagePlanId,
      description: "Starter-tier usage plan id (also exported via SSM)",
    });
    new cdk.CfnOutput(this, "ProUsagePlanId", {
      value: this.proUsagePlan.usagePlanId,
      description: "Pro-tier usage plan id (also exported via SSM)",
    });
  }

  private makeUsagePlan(
    constructIdSuffix: string,
    name: string,
    description: string,
    limits: { rateLimit: number; burstLimit: number },
  ): apigateway.UsagePlan {
    return this.api.addUsagePlan(`${constructIdSuffix}UsagePlan`, {
      name,
      description,
      throttle: {
        rateLimit: limits.rateLimit,
        burstLimit: limits.burstLimit,
      },
      apiStages: [{ api: this.api, stage: this.api.deploymentStage }],
    });
  }

  private exportUsagePlanId(
    constructIdSuffix: string,
    tierKey: string,
    environment: string,
    plan: apigateway.UsagePlan,
  ): void {
    new ssm.StringParameter(this, `${constructIdSuffix}UsagePlanIdParam`, {
      parameterName: `/argus-api/${environment}/usage-plan-id-${tierKey}`,
      stringValue: plan.usagePlanId,
      description: `${tierKey}-tier usage plan id, consumed by ms-argus-platform mint endpoint (${environment})`,
    });
  }
}
