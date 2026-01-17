// lib/constructs/cloudfront.ts
// AR-52: Updated to support HTTP API origin (replacing ALB)
import * as cdk from "aws-cdk-lib";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as route53targets from "aws-cdk-lib/aws-route53-targets";
import { Construct } from "constructs";
import { StageConfig } from "../config";

interface CloudFrontWafConstructProps {
  environment: string;
  stackName: string;
  httpApiEndpoint: string; // AR-52: HTTP API endpoint (e.g., "https://xxx.execute-api.us-east-1.amazonaws.com")
  rootDomain?: string;
  apiSubdomain?: string;
  hostedZone?: route53.IHostedZone;
  certificate?: acm.ICertificate;
  stageConfig: StageConfig;
}

export class CloudFrontWafConstruct extends Construct {
  public readonly distribution: cloudfront.Distribution;
  public readonly webAcl?: wafv2.CfnWebACL;

  constructor(
    scope: Construct,
    id: string,
    props: CloudFrontWafConstructProps,
  ) {
    super(scope, id);

    const {
      stackName,
      httpApiEndpoint,
      rootDomain,
      apiSubdomain,
      hostedZone,
      certificate,
      stageConfig,
    } = props;
    const fullDomainName =
      rootDomain && apiSubdomain ? `${apiSubdomain}.${rootDomain}` : undefined;

    // AR-51: Only create WAF in production to reduce costs (~$30/month in dev)
    if (stageConfig.waf.enabled) {
      this.webAcl = new wafv2.CfnWebACL(this, "WebACL", {
        scope: "CLOUDFRONT",
        defaultAction: { allow: {} },
        visibilityConfig: {
          cloudWatchMetricsEnabled: true,
          metricName: `${stackName}-waf-metrics`,
          sampledRequestsEnabled: true,
        },
        customResponseBodies: {
          RateLimitExceeded: {
            contentType: "APPLICATION_JSON",
            content: '{"message":"Too many requests","code":"rate_limited"}',
          },
        },
        rules: [
          // Geo-blocking BEFORE other rules (saves WAF request costs)
          {
            name: "GeoBlockCNRU",
            priority: 0,
            statement: { geoMatchStatement: { countryCodes: ["CN", "RU"] } },
            action: { block: {} },
            visibilityConfig: {
              sampledRequestsEnabled: true,
              cloudWatchMetricsEnabled: true,
              metricName: `${stackName}-GeoBlock`,
            },
          },
          // AWS Managed Common Rules
          {
            name: "AWSManagedCommonRules",
            priority: 1,
            statement: {
              managedRuleGroupStatement: {
                name: "AWSManagedRulesCommonRuleSet",
                vendorName: "AWS",
                excludedRules: [],
              },
            },
            overrideAction: { none: {} },
            visibilityConfig: {
              sampledRequestsEnabled: true,
              cloudWatchMetricsEnabled: true,
              metricName: `${stackName}-CommonRuleSet`,
            },
          },
          // Rate limiting per IP (AR-137: wired to config)
          {
            name: "RateLimitIP",
            priority: 2,
            statement: {
              rateBasedStatement: {
                limit: stageConfig.waf.rateLimitPerFiveMinutes,
                aggregateKeyType: "IP",
              },
            },
            action: {
              block: {
                customResponse: {
                  responseCode: 429,
                  customResponseBodyKey: "RateLimitExceeded",
                  responseHeaders: [{ name: "Retry-After", value: "60" }],
                },
              },
            },
            visibilityConfig: {
              sampledRequestsEnabled: true,
              cloudWatchMetricsEnabled: true,
              metricName: `${stackName}-IpRateLimit`,
            },
          },
          // Body size limit (AR-137: wired to config)
          {
            name: "LimitBodySize100KB",
            priority: 3,
            statement: {
              sizeConstraintStatement: {
                fieldToMatch: { body: { oversizeHandling: "CONTINUE" } },
                textTransformations: [{ priority: 0, type: "NONE" }],
                comparisonOperator: "GT",
                size: stageConfig.waf.bodySizeLimitBytes,
              },
            },
            action: { block: {} },
            visibilityConfig: {
              sampledRequestsEnabled: true,
              cloudWatchMetricsEnabled: true,
              metricName: `${stackName}-BodySizeLimit`,
            },
          },
        ],
      });
    }

    // AR-52: Extract domain from HTTP API endpoint using CloudFormation intrinsics
    // httpApiEndpoint format: "https://xxx.execute-api.us-east-1.amazonaws.com"
    // We can't use new URL() because httpApiEndpoint is a CDK token at synth time
    // Use Fn.select to extract domain from "https://xxx.execute-api.region.amazonaws.com"
    const apiDomain = cdk.Fn.select(2, cdk.Fn.split("/", httpApiEndpoint));

    // CloudFront distribution with HTTP API origin
    const distributionProps: cloudfront.DistributionProps = {
      defaultBehavior: {
        origin: new origins.HttpOrigin(apiDomain, {
          protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
        }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        originRequestPolicy:
          cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
      },
      ...(this.webAcl && { webAclId: this.webAcl.attrArn }),
      comment: `${stackName} - Argus API`,
    };

    // Add custom domain if provided
    if (fullDomainName && certificate) {
      Object.assign(distributionProps, {
        domainNames: [fullDomainName],
        certificate,
      });
    }

    this.distribution = new cloudfront.Distribution(
      this,
      "Distribution",
      distributionProps,
    );

    // Create Route53 record if hosted zone is provided
    if (hostedZone && fullDomainName) {
      new route53.ARecord(this, "ApiDnsRecord", {
        zone: hostedZone,
        recordName: fullDomainName,
        target: route53.RecordTarget.fromAlias(
          new route53targets.CloudFrontTarget(this.distribution),
        ),
      });
    }
  }
}
