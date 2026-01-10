// lib/constructs/cloudfront.ts
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53targets from 'aws-cdk-lib/aws-route53-targets';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import { Construct } from 'constructs';

interface CloudFrontWafConstructProps {
  environment: string;
  stackName: string;
  loadBalancer: elbv2.IApplicationLoadBalancer;
  domainName?: string;
  hostedZone?: route53.IHostedZone;
  certificate?: acm.ICertificate;
}

export class CloudFrontWafConstruct extends Construct {
  public readonly distribution: cloudfront.Distribution;
  public readonly webAcl: wafv2.CfnWebACL;

  constructor(scope: Construct, id: string, props: CloudFrontWafConstructProps) {
    super(scope, id);

    const { environment, stackName, loadBalancer, domainName, hostedZone, certificate } = props;

    // WAF for CloudFront (must be in us-east-1, CLOUDFRONT scope)
    this.webAcl = new wafv2.CfnWebACL(this, 'WebACL', {
      scope: 'CLOUDFRONT',
      defaultAction: { allow: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: `${stackName}-waf-metrics`,
        sampledRequestsEnabled: true,
      },
      customResponseBodies: {
        RateLimitExceeded: {
          contentType: 'APPLICATION_JSON',
          content: '{"message":"Too many requests","code":"rate_limited"}',
        },
      },
      rules: [
        // Geo-blocking BEFORE other rules (saves WAF request costs)
        {
          name: 'GeoBlockCNRU',
          priority: 0,
          statement: { geoMatchStatement: { countryCodes: ['CN', 'RU'] } },
          action: { block: {} },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: `${stackName}-GeoBlock`,
          },
        },
        // AWS Managed Common Rules
        {
          name: 'AWSManagedCommonRules',
          priority: 1,
          statement: {
            managedRuleGroupStatement: {
              name: 'AWSManagedRulesCommonRuleSet',
              vendorName: 'AWS',
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
        // Rate limiting per IP
        {
          name: 'RateLimitIP',
          priority: 2,
          statement: {
            rateBasedStatement: {
              limit: 600, // requests per 5 minutes per IP
              aggregateKeyType: 'IP',
            },
          },
          action: {
            block: {
              customResponse: {
                responseCode: 429,
                customResponseBodyKey: 'RateLimitExceeded',
                responseHeaders: [{ name: 'Retry-After', value: '60' }],
              },
            },
          },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: `${stackName}-IpRateLimit`,
          },
        },
        // Body size limit (100KB)
        {
          name: 'LimitBodySize100KB',
          priority: 3,
          statement: {
            sizeConstraintStatement: {
              fieldToMatch: { body: { oversizeHandling: 'CONTINUE' } },
              textTransformations: [{ priority: 0, type: 'NONE' }],
              comparisonOperator: 'GT',
              size: 102_400,
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

    // CloudFront distribution with ALB origin
    const distributionProps: cloudfront.DistributionProps = {
      defaultBehavior: {
        origin: new origins.HttpOrigin(loadBalancer.loadBalancerDnsName, {
          protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY, // ALB is HTTP, CloudFront handles HTTPS
          httpPort: 80,
        }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER,
      },
      webAclId: this.webAcl.attrArn,
      comment: `${stackName} - Argus API`,
    };

    // Add custom domain if provided
    if (domainName && certificate) {
      Object.assign(distributionProps, {
        domainNames: [`api.${domainName}`],
        certificate,
      });
    }

    this.distribution = new cloudfront.Distribution(this, 'Distribution', distributionProps);

    // Create Route53 record if hosted zone is provided
    if (hostedZone && domainName) {
      new route53.ARecord(this, 'ApiDnsRecord', {
        zone: hostedZone,
        recordName: `api.${domainName}`,
        target: route53.RecordTarget.fromAlias(
          new route53targets.CloudFrontTarget(this.distribution),
        ),
      });
    }
  }
}
