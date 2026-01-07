// lib/constructs/cloudfront.ts
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import * as cdk from 'aws-cdk-lib';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import { Construct } from 'constructs';

export class CloudFrontWafConstruct extends Construct {
  public readonly distribution: cloudfront.Distribution;
  public readonly webAcl: wafv2.CfnWebACL;

  constructor(
    scope: Construct,
    id: string,
    props: {
      httpApi: apigwv2.IHttpApi;
      stage: apigwv2.IStage;
      environment: string;
    },
  ) {
    super(scope, id);

    const { environment } = props;

    // WAF for CloudFront (global)
    this.webAcl = new wafv2.CfnWebACL(this, 'WebACL', {
      scope: 'CLOUDFRONT',
      defaultAction: { allow: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: `${environment}-argus-waf-metrics`,
        sampledRequestsEnabled: true,
      },
      customResponseBodies: {
        RateLimitExceeded: {
          contentType: 'APPLICATION_JSON',
          content: '{"message":"Too many requests","code":"rate_limited"}',
        },
      },
      rules: [
        {
          name: 'AWSManagedCommonVulns',
          priority: 0,
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
            metricName: `${environment}-CommonRuleSet`,
          },
        },
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
            metricName: `${environment}-IpRateLimit`,
          },
        },
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
            metricName: `${environment}-BodySizeLimit`,
          },
        },
        {
          name: 'BlockCertainCountry',
          priority: 5,
          statement: { geoMatchStatement: { countryCodes: ['CN', 'RU'] } },
          action: { block: {} },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: `${environment}-GeoMatchBlock`,
          },
        },
      ],
    });

    this.distribution = new cloudfront.Distribution(this, 'Distribution', {
      defaultBehavior: {
        origin: new origins.HttpOrigin(
          `${props.httpApi.apiId}.execute-api.${cdk.Stack.of(this).region}.amazonaws.com`,
          { originPath: `/${props.stage.stageName}` },
        ),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      },
      webAclId: this.webAcl.attrArn,
    });
  }
}
