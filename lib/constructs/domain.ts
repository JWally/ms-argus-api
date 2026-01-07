// lib/constructs/domain.ts
import { Construct } from 'constructs';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import { ApiMapping } from 'aws-cdk-lib/aws-apigatewayv2';

interface DomainHttpProps {
  stackName: string;
  rootDomain: string;
  httpApi: apigwv2.HttpApi;
  region: string;
  stage: string;
  httpApiStage: apigwv2.HttpStage;
}

export class DomainHttpConstruct extends Construct {
  public readonly domain: apigwv2.DomainName;

  constructor(scope: Construct, id: string, props: DomainHttpProps) {
    super(scope, id);

    const { rootDomain, httpApi, region, stage, httpApiStage } = props;

    // api.<rootDomain> for prod; <stage>-api.<rootDomain> otherwise
    const domainNameString = stage === 'prod' ? `argus-api.${rootDomain}` : `${stage}-argus-api.${rootDomain}`;

    // Lookup hosted zone (must already exist in Route53)
    const hostedZone = route53.HostedZone.fromLookup(this, 'HostedZone', {
      domainName: rootDomain,
    });

    // Certificate (must be in same region as HTTP API)
    const certificate = new acm.Certificate(this, 'HttpApiCertificate', {
      domainName: domainNameString,
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    // Create API Gateway v2 custom domain
    this.domain = new apigwv2.DomainName(this, 'HttpCustomDomain', {
      domainName: domainNameString,
      certificate,
    });

    // Map custom domain to API stage
    new ApiMapping(this, 'HttpApiMapping', {
      api: httpApi,
      domainName: this.domain,
      stage: httpApiStage,
    });

    // Route53 alias record (latency-based routing)
    const cfnDomain = this.domain.node.defaultChild as apigwv2.CfnDomainName;
    const regionalDomainName = cfnDomain.attrRegionalDomainName;
    const regionalHostedZoneId = cfnDomain.attrRegionalHostedZoneId;

    new route53.CfnRecordSet(this, 'LatencyAliasA', {
      name: `${domainNameString}.`,
      type: 'A',
      hostedZoneId: hostedZone.hostedZoneId,
      aliasTarget: {
        dnsName: regionalDomainName,
        hostedZoneId: regionalHostedZoneId,
      },
      setIdentifier: region,
      region,
    });
  }
}
