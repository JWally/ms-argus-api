// lib/constructs/ip-class-builder.ts

import { Construct } from "constructs";
import { Duration, RemovalPolicy } from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda-nodejs";
import * as s3 from "aws-cdk-lib/aws-s3";

interface IpClassBuilderProps {
  stackName: string;
  stage: string;
}

/**
 * Owns the S3 bucket that backs the ASN→category dataset, the
 * RDAP-discovered auto-overlay, and the browser-engine baselines. Also
 * bears the legacy class name + instance name "IpClass" so the bucket's
 * CDK logical ID (`IpClassBucket4B226CE3`) stays anchored across the
 * post-refactor reorg — losing that bucket would mean re-seeding
 * asn-categories.json.gz from RIB dumps.
 *
 * The Lambdas that read/write this bucket (ip-class-builder, ip-class-
 * discoverer, browser-baseline-builder) live on LambdasConstruct, along
 * with their EventBridge cron rules and the init-invoke custom resource.
 */
export class IpClassBuilderConstruct extends Construct {
  public readonly bucket: s3.Bucket;

  constructor(scope: Construct, id: string, props: IpClassBuilderProps) {
    super(scope, id);

    const { stackName, stage } = props;

    this.bucket = new s3.Bucket(this, "Bucket", {
      bucketName: `${stackName}-ip-class`,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy:
        stage === "prod" ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
      autoDeleteObjects: stage !== "prod",
      lifecycleRules: [
        {
          id: "expire-old-versions",
          noncurrentVersionExpiration: Duration.days(30),
        },
      ],
    });
  }

  /**
   * Grant a consumer Lambda read access to the dataset bucket and inject
   * the env vars its runtime classifier needs.
   *
   * Keys are constants here (not props) so the runtime contract stays a
   * single source of truth — LambdasConstruct uses the same literals when
   * writing.
   */
  public grantReadTo(fn: lambda.NodejsFunction): void {
    this.bucket.grantRead(fn);
    fn.addEnvironment("IP_CLASS_BUCKET", this.bucket.bucketName);
    fn.addEnvironment("IP_CLASS_KEY", "asn-categories.json.gz");
    fn.addEnvironment("IP_CLASS_AUTO_OVERLAY_KEY", "auto-overlay.json.gz");
    fn.addEnvironment("BROWSER_BASELINES_KEY", "browser-baselines.json.gz");
  }
}
