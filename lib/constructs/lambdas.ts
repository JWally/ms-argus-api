// lib/constructs/lambdas.ts

import * as path from "path";
import { Construct } from "constructs";
import * as cdk from "aws-cdk-lib";
import { Duration, RemovalPolicy, SecretValue } from "aws-cdk-lib";
import * as lambdaNode from "aws-cdk-lib/aws-lambda-nodejs";
import * as logs from "aws-cdk-lib/aws-logs";
import * as iam from "aws-cdk-lib/aws-iam";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as cr from "aws-cdk-lib/custom-resources";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import {
  createBaseLambdaConfig,
  createPowertoolsEnv,
  createWorkerEnv,
} from "./lambda-config";
import { StageConfig } from "../config/stage-config";
import { getStageConfig } from "../config";

/**
 * Lambdas — single-source-of-truth construct for every NodejsFunction in the
 * stack. Owns:
 *
 *   API-attached:   ingestion, session-get, pat-attest
 *   Cron / batch:   ip-class-builder, ip-class-discoverer, browser-baseline-builder
 *
 * Plus the EventBridge schedules, custom-resource init invokes, and IAM
 * grants those Lambdas need. Buckets, tables, and secrets remain owned by
 * their respective constructs and are passed in as props.
 *
 * Lambda + LogGroup logical IDs are pinned to their pre-refactor values via
 * `overrideLogicalId` so CFN updates each function in place rather than
 * trying to delete-and-recreate (which would collide on the explicit
 * `functionName` and the explicit `logGroupName`). EventBridge rules and
 * custom resources are stateless and fall through to standard replacement.
 */

interface LambdasConstructProps {
  stackName: string;
  stage: string;

  // Data layer references (not owned here).
  integrityResultsTable: dynamodb.ITable;
  archiveBucket: s3.IBucket; // analytics integrityArchiveBucket
  ipClassBucket: s3.IBucket; // shared by builder + discoverer + browser-baselines

  // Cross-stack (ms-argus-platform) references.
  /** Probe-tokens table NAME — for sigint redemption env var. */
  probeTokensTableName?: string;
  /** Probe-tokens table ARN — for the ingestion `dynamodb:GetItem` grant. */
  probeTokensTableArn?: string;
  /** Merchants table NAME — for session-get `MERCHANTS_TABLE_NAME`. */
  merchantsTableName: string;
  /** Merchants table ARN — for session-get `dynamodb:UpdateItem` grant. */
  merchantsTableArn: string;
  /**
   * Merchant-keys table NAME — for ingestion `MERCHANT_KEYS_TABLE` env var.
   * The ingestion handler resolves cpi → merchantId via this table's
   * `cpi-index` GSI to stamp `merchant_id` on each row.
   */
  merchantKeysTableName?: string;
  /** Merchant-keys table ARN — for ingestion `dynamodb:Query` grant on the cpi-index. */
  merchantKeysTableArn?: string;
  /** SIGINT AES key Secrets Manager ARN. Mounted as env var on ingestion + read at runtime by pat-attest via SecretsManager API. */
  sigintAesKeySecretArn?: string;
  /** SSM SecureString param name holding the ECDH keypair (ingestion ECDH-decrypt). */
  ecdhKeyParamName?: string;
  /** SSM path of the platform's Ed25519 pubkey for merchant token verify. */
  platformPubkeySsmPath: string;
  /** Firehose delivery stream name for ingestion's NDJSON archive dual-write. */
  integrityFirehoseStreamName?: string;

  // Stage-derived config (memory tuning, alarm thresholds, tracing).
  config: StageConfig;
}

export class LambdasConstruct extends Construct {
  // API-attached
  public readonly ingestion: lambdaNode.NodejsFunction;
  public readonly sessionGet: lambdaNode.NodejsFunction;
  public readonly patAttest?: lambdaNode.NodejsFunction;

  // Cron / batch
  public readonly ipClassBuilder: lambdaNode.NodejsFunction;
  public readonly ipClassDiscoverer: lambdaNode.NodejsFunction;
  public readonly browserBaselines: lambdaNode.NodejsFunction;

  /**
   * IpClass-bucket dataset key. Returned so consumers (and the
   * IpClassBucket construct) can wire the right env var + S3 grant.
   */
  public readonly datasetKeys = {
    ipClass: "asn-categories.json.gz",
    autoOverlay: "auto-overlay.json.gz",
    browserBaselines: "browser-baselines.json.gz",
  } as const;

  constructor(scope: Construct, id: string, props: LambdasConstructProps) {
    super(scope, id);

    this.ingestion = this.makeIngestion(props);
    this.sessionGet = this.makeSessionGet(props);
    if (props.sigintAesKeySecretArn) {
      this.patAttest = this.makePatAttest(props);
    }

    this.ipClassBuilder = this.makeIpClassBuilder(props);
    this.ipClassDiscoverer = this.makeIpClassDiscoverer(props);
    this.browserBaselines = this.makeBrowserBaselines(props);

    // Cross-Lambda S3 grants on the IpClass dataset bucket. The bucket
    // itself lives on the IpClassBucket construct; we only do the grants +
    // env-var wiring here.
    props.ipClassBucket.grantPut(this.ipClassBuilder);
    props.ipClassBucket.grantReadWrite(this.ipClassDiscoverer);
    props.ipClassBucket.grantPut(this.browserBaselines);
    props.archiveBucket.grantRead(this.ipClassDiscoverer);
    props.archiveBucket.grantRead(this.browserBaselines);

    this.applyApiLambdaGrants(props);
  }

  // ──────────────────────────────────────────────────────────────────────
  //  API-attached Lambdas
  // ──────────────────────────────────────────────────────────────────────

  private makeIngestion(
    props: LambdasConstructProps,
  ): lambdaNode.NodejsFunction {
    const { stackName, stage, config } = props;

    const logGroup = new logs.LogGroup(this, "IngestionLogGroup", {
      logGroupName: `/aws/lambda/${stackName}-ingestion`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    preserveLogicalId(logGroup, "HttpApiIngestionLogGroup2008CA96");

    const fn = new lambdaNode.NodejsFunction(this, "IngestionFunction", {
      ...createBaseLambdaConfig(),
      functionName: `${stackName}-ingestion`,
      handler: "handler",
      entry: path.join(__dirname, "../../src/handlers/ingestion.ts"),
      memorySize: config.lambda.ingestion.memorySize,
      timeout: Duration.seconds(10),
      logGroup,
      environment: {
        ...createPowertoolsEnv("argus-ingestion", `argus-${stage}`, stage),
        INTEGRITY_RESULTS_TABLE: props.integrityResultsTable.tableName,
        ...(props.ecdhKeyParamName && {
          ECDH_KEY_PARAM: props.ecdhKeyParamName,
        }),
        ...(process.env.INTEGRITY_DEPLOY_SECRET && {
          INTEGRITY_DEPLOY_SECRET: process.env.INTEGRITY_DEPLOY_SECRET,
        }),
        ...(props.sigintAesKeySecretArn && {
          SIGINT_AES_KEY: SecretValue.secretsManager(
            props.sigintAesKeySecretArn,
          ).unsafeUnwrap(),
        }),
        ...(props.probeTokensTableName && {
          PROBE_TOKENS_TABLE_NAME: props.probeTokensTableName,
        }),
        ...(props.merchantKeysTableName && {
          MERCHANT_KEYS_TABLE: props.merchantKeysTableName,
        }),
        ...(props.integrityFirehoseStreamName && {
          INTEGRITY_FIREHOSE_STREAM: props.integrityFirehoseStreamName,
        }),
      },
    });
    preserveLogicalId(fn, "HttpApiIngestionFunction9C2A30B0");
    return fn;
  }

  private makeSessionGet(
    props: LambdasConstructProps,
  ): lambdaNode.NodejsFunction {
    const { stackName, stage, config } = props;

    const logGroup = new logs.LogGroup(this, "SessionGetLogGroup", {
      logGroupName: `/aws/lambda/${stackName}-session-get`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    preserveLogicalId(logGroup, "HttpApiSessionGetLogGroupE0B3FEF1");

    const fn = new lambdaNode.NodejsFunction(this, "SessionGetFunction", {
      ...createBaseLambdaConfig(),
      functionName: `${stackName}-session-get`,
      handler: "handler",
      entry: path.join(__dirname, "../../src/handlers/session-get.ts"),
      memorySize: config.lambda.sessionGet.memorySize,
      timeout: Duration.seconds(10),
      logGroup,
      environment: {
        ...createPowertoolsEnv("argus-session-get", `argus-${stage}`, stage),
        INTEGRITY_RESULTS_TABLE: props.integrityResultsTable.tableName,
        STACK_NAME: stackName,
        PLATFORM_PUBKEY_SSM_PATH: props.platformPubkeySsmPath,
        MERCHANTS_TABLE_NAME: props.merchantsTableName,
      },
    });
    preserveLogicalId(fn, "HttpApiSessionGetFunction9EEFCD4A");
    return fn;
  }

  private makePatAttest(
    props: LambdasConstructProps,
  ): lambdaNode.NodejsFunction {
    const { stackName, stage } = props;
    const sigintAesKeySecretArn = props.sigintAesKeySecretArn;
    if (!sigintAesKeySecretArn) {
      throw new Error("makePatAttest called without sigintAesKeySecretArn");
    }

    const logGroup = new logs.LogGroup(this, "PatAttestLogGroup", {
      logGroupName: `/aws/lambda/${stackName}-pat-attest`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    preserveLogicalId(logGroup, "HttpApiPatAttestLogGroup938E2A72");

    const fn = new lambdaNode.NodejsFunction(this, "PatAttestFunction", {
      ...createBaseLambdaConfig(),
      functionName: `${stackName}-pat-attest`,
      handler: "handler",
      entry: path.join(__dirname, "../../src/handlers/pat-attest.ts"),
      memorySize: 256,
      timeout: Duration.seconds(5),
      logGroup,
      environment: {
        ...createPowertoolsEnv("argus-pat-attest", `argus-${stage}`, stage),
        SIGINT_AES_KEY_SECRET_ARN: sigintAesKeySecretArn,
      },
    });
    preserveLogicalId(fn, "HttpApiPatAttestFunction0CD14068");

    fn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["secretsmanager:GetSecretValue"],
        resources: [sigintAesKeySecretArn],
      }),
    );

    return fn;
  }

  // ──────────────────────────────────────────────────────────────────────
  //  Cron Lambdas (with their schedules + init invokes)
  // ──────────────────────────────────────────────────────────────────────

  private makeIpClassBuilder(
    props: LambdasConstructProps,
  ): lambdaNode.NodejsFunction {
    const { stackName, stage, ipClassBucket } = props;
    const cfg = getStageConfig(stage);

    const fn = new lambdaNode.NodejsFunction(this, "IpClassBuilderFn", {
      ...createBaseLambdaConfig({
        tracing: cfg.lambda.tracingEnabled,
        keepNames: true,
      }),
      entry: path.join(__dirname, "../../src/handlers/ip-class-builder.ts"),
      functionName: `${stackName}-ip-class-builder`,
      memorySize: 512,
      timeout: Duration.minutes(5),
      environment: {
        ...createWorkerEnv(stage, stackName, `${stackName}-ip-class-builder`),
        IP_CLASS_BUCKET: ipClassBucket.bucketName,
        IP_CLASS_KEY: this.datasetKeys.ipClass,
      },
    });
    preserveLogicalId(fn, "IpClassBuilderFn43184800");

    // Weekly cron — Friday 06:00 UTC. IPtoASN refreshes Mondays from BGP RIB
    // dumps; Friday gives us the freshest mid-week-business snapshot.
    const weeklyRule = new events.Rule(this, "IpClassWeeklyRefreshRule", {
      ruleName: `${stackName}-ip-class-weekly`,
      description:
        "Weekly refresh of the ASN→category dataset from IPtoASN.com",
      schedule: events.Schedule.cron({
        weekDay: "FRI",
        hour: "6",
        minute: "0",
      }),
      targets: [new targets.LambdaFunction(fn)],
    });
    preserveLogicalId(weeklyRule, "IpClassWeeklyRefreshRule03910FAE");

    // Initialize on stack create/update — invoke once so the bucket is
    // seeded. Without this, the first cold start after a fresh deploy
    // 404s on asn-categories.json.gz until next Friday.
    const initInvoke = new cr.AwsCustomResource(this, "IpClassInitInvoke", {
      onCreate: {
        service: "Lambda",
        action: "invoke",
        parameters: {
          FunctionName: fn.functionName,
          InvocationType: "RequestResponse",
        },
        physicalResourceId: cr.PhysicalResourceId.of(
          `${stackName}-ip-class-init`,
        ),
      },
      onUpdate: {
        service: "Lambda",
        action: "invoke",
        parameters: {
          FunctionName: fn.functionName,
          InvocationType: "RequestResponse",
        },
        physicalResourceId: cr.PhysicalResourceId.of(
          `${stackName}-ip-class-init-${Date.now()}`,
        ),
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ["lambda:InvokeFunction"],
          resources: [fn.functionArn],
        }),
      ]),
      timeout: Duration.minutes(6),
    });
    initInvoke.node.addDependency(fn);
    // (Custom resource has no explicit physical name — safe to let CFN
    // replace its logical ID. Re-fires the builder Lambda on stack update,
    // which is identical to a normal weekly cron run.)

    return fn;
  }

  private makeIpClassDiscoverer(
    props: LambdasConstructProps,
  ): lambdaNode.NodejsFunction {
    const { stackName, stage, ipClassBucket, archiveBucket } = props;
    const cfg = getStageConfig(stage);

    const fn = new lambdaNode.NodejsFunction(this, "IpClassDiscovererFn", {
      ...createBaseLambdaConfig({
        tracing: cfg.lambda.tracingEnabled,
        keepNames: true,
      }),
      entry: path.join(__dirname, "../../src/handlers/ip-class-discoverer.ts"),
      functionName: `${stackName}-ip-class-discoverer`,
      memorySize: 1024,
      timeout: Duration.minutes(15),
      environment: {
        ...createWorkerEnv(
          stage,
          stackName,
          `${stackName}-ip-class-discoverer`,
        ),
        IP_CLASS_BUCKET: ipClassBucket.bucketName,
        IP_CLASS_AUTO_OVERLAY_KEY: this.datasetKeys.autoOverlay,
        INTEGRITY_ARCHIVE_BUCKET: archiveBucket.bucketName,
      },
      reservedConcurrentExecutions: 1,
    });
    preserveLogicalId(fn, "IpClassDiscovererDiscovererFn24C17617");

    const dailyRule = new events.Rule(this, "IpClassDiscovererDailyRule", {
      ruleName: `${stackName}-ip-class-discoverer-daily`,
      description:
        "Daily RDAP-discovery walk over recent unmapped IPs in the integrity archive",
      schedule: events.Schedule.cron({ hour: "3", minute: "0" }),
      targets: [new targets.LambdaFunction(fn)],
    });
    preserveLogicalId(dailyRule, "IpClassDiscovererDailyRule5247F4C0");

    return fn;
  }

  private makeBrowserBaselines(
    props: LambdasConstructProps,
  ): lambdaNode.NodejsFunction {
    const { stackName, stage, ipClassBucket, archiveBucket } = props;
    const cfg = getStageConfig(stage);

    const fn = new lambdaNode.NodejsFunction(
      this,
      "BrowserBaselinesBuilderFn",
      {
        ...createBaseLambdaConfig({
          tracing: cfg.lambda.tracingEnabled,
          keepNames: true,
        }),
        entry: path.join(
          __dirname,
          "../../src/handlers/browser-baseline-builder.ts",
        ),
        functionName: `${stackName}-browser-baseline-builder`,
        memorySize: 1024,
        timeout: Duration.minutes(10),
        environment: {
          ...createWorkerEnv(
            stage,
            stackName,
            `${stackName}-browser-baseline-builder`,
          ),
          IP_CLASS_BUCKET: ipClassBucket.bucketName,
          BROWSER_BASELINES_KEY: this.datasetKeys.browserBaselines,
          INTEGRITY_ARCHIVE_BUCKET: archiveBucket.bucketName,
        },
        reservedConcurrentExecutions: 1,
      },
    );
    preserveLogicalId(fn, "BrowserBaselinesBuilderFn80DC642D");

    const dailyRule = new events.Rule(this, "BrowserBaselinesDailyRule", {
      ruleName: `${stackName}-browser-baseline-daily`,
      description:
        "Daily aggregation of browser-engine invariant baselines from recent sessions",
      schedule: events.Schedule.cron({ hour: "4", minute: "0" }),
      targets: [new targets.LambdaFunction(fn)],
    });
    preserveLogicalId(dailyRule, "BrowserBaselinesDailyRule656B4D82");

    return fn;
  }

  // ──────────────────────────────────────────────────────────────────────
  //  IAM grants for the API-attached Lambdas. Cron-Lambda grants are
  //  applied inline in their make*() above.
  // ──────────────────────────────────────────────────────────────────────

  private applyApiLambdaGrants(props: LambdasConstructProps): void {
    // ── ingestion ──
    props.integrityResultsTable.grantWriteData(this.ingestion);

    if (props.probeTokensTableArn) {
      this.ingestion.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["dynamodb:GetItem"],
          resources: [props.probeTokensTableArn],
        }),
      );
    }
    if (props.sigintAesKeySecretArn) {
      this.ingestion.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["secretsmanager:GetSecretValue"],
          resources: [props.sigintAesKeySecretArn],
        }),
      );
    }
    if (props.ecdhKeyParamName) {
      this.ingestion.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["ssm:GetParameter"],
          resources: [
            `arn:aws:ssm:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:parameter${props.ecdhKeyParamName}`,
          ],
        }),
      );
    }

    // Cross-stack: Query the platform's merchant-keys cpi-index to resolve
    // cpi → merchantId on the ingest path. Cached in Lambda memory, so
    // this grant is exercised only on first request per cpi per container.
    if (props.merchantKeysTableArn) {
      this.ingestion.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ["dynamodb:Query"],
          resources: [
            props.merchantKeysTableArn,
            `${props.merchantKeysTableArn}/index/*`,
          ],
        }),
      );
    }

    // ── session-get ──
    props.integrityResultsTable.grantReadData(this.sessionGet);

    this.sessionGet.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["ssm:GetParameter"],
        resources: [
          `arn:aws:ssm:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:parameter${props.platformPubkeySsmPath}`,
        ],
      }),
    );

    // Atomic credit decrement on the platform's merchants table — billing
    // happens here, on each successful session-get. Conditional UpdateItem
    // with `credits >= :one` returns 402 from the handler when it fails.
    this.sessionGet.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["dynamodb:UpdateItem"],
        resources: [props.merchantsTableArn],
      }),
    );
  }
}

/**
 * Pin a CDK-generated logical ID to a fixed value. Used to preserve the
 * pre-refactor IDs of stateful resources whose physical names would
 * collide if CFN tried to delete-and-recreate.
 */
function preserveLogicalId(resource: Construct, id: string): void {
  const cfn = resource.node.defaultChild as cdk.CfnResource | undefined;
  if (!cfn) {
    throw new Error(
      `preserveLogicalId: ${resource.node.path} has no defaultChild`,
    );
  }
  cfn.overrideLogicalId(id);
}
