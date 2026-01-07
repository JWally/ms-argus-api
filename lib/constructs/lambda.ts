// lib/constructs/lambda.ts
import * as path from 'path';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda-nodejs';
import { Runtime, Tracing, Architecture } from 'aws-cdk-lib/aws-lambda';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { OutputFormat } from 'aws-cdk-lib/aws-lambda-nodejs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import { Duration } from 'aws-cdk-lib';
import * as actions from 'aws-cdk-lib/aws-cloudwatch-actions';

interface LambdaConstructProps {
  environment: string;
  stackName: string;
  stage: string;
  projectName: string;
  alarmsTopic: sns.ITopic;
}

/**
 * LambdaConstruct for Argus API
 * Creates the collect Lambda function with monitoring
 */
export class LambdaConstruct extends Construct {
  private readonly alarmsTopic: sns.ITopic;
  public readonly collectFunction: lambda.NodejsFunction;

  constructor(scope: Construct, id: string, props: LambdaConstructProps) {
    super(scope, id);

    const { environment, stackName, projectName, stage, alarmsTopic } = props;

    this.alarmsTopic = alarmsTopic;

    // Secrets Manager reference
    const secret = secretsmanager.Secret.fromSecretNameV2(
      this,
      `SECURITY_KEY_${id}`,
      `${stage}/${projectName}`,
    );

    // Common Lambda configuration
    const commonConfig = {
      runtime: Runtime.NODEJS_20_X,
      architecture: Architecture.ARM_64,
      memorySize: 1024,
      timeout: Duration.seconds(30),
      bundling: {
        minify: true,
        sourceMap: true,
        target: 'node20',
        keepNames: true,
        format: OutputFormat.CJS,
        mainFields: ['module', 'main'],
        environment: { NODE_ENV: 'production' },
      },
      environment: {
        AWS_NODEJS_CONNECTION_REUSE_ENABLED: '1',
        ENVIRONMENT: environment,
        POWERTOOLS_SERVICE_NAME: stackName,
        POWERTOOLS_METRICS_NAMESPACE: stackName,
        LOG_LEVEL: 'INFO',
        SECRET_KEY_ARN: secret.secretArn,
      },
      tracing: Tracing.ACTIVE,
    };

    // IAM Logging Policy
    const IAM_LOGGING_POLICY = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
      resources: ['*'],
    });

    // Create collect Lambda (main fingerprint ingestion endpoint)
    this.collectFunction = new lambda.NodejsFunction(this, `${stackName}-collect`, {
      ...commonConfig,
      entry: path.join(__dirname, '../../src/handlers/collect.ts'),
      functionName: `${stackName}-collect`,
    });

    // Attach logging policy
    this.collectFunction.addToRolePolicy(IAM_LOGGING_POLICY);

    // Create alarms
    this.createLambdaAlarms(this.collectFunction, 'CollectFn');

    // Grant secrets read access
    secret.grantRead(this.collectFunction);
  }

  private createLambdaAlarms(fn: lambda.NodejsFunction, alarmPrefix: string) {
    // Error count alarm
    const alarmErrorCount = new cloudwatch.Alarm(this, `${alarmPrefix}-Errors`, {
      metric: fn.metricErrors({
        period: Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 5,
      evaluationPeriods: 1,
      alarmDescription: `Lambda ${fn.functionName} has > 5 errors in a 5-minute interval`,
    });
    alarmErrorCount.addAlarmAction(new actions.SnsAction(this.alarmsTopic));

    // Throttle alarm
    const alarmThrottle = new cloudwatch.Alarm(this, `${alarmPrefix}-Throttles`, {
      metric: fn.metricThrottles({
        period: Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 1,
      evaluationPeriods: 1,
      alarmDescription: `Lambda ${fn.functionName} is throttled`,
    });
    alarmThrottle.addAlarmAction(new actions.SnsAction(this.alarmsTopic));

    // High Duration (p95)
    const alarmP95 = new cloudwatch.Alarm(this, `${alarmPrefix}-HighDuration`, {
      metric: fn.metricDuration({
        period: Duration.minutes(5),
        statistic: 'p95',
      }),
      threshold: 3000,
      evaluationPeriods: 2,
      alarmDescription: `Lambda ${fn.functionName} p95 duration > 3s over 2 intervals`,
    });
    alarmP95.addAlarmAction(new actions.SnsAction(this.alarmsTopic));
  }
}
