// lib/constructs/secrets.ts
import * as path from "path";
import { Construct } from "constructs";
import { Duration } from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda-nodejs";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import { Runtime, Tracing } from "aws-cdk-lib/aws-lambda";
import { OutputFormat } from "aws-cdk-lib/aws-lambda-nodejs";

interface SecretConstructProps {
  environment: string;
  stackName: string;
  stage: string;
  projectName: string;
}

export class SecretConstruct extends Construct {
  public readonly secret: secretsmanager.Secret;

  constructor(scope: Construct, id: string, props: SecretConstructProps) {
    super(scope, id);

    const { stackName, environment, projectName, stage } = props;

    // Create the secret with initial HMAC_KEY
    this.secret = new secretsmanager.Secret(this, `SECURITY_KEY_${id}`, {
      secretName: `${stage}/${projectName}`,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({}),
        generateStringKey: "HMAC_KEY",
        excludePunctuation: true,
        passwordLength: 64,
      },
    });

    // Common Lambda configuration for rotation
    const commonConfig = {
      runtime: Runtime.NODEJS_20_X,
      memorySize: 1024,
      bundling: {
        minify: true,
        sourceMap: true,
        target: "node20",
        keepNames: true,
        format: OutputFormat.CJS,
        mainFields: ["module", "main"],
        environment: { NODE_ENV: "production" },
      },
      environment: {
        AWS_NODEJS_CONNECTION_REUSE_ENABLED: "1",
        ENVIRONMENT: environment,
        POWERTOOLS_SERVICE_NAME: stackName,
        POWERTOOLS_METRICS_NAMESPACE: stackName,
        LOG_LEVEL: "INFO",
      },
      tracing: Tracing.ACTIVE,
    };

    const rotationFunction = new lambda.NodejsFunction(
      this,
      `${stackName}-secret-rotation`,
      {
        ...commonConfig,
        entry: path.join(__dirname, "../../src/services/rotate-aws-secrets.ts"),
        functionName: `${stackName}-secret-rotation`,
        environment: {
          SECRET_ARN: this.secret.secretArn,
        },
      },
    );

    // Grant permission for the Lambda to update the secret
    this.secret.grantWrite(rotationFunction);

    // Schedule rotation every 48 hours
    const rotationSchedule = new events.Rule(this, "RotationSchedule", {
      schedule: events.Schedule.rate(Duration.hours(48)),
    });

    rotationSchedule.addTarget(new targets.LambdaFunction(rotationFunction));
  }
}
