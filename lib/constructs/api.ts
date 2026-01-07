// lib/constructs/api.ts
import { Construct } from 'constructs';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpMethod } from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as actions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Duration } from 'aws-cdk-lib';
import { LambdaConstruct } from './lambda';

export class HttpApiConstruct extends Construct {
  public readonly api: apigwv2.HttpApi;
  public readonly stage: apigwv2.HttpStage;

  constructor(
    scope: Construct,
    id: string,
    lambdaConstruct: LambdaConstruct,
    stackName: string,
    alarmsTopic: sns.ITopic,
  ) {
    super(scope, id);

    const name = stackName || 'ms-argus-api';

    // Access Logs
    const logGroup = new logs.LogGroup(this, `${name}-httpapi-logs`, {
      retention: logs.RetentionDays.ONE_MONTH,
    });
    logGroup.grantWrite(new iam.ServicePrincipal('apigateway.amazonaws.com'));

    // HTTP API (v2)
    this.api = new apigwv2.HttpApi(this, `${name}-httpapi`, {
      apiName: name,
      corsPreflight: {
        allowOrigins: ['*'],
        allowMethods: [
          apigwv2.CorsHttpMethod.GET,
          apigwv2.CorsHttpMethod.POST,
          apigwv2.CorsHttpMethod.OPTIONS,
        ],
        allowHeaders: ['Content-Type', 'Authorization'],
        maxAge: Duration.days(1),
      },
      createDefaultStage: false,
    });

    // Named 'prod' stage
    this.stage = new apigwv2.HttpStage(this, `${name}-stage`, {
      httpApi: this.api,
      stageName: 'prod',
      autoDeploy: true,
    });

    // Lambda integration for collect endpoint
    const collectIntegration = new HttpLambdaIntegration(
      `${name}-collect-int`,
      lambdaConstruct.collectFunction,
    );

    // POST /v1/collect - main fingerprint collection endpoint
    this.api.addRoutes({
      path: '/v1/collect',
      methods: [HttpMethod.POST],
      integration: collectIntegration,
    });

    // GET /health - health check endpoint
    this.api.addRoutes({
      path: '/health',
      methods: [HttpMethod.GET],
      integration: collectIntegration,
    });

    // Create alarms
    this.createHttpApiAlarms(name, alarmsTopic);
  }

  private createHttpApiAlarms(name: string, alarmsTopic: sns.ITopic) {
    const dims = {
      ApiId: this.api.apiId,
      Stage: this.stage.stageName,
    };

    const metric = (metricName: string, stat = 'Sum') =>
      new cloudwatch.Metric({
        namespace: 'AWS/ApiGateway',
        metricName,
        dimensionsMap: dims,
        period: Duration.minutes(5),
        statistic: stat,
      });

    // 4XX alarm
    const m4xx = metric('4xx');
    const a4xx = new cloudwatch.Alarm(this, `${name}-4XX-errors`, {
      metric: m4xx,
      threshold: 10,
      evaluationPeriods: 2,
      alarmDescription: 'HTTP API 4XX error count exceeded threshold',
    });
    a4xx.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // 5XX alarm
    const m5xx = metric('5xx');
    const a5xx = new cloudwatch.Alarm(this, `${name}-5XX-errors`, {
      metric: m5xx,
      threshold: 5,
      evaluationPeriods: 1,
      alarmDescription: 'HTTP API 5XX error count exceeded threshold',
    });
    a5xx.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // p95 Latency alarm
    const mLatency = metric('Latency', 'p95');
    const aLatency = new cloudwatch.Alarm(this, `${name}-high-latency`, {
      metric: mLatency,
      threshold: 1000,
      evaluationPeriods: 2,
      alarmDescription: 'HTTP API p95 latency exceeds 1s',
    });
    aLatency.addAlarmAction(new actions.SnsAction(alarmsTopic));

    // No traffic alarm
    const mCount = metric('Count');
    const aNoTraffic = new cloudwatch.Alarm(this, `${name}-no-traffic`, {
      metric: mCount,
      threshold: 0,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription: 'No requests recorded over 10 minutes',
    });
    aNoTraffic.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }
}
