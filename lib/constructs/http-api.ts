// lib/constructs/http-api.ts

import { Construct } from "constructs";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as apigatewayv2 from "aws-cdk-lib/aws-apigatewayv2";
import * as integrations from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as logs from "aws-cdk-lib/aws-logs";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import { Duration } from "aws-cdk-lib";
import { StageConfig } from "../config/stage-config";

interface HttpApiConstructProps {
  stackName: string;
  alarmsTopic: sns.ITopic;
  config: StageConfig;

  /** Pre-built ingestion Lambda from LambdasConstruct. */
  ingestionFunction: lambda.Function;
  /** Pre-built session-get Lambda. (Wired only for log-group import here —
   *  routes are on RestApiConstruct, not the HTTP API.) */
  sessionGetFunction: lambda.Function;
  /** Pre-built PAT-attestation Lambda. Routes only mount when present. */
  patAttestFunction?: lambda.Function;
}

/**
 * HttpApiConstruct — owns the HTTP API Gateway and route mounting only.
 * Lambdas come in pre-built via props (LambdasConstruct is the single
 * source of truth for NodejsFunction creation).
 *
 * Routes:
 *   GET  /health                  → ingestion
 *   POST /v1/integrity-collect    → ingestion
 *   OPTIONS /v1/integrity-collect → ingestion (CORS preflight via middleware)
 *   GET  /v1/pat-attestation      → patAttest (when present)
 *   OPTIONS /v1/pat-attestation   → patAttest
 *   GET  /v1/pat-test             → patAttest (transient HTML test page)
 *
 * CORS: handled at the Lambda layer via `helpers/cors-middleware.ts` —
 * `credentials: 'include'` requires per-request Origin reflection, which
 * API GW's static corsPreflight can't do.
 *
 * Logical IDs preserved across the refactor:
 *   - HTTP API itself: top-level child of this construct, named "HttpApi"
 *   - Integration logical IDs derived from "IngestionIntegration" /
 *     "PatAttestIntegration" stay stable because both this construct's
 *     instance name ("HttpApi") and the integration ids are unchanged.
 */
export class HttpApiConstruct extends Construct {
  public readonly api: apigatewayv2.HttpApi;
  public readonly apiEndpoint: string;

  constructor(scope: Construct, id: string, props: HttpApiConstructProps) {
    super(scope, id);

    this.api = new apigatewayv2.HttpApi(this, "HttpApi", {
      apiName: `${props.stackName}-api`,
      description: "Argus integrity collection API",
    });

    const ingestionIntegration = new integrations.HttpLambdaIntegration(
      "IngestionIntegration",
      props.ingestionFunction,
    );

    this.api.addRoutes({
      path: "/health",
      methods: [apigatewayv2.HttpMethod.GET],
      integration: ingestionIntegration,
    });

    this.api.addRoutes({
      path: "/v1/integrity-collect",
      methods: [apigatewayv2.HttpMethod.POST, apigatewayv2.HttpMethod.OPTIONS],
      integration: ingestionIntegration,
    });

    if (props.patAttestFunction) {
      const patIntegration = new integrations.HttpLambdaIntegration(
        "PatAttestIntegration",
        props.patAttestFunction,
      );

      this.api.addRoutes({
        path: "/v1/pat-attestation",
        methods: [apigatewayv2.HttpMethod.GET, apigatewayv2.HttpMethod.OPTIONS],
        integration: patIntegration,
      });

      // Transient first-party HTML test page (same Lambda; deleted with
      // test-page.ts when smoke test concludes).
      this.api.addRoutes({
        path: "/v1/pat-test",
        methods: [apigatewayv2.HttpMethod.GET],
        integration: patIntegration,
      });
    }

    // Suppress unused-prop lint — sessionGet is wired only to RestApi but
    // we accept it on the props bag so a future dashboard route could mount
    // here without churning the surface.
    void props.sessionGetFunction;
    void logs;

    this.apiEndpoint = this.api.apiEndpoint;

    if (props.config.alarms.enabled) {
      this.createIngestionAlarms(
        props.stackName,
        props.alarmsTopic,
        props.ingestionFunction,
      );
    }
  }

  private createIngestionAlarms(
    stackName: string,
    alarmsTopic: sns.ITopic,
    ingestion: lambda.Function,
  ): void {
    const errorsAlarm = new cloudwatch.Alarm(this, "IngestionErrorsAlarm", {
      metric: ingestion.metricErrors({
        period: Duration.minutes(5),
        statistic: "Sum",
      }),
      threshold: 10,
      evaluationPeriods: 2,
      alarmDescription: `${stackName} ingestion Lambda errors > 10 in 5 min`,
    });
    errorsAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    const durationAlarm = new cloudwatch.Alarm(this, "IngestionDurationAlarm", {
      metric: ingestion.metricDuration({
        period: Duration.minutes(5),
        statistic: "p99",
      }),
      threshold: 5000,
      evaluationPeriods: 3,
      alarmDescription: `${stackName} ingestion Lambda p99 duration > 5s`,
    });
    durationAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));

    const throttlesAlarm = new cloudwatch.Alarm(
      this,
      "IngestionThrottlesAlarm",
      {
        metric: ingestion.metricThrottles({
          period: Duration.minutes(5),
          statistic: "Sum",
        }),
        threshold: 5,
        evaluationPeriods: 2,
        alarmDescription: `${stackName} ingestion Lambda throttled > 5 times`,
      },
    );
    throttlesAlarm.addAlarmAction(new actions.SnsAction(alarmsTopic));
  }
}
