// lib/constructs/post-deploy-warmer.ts
//
// Fires a single async warmup invoke at each target on every deploy, so the
// user-facing path isn't cold for the first real request after a release.
//
// The recurring heaters can take up to a minute to reach a newly published
// alias version. This deployment-triggered ping closes that first-minute gap.
//
// Targets MUST short-circuit the warmup event as a no-op. The handlers use
// @middy/warmup, whose default detector matches `source ===
// "serverless-plugin-warmup"` — so that's the payload we send. The invoke is
// async (InvocationType: Event); we don't wait on or read the result.

import { Construct } from "constructs";
import * as cr from "aws-cdk-lib/custom-resources";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";

export interface PostDeployWarmerProps {
  /** Functions/aliases to wake. Each must no-op on a `{warmup:true}` event. */
  targets: lambda.IFunction[];
  /**
   * A value that changes on every synth (e.g. `Date.now().toString()`), so the
   * custom resource is seen as changed each deploy and re-fires the warm.
   */
  deployId: string;
}

export class PostDeployWarmer extends Construct {
  constructor(scope: Construct, id: string, props: PostDeployWarmerProps) {
    super(scope, id);

    for (const [idx, fn] of props.targets.entries()) {
      // onUpdate also covers create. The deployId in the physicalResourceId
      // forces a re-run on every deploy (not just when the target changes).
      new cr.AwsCustomResource(this, `Warm${idx}`, {
        onUpdate: {
          service: "Lambda",
          action: "invoke",
          parameters: {
            FunctionName: fn.functionArn,
            InvocationType: "Event",
            Payload: JSON.stringify({ source: "serverless-plugin-warmup" }),
          },
          physicalResourceId: cr.PhysicalResourceId.of(
            `warm-${idx}-${props.deployId}`,
          ),
        },
        policy: cr.AwsCustomResourcePolicy.fromStatements([
          new iam.PolicyStatement({
            actions: ["lambda:InvokeFunction"],
            resources: [fn.functionArn],
          }),
        ]),
        installLatestAwsSdk: false,
      });
    }
  }
}
