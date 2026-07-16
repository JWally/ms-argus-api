import { App, CfnOutput, Stack } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { describe, expect, it } from "vitest";
import {
  resolveSharedDataContracts,
  sharedDataSsmPath,
} from "./shared-data-contracts";

describe("shared data contracts", () => {
  it("uses the infra-owned canonical namespace", () => {
    expect(sharedDataSsmPath("dev-jw", "merchants-table-name")).toBe(
      "/argus/dev-jw/data/merchants-table-name",
    );
  });

  it("resolves contracts as deployment-time SSM references", () => {
    const app = new App();
    const stack = new Stack(app, "ContractConsumer", {
      env: { account: "111111111111", region: "us-east-1" },
    });
    const contracts = resolveSharedDataContracts(stack, "dev-test");
    new CfnOutput(stack, "MerchantsTableName", {
      value: contracts.merchantsTableName,
    });
    new CfnOutput(stack, "SigintSecretArn", {
      value: contracts.sigintSecretArn,
    });

    const synthesized = Template.fromStack(stack).toJSON();
    const parameters = Object.values(synthesized.Parameters ?? {});
    expect(parameters).toEqual(
      expect.arrayContaining([
        {
          Type: "AWS::SSM::Parameter::Value<String>",
          Default: "/argus/dev-test/data/merchants-table-name",
        },
        {
          Type: "AWS::SSM::Parameter::Value<String>",
          Default: "/argus/dev-test/data/sigint-aes-key-secret-name",
        },
      ]),
    );
    expect(JSON.stringify(synthesized.Outputs?.SigintSecretArn)).toContain(
      "secretsmanager:us-east-1:111111111111:secret:",
    );
    expect(JSON.stringify(synthesized.Outputs?.SigintSecretArn)).toContain(
      "-*",
    );
  });
});
