import * as cdk from "aws-cdk-lib";
import * as ssm from "aws-cdk-lib/aws-ssm";

export interface SharedDataContracts {
  sigintSecretId: string;
  sigintSecretArn: string;
  probeTokensTableName: string;
  probeTokensTableArn: string;
  merchantsTableName: string;
  merchantsTableArn: string;
  merchantKeysTableName: string;
  merchantKeysTableArn: string;
  integrityResultsTableName: string;
  integrityResultsTableArn: string;
}

export function sharedDataSsmPath(
  environment: string,
  contract: string,
): string {
  return `/argus/${environment}/data/${contract}`;
}

/**
 * Resolve shared data contracts at CloudFormation deployment time.
 *
 * `valueForStringParameter` deliberately avoids CDK context lookups. Infra is
 * the only prerequisite stack; API no longer needs Platform to have already
 * synthesized or deployed its peer exports.
 */
export function resolveSharedDataContracts(
  scope: cdk.Stack,
  environment: string,
): SharedDataContracts {
  const get = (contract: string) =>
    ssm.StringParameter.valueForStringParameter(
      scope,
      sharedDataSsmPath(environment, contract),
    );
  const sigintSecretId = get("sigint-aes-key-secret-name");

  return {
    sigintSecretId,
    sigintSecretArn: scope.formatArn({
      service: "secretsmanager",
      resource: "secret",
      resourceName: `${sigintSecretId}-*`,
      arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME,
    }),
    probeTokensTableName: get("probe-tokens-table-name"),
    probeTokensTableArn: get("probe-tokens-table-arn"),
    merchantsTableName: get("merchants-table-name"),
    merchantsTableArn: get("merchants-table-arn"),
    merchantKeysTableName: get("merchant-keys-table-name"),
    merchantKeysTableArn: get("merchant-keys-table-arn"),
    integrityResultsTableName: get("integrity-results-table-name"),
    integrityResultsTableArn: get("integrity-results-table-arn"),
  };
}
