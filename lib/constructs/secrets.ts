// lib/constructs/secrets.ts
import { Construct } from "constructs";
import * as cdk from "aws-cdk-lib";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";

interface SecretConstructProps {
  environment: string;
  stackName: string;
  stage: string;
  projectName: string;
}

/**
 * Secret construct for encryption and HMAC keys.
 *
 * IMPORTANT: Automatic key rotation has been disabled (AR-18).
 *
 * Reason: The previous 48-hour rotation destroyed old keys, making historical
 * encrypted data unrecoverable. This prevented debugging, reprocessing, and
 * recovery of data older than 48 hours.
 *
 * Current approach: Long-lived keys with manual rotation via quarterly review.
 * Future: Implement envelope encryption with KMS for proper key versioning.
 *
 * Secret structure includes a version field for future migration to envelope encryption.
 */
export class SecretConstruct extends Construct {
  public readonly secret: secretsmanager.Secret;
  /** AR-131: API keys secret for tenant authentication */
  public readonly apiKeysSecret: secretsmanager.Secret;

  constructor(scope: Construct, id: string, props: SecretConstructProps) {
    super(scope, id);

    const { projectName, stage } = props;

    // Create the secret with initial keys
    // Version field added for future migration to envelope encryption
    this.secret = new secretsmanager.Secret(this, `SECURITY_KEY_${id}`, {
      secretName: `${stage}/${projectName}`,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          version: "1",
        }),
        generateStringKey: "HMAC_KEY",
        excludePunctuation: true,
        passwordLength: 64,
      },
    });

    // AR-131: Create API keys secret for tenant authentication
    // Format: { "api-key-1": "tenant-id-1", "api-key-2": "tenant-id-2" }
    // Initial value is empty object - populate via AWS Console or CLI
    this.apiKeysSecret = new secretsmanager.Secret(this, `API_KEYS_${id}`, {
      secretName: `${stage}/${projectName}/api-keys`,
      description: "API keys to tenant ID mapping for authentication",
      secretStringValue: cdk.SecretValue.unsafePlainText(JSON.stringify({})),
    });
  }
}
