// lib/constructs/secrets.ts
import { Construct } from "constructs";
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
 * IMPORTANT: Automatic key rotation has been disabled.
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
  }
}
