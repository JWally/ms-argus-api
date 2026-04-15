# Vector admin API — authentication

The `VectorTestApi` (deployed by `lib/constructs/vector-worker.ts`) exposes
admin/operator routes over Qdrant:

- `GET  /v1/vector/health`
- `POST /v1/vector/search`
- `POST /v1/vector/upsert`
- `POST /v1/vector/collection`

All four routes are gated with **IAM authorization** (`HttpIamAuthorizer`).
Callers must sign requests with SigV4 using credentials that have
`execute-api:Invoke` on the API.

## Endpoint discovery

```bash
aws apigatewayv2 get-apis \
  --query "Items[?contains(Name, 'vector-test')].ApiEndpoint" --output text
```

## Invoking from the CLI

### Option A — `awscurl` (recommended)

```bash
pip install awscurl   # one-time

awscurl --service execute-api \
  "$(aws apigatewayv2 get-apis \
     --query "Items[?contains(Name, 'vector-test')].ApiEndpoint" \
     --output text)/v1/vector/health"
```

### Option B — plain `curl` with SigV4

Requires `curl` 7.75+ built with `--aws-sigv4` support.

```bash
AWS_REGION=us-east-1
API=$(aws apigatewayv2 get-apis \
       --query "Items[?contains(Name, 'vector-test')].ApiEndpoint" \
       --output text)

curl --aws-sigv4 "aws:amz:${AWS_REGION}:execute-api" \
     --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
     -H "x-amz-security-token: ${AWS_SESSION_TOKEN}" \
     "${API}/v1/vector/health"
```

### Option C — Node SDK / Python boto3

Sign the request with `@aws-sdk/signature-v4` (Node) or `botocore.auth.SigV4Auth`
(Python). Any AWS SDK works; this is the same pattern used by internal services.

## Expected responses

| Request                                    | Status | Meaning                     |
| ------------------------------------------ | ------ | --------------------------- |
| Unsigned                                   | `403`  | `Forbidden` — missing SigV4 |
| Signed by principal without IAM permission | `403`  | IAM policy denies invoke    |
| Signed by principal with invoke permission | `2xx`  | Handler executes            |

## Granting access

Attach a policy like the following to the IAM user / role that should
be able to hit the admin API:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:us-east-1:*:<api-id>/*/*/v1/vector/*"
    }
  ]
}
```

Replace `<api-id>` with the ID from `aws apigatewayv2 get-apis` above.

## Rationale

These routes perform direct Qdrant reads/writes (search, upsert, create
collection). They are intentionally **not** covered by the merchant
`integrity-api-key` — that key authenticates server-to-server calls from
trusted proxies (e.g., ms-argus-games), not operator admin actions. IAM
auth means:

- No static secret to rotate or leak.
- Existing AWS credentials used for `cdk deploy` also invoke these routes.
- Access revocation is immediate via IAM policy change — no restart needed.
