# Claude Code Workflow for ms-argus-api

## Quick Start

Work through JIRA tickets autonomously. For each ticket:

1. **Get ticket** → Query JIRA for To Do tickets (bugs first, then by priority P0-P3)
2. **Branch** → `git checkout -b AR-XX`
3. **Implement** → Make changes
4. **Test** → `npm test` (517+ tests must pass)
5. **Deploy** → `npx cdk deploy ms-argus-api-dev-jw --require-approval never`
6. **Integration test** → `cd ~/Dev/ms-argus-automation && npm test`
7. **PR** → `gh pr create` then `gh pr merge --squash --delete-branch`
8. **JIRA** → Transition to Done, add completion comment
9. **Repeat** → Return to step 1

---

## JIRA API

Credentials in `~/Dev/jira.txt`:

```bash
JIRA_TOKEN=$(grep "token:" ~/Dev/jira.txt | cut -d' ' -f2)
```

### Query Tickets

```bash
# Get To Do tickets (bugs first)
curl -s -X POST \
  -u "jira@wolcott.io:$JIRA_TOKEN" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  --data '{
    "jql": "project = AR AND status = \"To Do\" ORDER BY rank ASC",
    "fields": ["key", "summary", "description", "priority", "issuetype"],
    "maxResults": 20
  }' \
  "https://wolcott.atlassian.net/rest/api/3/search/jql"
```

### Transition Ticket

```bash
# To In Progress (id: 21)
curl -s -X POST -u "jira@wolcott.io:$JIRA_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"transition": {"id": "21"}}' \
  "https://wolcott.atlassian.net/rest/api/3/issue/AR-XX/transitions"

# To Done (id: 31)
curl -s -X POST -u "jira@wolcott.io:$JIRA_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"transition": {"id": "31"}}' \
  "https://wolcott.atlassian.net/rest/api/3/issue/AR-XX/transitions"
```

### Add Comment

```bash
curl -s -X POST -u "jira@wolcott.io:$JIRA_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "body": {
      "type": "doc", "version": 1,
      "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Completed via PR #XX."}]}]
    }
  }' \
  "https://wolcott.atlassian.net/rest/api/3/issue/AR-XX/comment"
```

---

## Commands

### Local Development

```bash
npm run format       # Prettier
npm run lint:test    # ESLint (warnings OK, errors fail)
npm test             # Vitest unit tests (593+)
```

### Deployment

```bash
npx cdk deploy ms-argus-api-dev-jw --require-approval never
```

### Integration Tests

```bash
cd ~/Dev/ms-argus-automation
npm test                          # All tests
npx playwright test tests/api/    # API tests only
npx playwright test tests/security/  # Security tests
```

---

## Git Workflow

```bash
# Start work
git checkout main && git pull origin main
git checkout -b AR-XX

# Commit
git add . && git commit -m "$(cat <<'EOF'
AR-XX: Brief summary

- Detail 1
- Detail 2

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"

# Push and PR
git push -u origin AR-XX
gh pr create --title "AR-XX: Summary" --body "..."
gh pr merge --squash --delete-branch
```

---

## Priority Order

1. **Bug** tickets (fix broken functionality)
2. **P0** - Critical blockers
3. **P1** - High priority
4. **P2** - Medium priority
5. **P3** - Low priority

---

## Architecture

```
Browser → CloudFront → API Gateway (HTTP API) → Lambda (Ingestion) → SQS
                                                                      ↓
                                                          Lambda (Matching) → DynamoDB
                                                                      ↓
                                                          SQS → Lambda (Profile) → DynamoDB

EventBridge (daily) → Lambda (Cardinality Recalc) → DynamoDB (Tier2Buckets)
```

AR-52: Replaced Go/ECS ingestion with HTTP API + Lambda. Replaced Redis cache with DynamoDB session cache.
AR-130: Added daily cardinality recalculation Lambda to fix bucket stats drift.
AR-149/AR-150: Tier-gated identity association - prevents viral spreading of device_ids from low-confidence Tier 2 matches.

### Key Files

| Purpose            | Location                     |
| ------------------ | ---------------------------- |
| Lambda handlers    | `src/handlers/`              |
| Services           | `src/services/`              |
| CDK infrastructure | `lib/constructs/`            |
| Tests              | `src/**/*.test.ts`, `tests/` |

### DynamoDB Tables

- `Profiles` - Device fingerprint profiles
- `Tier1Index` - Hash lookups (evercookie, stable, fuzzy, public_key, sigint_id)
- `Tier2Buckets` - Compound filter matching
- `SessionCache` - Session state and mutation gates (AR-52)

---

## Merge Checklist

Before merging ANY PR:

- [ ] Unit tests pass (`npm test` - all 593+)
- [ ] Lint passes (warnings OK)
- [ ] Deployed to dev (`cdk deploy ms-argus-api-dev-jw`)
- [ ] Integration tests pass (`cd ms-argus-automation && npm test`)

**Never merge without deploy + integration verification.**

---

## Ticket Completion Template

```bash
# After merge, update JIRA:
JIRA_TOKEN=$(grep "token:" ~/Dev/jira.txt | cut -d' ' -f2)

# Transition to Done
curl -s -X POST -u "jira@wolcott.io:$JIRA_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"transition": {"id": "31"}}' \
  "https://wolcott.atlassian.net/rest/api/3/issue/AR-XX/transitions"

# Add comment
curl -s -X POST -u "jira@wolcott.io:$JIRA_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "body": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Completed via PR #XX. Deployed and integration tests passing."}]}]}
  }' \
  "https://wolcott.atlassian.net/rest/api/3/issue/AR-XX/comment"
```

---

## Common Issues

### CDK Deploy Fails

- Check CloudFormation console for detailed error
- Common: Table replacement (use `-v2` suffix), IAM permissions

### Integration Tests Fail

- Verify stack deployed: `aws cloudformation describe-stacks --stack-name ms-argus-api-dev-jw`
- Some async tests may be flaky - rerun

### Pre-commit Hooks

- `format`, `typecheck`, `lint` run automatically
- Warnings OK, errors block commit
