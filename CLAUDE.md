# Claude Code Workflow for ms-argus-api

## Core Principles

When planning, reviewing, or implementing:

- **Readable over clever** → Code should be obvious, not impressive
- **Understandable by the next engineer** → Write for the maintainer, not yourself
- **Boring technology choices** → Proven beats cutting-edge (nobody got fired choosing IBM)
- **Explicit over implicit** → Magic is the enemy of debugging
- **Tests prove behavior** → Tests verify the feature works, not just that code runs

---

## Sprint Planning

Before tickets exist:

1. **Define goal** → User describes what the sprint should accomplish
2. **Create plan** → Design approach based on Core Principles
3. **Review together** → Agree on scope, direction, trade-offs
4. **Write tickets** → Create JIRA tickets with verifiable AC (pass/fail criteria)
5. **Plan automation** → Define test coverage for each ticket before implementation
6. **Begin work** → Start pulling tickets

---

## Per-Ticket Workflow

Work through JIRA tickets autonomously. For each ticket:

1. **Get ticket** → Query JIRA for To Do tickets (bugs first, then by priority P0-P3)
2. **Branch** → `git checkout -b AR-XX` (both repos)
3. **Automation first** → Write tests in ms-argus-automation that cover the ticket's AC
4. **Verify tests fail** → Proves tests are actually testing something
5. **Implement** → Make changes (includes unit tests, linting, formatting)
6. **Unit test** → `npm test` (all must pass)
7. **Deploy** → `npx cdk deploy ms-argus-api-dev-jw --require-approval never`
8. **Integration test** → `cd ~/Dev/ms-argus-automation && npm test` (all must pass)
9. **Update docs** → If user-facing behavior changed, update `docs/features/` and README
10. **Self-review** → Review PR against Core Principles
11. **PR + Merge** → `gh pr create` then `gh pr merge --squash --delete-branch` (both repos)
12. **JIRA** → Transition to Done, add completion comment
13. **Repeat** → Return to step 1

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
npm run format       # Prettier + Go fmt
npm run lint:test    # ESLint (warnings OK, errors fail)
npm test             # Vitest unit tests
cd cmd/ingestion && go test -v ./...  # Go tests
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
Browser → CloudFront → ALB → ECS (Go) → SQS → Lambda (Matching) → DynamoDB
                                               ↓
                                         SQS → Lambda (Profile) → DynamoDB
                                               ↓
                                             Redis (cache)
```

### Key Files

| Purpose            | Location                     |
| ------------------ | ---------------------------- |
| Lambda handlers    | `src/handlers/`              |
| Services           | `src/services/`              |
| CDK infrastructure | `lib/constructs/`            |
| Go ingestion       | `cmd/ingestion/`             |
| Tests              | `src/**/*.test.ts`, `tests/` |

### DynamoDB Tables

- `Profiles` - Device fingerprint profiles
- `Tier1Index` - Hash lookups (evercookie, stable, fuzzy, ja4)
- `Tier2Buckets` - Compound filter matching

---

## Documentation

Keep these up to date as features change:

| Location         | Purpose                                                            |
| ---------------- | ------------------------------------------------------------------ |
| `docs/features/` | User-facing feature docs (what it does, inputs, outputs, examples) |
| `CHANGELOG.md`   | Sprint-level changes (features added/removed/changed)              |
| `README.md`      | Architecture, API reference, setup instructions                    |
| `docs/adr/`      | Architecture Decision Records (for non-trivial design choices)     |

**When to update:**

- New endpoint or behavior change → `docs/features/` + `README.md`
- Any merged PR → `CHANGELOG.md`
- Design decision with trade-offs → `docs/adr/NNNN-title.md`

---

## Merge Checklist

Before merging ANY PR:

- [ ] Unit tests pass (`npm test` - all 261+)
- [ ] Go tests pass (`go test ./...`)
- [ ] Lint passes (warnings OK)
- [ ] Deployed to dev (`cdk deploy ms-argus-api-dev-jw`)
- [ ] Integration tests pass (`cd ms-argus-automation && npm test`)
- [ ] Docs updated (if user-facing behavior changed)
- [ ] Self-review against Core Principles
- [ ] CHANGELOG.md updated

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
- Redis tests may skip locally (requires VPC access)

### Pre-commit Hooks

- `format`, `typecheck`, `lint` run automatically
- Warnings OK, errors block commit
