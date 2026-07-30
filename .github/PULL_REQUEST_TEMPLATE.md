## Linear and ownership

- Primary Linear issue: GUG-___
- Assignee:
- Reviewers/code owners:
- Risk class: P0 / P1 / P2

> One issue = one branch = one worktree = one pull request.

## Summary

<!-- What changed, why it is needed, and the intended outcome. -->

## Scope

### In scope

- 

### Out of scope

- 

## Acceptance criteria

<!-- Copy or link each criterion and state how this PR satisfies it. -->

- [ ] 

## Change classification

Mark every applicable area:

- [ ] Documentation only
- [ ] Frontend
- [ ] API/backend
- [ ] Worker/event processing
- [ ] Authentication or authorization
- [ ] Tenant/customer isolation
- [ ] Schema or contract
- [ ] Data model or migration
- [ ] Terraform, IAM, network, or encryption
- [ ] CI/CD, GitHub Actions, or repository governance
- [ ] Runtime configuration, rollout, or feature flag
- [ ] External integration

## Security and privacy impact

<!-- Address auth, object authorization, tenant binding, secrets, PII/customer
data, logging, IAM, supply chain, and negative tests. Use "None" with a reason
when there is no impact. Never paste sensitive evidence. -->

## Architecture and contract impact

- ADR required/updated:
- API/event/schema compatibility:
- Terraform/IaC ownership:
- New dependency and rationale:

## Validation performed

List the exact command, scope, revision when relevant, and result.

```text
<command>  # <result>
```

### Negative and failure-path validation

- 

### Validation not run

<!-- State why, residual risk, and who/what must complete it. Do not delete. -->

- 

## Documentation

- [ ] Closest component README updated or not applicable
- [ ] ADR updated or not applicable
- [ ] Contract/API/schema documentation updated or not applicable
- [ ] Runbook/rollback/recovery updated or not applicable
- [ ] Current versus target state is explicit

## Rollout, rollback, and recovery

### Rollout

<!-- Local, CI, non-production, feature flag, sequencing, and observability.
Merge is not deployment. -->

### Rollback/recovery

<!-- Revert/forward-fix path, compatibility, stateful effects, and stop
conditions. Terraform state manipulation is not routine rollback. -->

## Cloud and production boundary

- AWS access used: none / read-only / separately authorized write
- Profile and region, if read-only evidence was used: `<AWS_PROFILE>` / `<AWS_REGION>`
- AWS caller identity verified: yes / no / not applicable
- Cloud mutations performed: none / describe exact separately authorized action
- Production status: **NO-GO unless separately and explicitly approved**

## Evidence

<!-- Link sanitized CI/test artifacts, schema diffs, screenshots without customer
data, or other durable evidence. Do not attach raw plans, state, logs, tokens,
documents, PII, or signed URLs. -->

- 

## Reviewer focus

<!-- Name the highest-risk decisions, files, and trust boundaries. -->

- 

## Author checklist

- [ ] I started from current `origin/main` in an issue-specific worktree.
- [ ] This PR contains no unrelated changes.
- [ ] I reviewed the final diff and checked for secrets/sensitive artifacts.
- [ ] Acceptance criteria and Linear scope match this change.
- [ ] Focused tests pass and broader applicable gates are reported above.
- [ ] Auth, tenant, data, retry/idempotency, DLQ, and rollback behavior are covered where relevant.
- [ ] Documentation was updated in the same change.
- [ ] I did not weaken tests, scanners, CI, CODEOWNERS, or branch controls.
- [ ] I did not perform an unauthorized AWS or production action.
- [ ] Every claim above distinguishes merge, deployment, runtime evidence, and approval.

