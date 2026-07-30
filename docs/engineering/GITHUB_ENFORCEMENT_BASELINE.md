# GitHub Contribution Enforcement Baseline

## Document control

| Field | Value |
|---|---|
| Owner | Platform Engineering |
| Status | VERIFIED SNAPSHOT; not a production authorization |
| Repository | `cesar-guzman/scanalyze-deployment-platform` |
| Default branch | `main` |
| Verified | 2026-07-23 |
| Verified revision | `main@0f3dc10da4ea811a10974954f25cc5899dbf7393` |
| Tracking | [GUG-111](https://linear.app/guguce/issue/GUG-111/versionar-el-contexto-operativo-de-codex-y-las-plantillas-de-trabajo), [GUG-119](https://linear.app/guguce/issue/GUG-119/risk-single-maintainer-approval-model) |

This snapshot distinguishes written contribution policy from GitHub controls
that are technically enforced. It is evidence for planning and review only.

## Repository metadata

| Control | Observed state |
|---|---|
| Visibility | Public |
| Default branch | `main` |
| Administrator access used for readback | Available to repository owner |
| Merge methods enabled | Merge commit, squash, and rebase |
| Auto-merge | Disabled |
| Repository rulesets | None returned |
| Protection model | Classic branch protection |
| Public private-vulnerability reporting | Disabled |

Public visibility means every tracked file, commit message, issue, pull request,
comment, check output, and uploaded artifact must be safe for public disclosure.
If public visibility is not intentional, changing it requires a separate,
reviewed security/governance action.

## Enforced controls on `main`

| Control | Observed | Enterprise policy |
|---|---:|---|
| Branch must be current before merge | Yes (`strict`) | Required |
| Administrators are subject to protection | Yes | Required |
| Force pushes allowed | No | Prohibited |
| Branch deletion allowed | No | Prohibited |
| Required approving reviews | **0** | P2/P1: 1; P0: 2 |
| CODEOWNER review required | **No** | Required |
| Stale approvals dismissed | **No** | Required for material pushes |
| Approval required after last push | **No** | Required |
| Conversation resolution required | **No** | Required |
| Signed commits required | **No** | Target control |

The following six static status checks are enforced:

1. `Lint, security, and schema checks`
2. `Python tests`
3. `Validate deployment manifest schema`
4. `Terraform validate (no AWS)`
5. `Verify clean clone reproducibility`
6. `Microservices validation gate`

The exact Git-safe status-check contract is
[`governance/github-policy.json`](../../governance/github-policy.json).

## Gap and interim control

GitHub currently enforces CI but not the human-review policy in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md). Until GUG-119 is resolved:

- authors MUST NOT self-approve or self-merge;
- maintainers MUST verify the applicable independent approvals manually;
- P0 work waits when two independent qualified reviewers are unavailable;
- the final review must cover the final material SHA;
- unresolved blocking conversations prevent merge even though GitHub does not
  enforce conversation resolution;
- production remains NO-GO without independent audited approval;
- an exception requires the documented exception process and cannot convert
  missing separation of duties into production authorization.

Email, chat acknowledgement, CI success, or administrator capability does not
count as independent approval.

## Target enforcement plan

A separate governance change should:

1. add at least one qualified second human reviewer with MFA and least privilege;
2. update `CODEOWNERS` with real GitHub identities or teams;
3. require the appropriate number of approvals;
4. require CODEOWNER review;
5. dismiss stale approvals;
6. require approval after the most recent material push;
7. require conversation resolution;
8. retain admin enforcement and force-push/deletion prohibitions;
9. evaluate verified commit signatures;
10. test that self-approval, stale approval reuse, missing reviewer, and bypass
    attempts fail closed;
11. capture a readback and rollback plan.
12. decide whether to enable public private-vulnerability reporting and verify
    the notification/triage owner before advertising that path.

Do not mutate branch protection as part of this documentation package.

## Verification sources

The snapshot used read-only GitHub repository metadata and:

```bash
gh api \
  repos/cesar-guzman/scanalyze-deployment-platform/branches/main/protection

gh api \
  repos/cesar-guzman/scanalyze-deployment-platform/rulesets

gh api \
  repos/cesar-guzman/scanalyze-deployment-platform/actions/workflows

gh api \
  repos/cesar-guzman/scanalyze-deployment-platform/private-vulnerability-reporting
```

No repository, branch-protection, workflow, environment, or AWS setting was
changed during verification.

## Revalidation

Revalidate this file after:

- a branch protection or ruleset change;
- a CODEOWNERS or team membership change;
- a merge-method change;
- a public/private visibility decision;
- a review-control incident;
- completion of GUG-119.

Update the verified revision/date and retain the previous decision in Git
history. Never assume this snapshot remains current indefinitely.
