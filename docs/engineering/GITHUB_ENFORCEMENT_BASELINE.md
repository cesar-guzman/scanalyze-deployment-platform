# GitHub Contribution Enforcement Baseline

## Document control

| Field | Value |
|---|---|
| Owner | Platform Engineering |
| Status | HISTORICAL VERIFIED SNAPSHOT; not a current-state claim or production authorization |
| Repository | `cesar-guzman/scanalyze-deployment-platform` |
| Default branch | `main` |
| Verified | 2026-07-23 |
| Verified revision | `main@0f3dc10da4ea811a10974954f25cc5899dbf7393` |
| Tracking | [GUG-111](https://linear.app/guguce/issue/GUG-111/versionar-el-contexto-operativo-de-codex-y-las-plantillas-de-trabajo), [GUG-119](https://linear.app/guguce/issue/GUG-119/risk-single-maintainer-approval-model) |

This snapshot distinguishes written contribution policy from GitHub controls
that were technically enforced at the recorded date and revision. It is
evidence for planning and review only. Do not cite it as current remote state;
obtain a fresh readback for every GUG-119 authorization decision.

GUG-119 uses distinct evidence classes:

- this file records a `HISTORICAL_SNAPSHOT`;
- reviewed repository policy at an exact commit is the `CHECKED_IN_TARGET`;
- fresh read-only API results immediately before an authorized change are
  `REMOTE_BEFORE`;
- direct write responses are `REMOTE_AFTER` but do not prove the final state;
- fresh endpoint-by-endpoint comparison may establish `READBACK_VERIFIED`;
- reviewer identity, MFA, independence, and least privilege require separate
  `HUMAN_ATTESTED` evidence; and
- production requires an unrelated, explicit `PRODUCTION_AUTHORIZED` decision.

## Historical repository metadata

| Control | State observed on 2026-07-23 |
|---|---|
| Visibility | Public |
| Default branch | `main` |
| Administrator access used for readback | Available to repository owner |
| Merge methods enabled | Merge commit, squash, and rebase |
| Auto-merge | Disabled |
| Repository rulesets | None returned |
| Protection model | Classic branch protection |
| Public private-vulnerability reporting | Disabled |

The observed public visibility means every tracked file, commit message, issue, pull request,
comment, check output, and uploaded artifact must be safe for public disclosure.
If public visibility is not intentional, changing it requires a separate,
reviewed security/governance action.

## Controls observed on `main` in the historical snapshot

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

## Historical gap and continuing human control

At the snapshot revision, GitHub enforced CI but not the human-review policy in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md). Unless a fresh remote readback proves
otherwise, maintain the following fail-closed human controls:

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

## GUG-119 checked-in target

A GUG-119 repository change defines the following reviewed target without
claiming that the remote repository already enforces it:

1. designate `guguce-google` as the required independent-review candidate,
   subject to human attestation of MFA, independence, and least privilege;
2. retain `@Ferrusca08` as an authorized additional owner and update every
   `CODEOWNERS` rule with the candidate;
3. require one current CODEOWNER approval as the technical branch-protection
   floor, while preserving the manual P0 requirement for two humans;
4. require CODEOWNER review;
5. dismiss stale approvals;
6. require approval after the most recent material push;
7. require conversation resolution;
8. retain admin enforcement and force-push/deletion prohibitions;
9. keep bypass actors empty and auto-merge disabled;
10. test that self-approval, stale approval reuse, missing reviewer, and bypass
    attempts fail closed;
11. capture a readback and rollback plan.
12. target private vulnerability reporting through its separate repository
    endpoint and verify a named notification/triage owner before advertising
    that path;
13. inspect only existing Route B GitHub Environments, require the candidate
    reviewer and prevent self-review, and block rather than create a missing
    Environment; and
14. preserve exactly the six application-bound required checks recorded above.

The normative target and negative tests are in
[`docs/governance/independent-approval-standard.md`](../governance/independent-approval-standard.md).
Repository publication comes first. Stop at a human checkpoint before merge.
After an approved merge is independently verified on `main`, any
branch-protection, existing-Environment, private-reporting, or auto-merge
mutation requires a new, separate authorization, deterministic reviewed payload
or endpoint plan, fresh `REMOTE_BEFORE`, and rollback evidence. These controls
use separate GitHub endpoints and must be read back separately.

Reviewer unavailability, inability to prevent self-review, a conflicting
ruleset, or a missing Environment is a blocker. Break-glass never permits
self-approval, admin bypass, fewer approvals, disabled checks, force-push,
branch deletion, Environment creation, or production activity.

Merging the target into `main`, receiving green CI, or obtaining one successful
API response does not update this historical snapshot and does not prove remote
enforcement. Production remains **NO-GO**.

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

No repository, branch-protection, workflow, Environment, or AWS setting was
changed during this historical verification.

## Revalidation

Revalidate this file after:

- a branch protection or ruleset change;
- a CODEOWNERS or team membership change;
- a merge-method change;
- a public/private visibility decision;
- a review-control incident;
- completion of GUG-119.

Record a new dated snapshot or an explicitly labeled readback; do not rewrite
the historical observation as though the 2026-07-23 evidence were newly
verified. Retain previous decisions in Git history. Never assume this snapshot
remains current indefinitely.
