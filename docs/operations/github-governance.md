# GitHub CI Governance and Multi-Client Environment Runbook

## Purpose

This runbook keeps two control planes separate and repeatable:

1. **repository merge governance**, shared by every Scanalyze deployment; and
2. **deployment authorization**, isolated in one protected GitHub Environment
   per deployment and logical stage.

It does not authorize AWS access, Terraform apply, image publication, or
production. The current release workflow remains dry-run only.

```text
                           one repository policy
pull request --------------------------------------------------> main
      | static checks | dynamic evidence -> stable gate |
                                                               |
                                                               v
                                            Git-safe deployment request
                                                 /        |        \
                                                v         v         v
                                      client A / dev  client A / staging
                                                        client B / dev
                                          protected deployment Environments
```

## Incident And Root Cause

The classic `main` protection rule required fourteen contexts. Seven were
dynamic matrix expansions (`Validate ingest-api`, `Validate ocr-worker`, and so
on). For a pull request that changed only infrastructure and documentation, the
service selector returned `[]`; GitHub therefore created no concrete matrix
jobs. The rule waited forever for absent contexts.

Waiting, rerunning, or marking the pull request ready does not resolve this
state. Required status checks use the exact job name and do not understand a
workflow's matrix or path-selection intent.

## Desired Repository Policy

[`governance/github-policy.json`](../../governance/github-policy.json) is the
Git-safe source contract. The target contexts are:

1. `Lint, security, and schema checks`
2. `Python tests`
3. `Validate deployment manifest schema`
4. `Terraform validate (no AWS)`
5. `Verify clean clone reproducibility`
6. `Microservices validation gate`

The concrete `Service matrix evidence / <service>` jobs remain visible evidence,
but they are never required contexts. Pull requests retain path-aware selection;
manual dispatch validates all seven services before producing the same stable
gate, while its service input scopes only publication. `Select services` and
`Validate build tooling` are internal dependencies covered by the aggregate gate
and are not branch-protection APIs.

Validate the local contract without network or credentials:

```bash
make github-governance-check
python -m pytest tests/test_governance -q
```

The validator rejects colliding dynamic names in every workflow, duplicate
producers, required matrix jobs, pull-request path filters, and dependent
required jobs that can disappear without an `always()` gate. The required job
and its complete transitive `needs` closure must remain read-only, must not target
a deployment Environment, and may use `continue-on-error` only as literal
`false`. Privileged post-merge jobs remain valid when they are outside that
closure.

## Safe Branch-Protection Reconciliation

### Preconditions

- The workflow change is pushed to a pull request while the legacy protection
  still applies.
- The full evidence SHA is the current head of exactly one open pull request
  targeting the manifest's default branch, and that commit is available in the
  local Git object database.
- `governance/github-policy.json` in the working tree is byte-identical to that
  canonical path at the evidence SHA. Apply rejects absolute, alternate,
  content-divergent, or commit-missing manifest sources.
- Every target context has successful GitHub Actions CheckRun evidence tied to
  that pull request revision.
- `gh auth status` identifies the intended GitHub account.
- Read-only operations use repository read access. Apply/rollback uses a
  short-lived GitHub App or fine-grained token with repository
  `Administration: write`; do not create a long-lived PAT.
- No repository ruleset overlaps the classic branch rule.

The reconciler is read-only by default and targets only the dedicated classic
required-status-checks endpoint. It never changes reviews, admin enforcement,
force-push, deletion, or Environment settings.

### 1. Plan

```bash
python scripts/governance/sync-required-checks.py plan \
  --repo OWNER/REPOSITORY
```

Expected initial state is `LEGACY`. `DIVERGED` means an unmanaged context,
strict-mode drift, or a missing stable context exists; investigate and update
the reviewed policy instead of forcing the apply. `MIXED` is also fail-closed.

### 2. Capture the evidence SHA

Use the full SHA that produced the successful pull-request checks:

```bash
EVIDENCE_SHA="$(git rev-parse HEAD)"
test "$(printf '%s' "$EVIDENCE_SHA" | wc -c | tr -d ' ')" = "40"
```

Do not use a prior SHA. The reconciler rejects a commit that is not the current
head of exactly one open pull request targeting the policy's default branch.

### 3. Apply atomically

Snapshots belong in the ignored `.work/` directory:

```bash
python scripts/governance/sync-required-checks.py apply \
  --repo OWNER/REPOSITORY \
  --evidence-sha "$EVIDENCE_SHA" \
  --snapshot-out ".work/github-governance/main-before-${EVIDENCE_SHA}.json" \
  --confirm-repository OWNER/REPOSITORY
```

The apply command deliberately uses only the canonical repository-relative
manifest path; `--manifest` cannot redirect a mutation to a local policy file.

The tool:

1. binds the loaded policy object and working-tree
   `governance/github-policy.json` byte-for-byte to that path at the evidence
   SHA, before any remote read;
2. verifies the exact legacy/transition state and absence of active rulesets;
3. resolves the full SHA to exactly one current open pull request against the
   default branch;
4. reads each workflow from the local Git object at that SHA and verifies the
   manifest's exact workflow/job/context mapping;
5. binds every successful CheckRun to the expected GitHub App, head SHA, pull
   request, canonical Actions job URL, workflow path, `pull_request` event,
   numeric workflow run, and numeric Actions job;
6. rereads protection and the exact pull-request identity immediately before
   mutation to detect concurrent changes;
7. writes a mode-`0600`, SHA-256-protected snapshot, then revalidates the
   pull-request identity, manifest binding, required checks, and effective
   rules immediately before the PATCH;
8. patches `strict` plus application-bound `checks` in one request;
9. reads the result back, including after a lost or timed-out PATCH response;
   and
10. compensates to the snapshot only while two consecutive recovery reads still
   match the exact intended target. If the original state remains, no write is
   needed; if third-party drift or an unreadable outcome is observed, recovery
   stops without overwriting it and requires operator reconciliation.

GitHub's workflow-run and job APIs expose the workflow path, numeric run/job
IDs, job name, head SHA, CheckRun link, event, and pull-request association. They
do **not** expose the YAML `jobs.<job_id>` key. The reconciler therefore proves
the runtime side with exact context/name and numeric API links, and separately
proves the YAML job ID by reading the committed workflow offline at the same
evidence SHA. This is deliberately not represented as an API-level YAML job-ID
guarantee.

Never commit the snapshot.

### 4. Verify

```bash
python scripts/governance/sync-required-checks.py check \
  --repo OWNER/REPOSITORY

gh pr checks PR_NUMBER --required
```

`check` succeeds only in exact `TARGET` state with no effective ruleset conflict.
The pull request can remain blocked by its draft status or required human review;
those are independent governance controls and must not be bypassed.

### 5. Roll back required checks

Rollback is allowed only when the remote state still matches the snapshot's
expected post-apply state:

```bash
python scripts/governance/sync-required-checks.py rollback \
  --repo OWNER/REPOSITORY \
  --snapshot-in ".work/github-governance/main-before-${EVIDENCE_SHA}.json" \
  --confirm-repository OWNER/REPOSITORY
```

If another administrator changed protection after the migration, rollback
aborts rather than overwriting that change. A failed or timed-out rollback is
read back twice and is rolled forward only while the remote still equals the
exact snapshot `before` state written by that rollback attempt. Unknown outcomes
and third-party drift never trigger another write. Review drift and create a new
plan.

## Deployment-Scoped GitHub Environments

The logical environment and GitHub authorization boundary are different values:

| Value | Meaning | Example |
|---|---|---|
| `logical_environment` | Release stage recorded in the Git-safe request | `dev` |
| `github_environment` | Protected deployment-specific approval and variable boundary | `scanalyze-dep_...-dev` |

For every new deployment and logical stage, create one distinct Environment.
Do not reuse a generic `dev` or `staging` Environment across clients.

Minimum non-secret Environment variables:

| Variable | Binding |
|---|---|
| `DEPLOYMENT_ID` | Exact deployment ULID from the approved registry/request |
| `LOGICAL_ENVIRONMENT` | `sandbox`, `dev`, or `staging` |
| `AWS_REGION` | Exact deployment region |

Mandatory Environment protections before live/OIDC enablement:

- deployment branches limited to `main`;
- independent required reviewer(s);
- prevent self-review and bypass where the GitHub plan supports it;
- deployment-specific variables, never values copied from another client; and
- no static AWS access keys or secrets.

The dry-run gate compares all three resolved `vars` values to workflow inputs
without logging them. A missing or mismatched value fails closed before the
layer DAG runs, but this comparison does **not** prove the variable's scope or
that the Environment was pre-provisioned and protected. GitHub may create a
referenced Environment that did not exist, and `vars` can resolve values defined
at organization, repository, or Environment scope.

Reserve `DEPLOYMENT_ID`, `LOGICAL_ENVIRONMENT`, and `AWS_REGION` for Environment
scope: do not define those names as organization or repository Actions
variables. Before live enablement, an external bootstrap/governance control—not
the release workflow being governed—must fail closed unless it can:

1. read the exact Environment by name through the GitHub API;
2. verify required reviewers, self-review/bypass posture, and a `main`-only
   deployment branch policy;
3. read the Environment variable endpoint and confirm the three names and values
   against the approved deployment registry;
4. confirm the reserved names are absent from repository and applicable
   organization variable scopes; and
5. retain only a sanitized configuration digest and review evidence.

Future privileged jobs must target the same verified Environment themselves and
use an AWS trust policy whose subject is bound to the exact repository and
Environment. Equality in the workflow is defense in depth; it is never the sole
authorization source.

## Repeatable Client Onboarding

For each deployment:

1. allocate the immutable `deployment_id` in the approved external registry;
2. create deployment-scoped GitHub Environments for the required logical stages;
3. configure the three non-secret binding variables and protection rules;
4. run the external Environment/registry audit and record sanitized evidence;
5. configure future live OIDC role variables only after IAM review;
6. create a synthetic or Git-safe deployment request—never a real manifest;
7. run `make github-governance-check` once for the shared repository policy;
8. dispatch `nonprod-release.yml` from `main`, selecting the logical and protected
   Environments separately; and
9. retain sanitized operational evidence outside Git.

Adding a client never adds required status contexts, copies workflows, or forks
application source.

## Organization-Scale Direction

This repository is currently personal and uses classic branch protection. If
platform source later spans multiple repositories, move enforcement to an
organization ruleset or external governance controller using the same static
context contract. Use a short-lived GitHub App installation token, reviewed
plan/apply, and organization repository targeting. Do not run a self-modifying
governance workflow inside each governed repository.

Do not enable merge queue until every required workflow supports the
`merge_group` event. Adding only the trigger is insufficient because path and
base/head selection must also support that event.

## References

- [ADR-018](../../ADR/ADR-018-stable-ci-governance.md)
- [GitOps orchestrator](../deployment/gitops-orchestrator.md)
- [GitHub required-check troubleshooting](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/collaborating-on-repositories-with-code-quality-features/troubleshooting-required-status-checks)
- [GitHub branch-protection API](https://docs.github.com/en/rest/branches/branch-protection)
