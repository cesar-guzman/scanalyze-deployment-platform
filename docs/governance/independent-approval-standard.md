# Independent Approval Standard

## Objective and evidence boundary

GUG-119 defines the checked-in target for auditable separation of duties in
`cesar-guzman/scanalyze-deployment-platform`. Merging this document or its
policy does not prove that GitHub enforces the target remotely.

Keep these states separate:

| State | Required evidence | What it does not prove |
|---|---|---|
| Historical snapshot | Dated, revision-bound read-only evidence in `docs/engineering/GITHUB_ENFORCEMENT_BASELINE.md` | Current remote state |
| Checked-in target | Reviewed policy, schema, tests, CODEOWNERS, and runbooks at an exact commit | Any repository-administration mutation |
| Remote before | Fresh read-only branch-protection, ruleset, Environment, repository-setting, and reviewer-identity evidence | Authorization to write |
| Remote after | Response from a separately authorized mutation tied to the reviewed payload and exact target | Successful or complete enforcement |
| Readback verified | Fresh endpoint-by-endpoint reads match the approved target and no conflicting rule exists | Human identity or MFA attestation; production authorization |
| Human attested | An authorized human confirms the candidate account, MFA, independence, and least privilege | Runtime or production approval |
| Production authorized | A separate, current approval names the exact environment and action | Any other production action |

Repository publication comes first. The pre-merge human checkpoint reviews the
exact PR SHA, candidate attestation, repository tests, negative-test evidence,
rollback design, and confirmation that remote protection has not changed. It
does not authorize or require an operational payload. Only after the reviewed
tree is verified on `main` may a fresh remote-before readback and deterministic
payload form a separate GitHub-administration package. That later mutation
requires its own authorization and MUST NOT be folded into the authorization to
publish or merge the repository PR.

## Roles

- **Issue owner / maintainer:** César Guzmán (`@cesar-guzman`).
- **Required independent-review candidate:** `guguce-google`. The candidate is
  not an approved independent reviewer until a human has attested the account,
  MFA, independence from the author, and least-privilege repository role.
- **Additional authorized code owner:** Emiliano Díaz (`@Ferrusca08`). Retaining
  this owner does not make one person both the required candidate and the sole
  exception actor.

No shared account, bot, AI identity, author, or administrator capability counts
as an independent human approval. If the required candidate is unavailable,
unattested, conflicted, or lacks the required access, the change is blocked.
Urgency does not lower the bar.

## Checked-in machine-readable contract markers

The labels below are normative documentation markers. Each assignment must
agree with `governance/github-policy.json` and its schema.

| Label | Contract marker |
|---|---|
| `reviewer_candidate` | `github-policy.independent_review.reviewer_candidate="guguce-google"` |
| `prevent_self_review` | `github-policy.independent_review.prevent_self_review=true` |
| `required_approval_count` | `github-policy.required_pull_request_reviews.required_approving_review_count=1` |
| `codeowner_review` | `github-policy.required_pull_request_reviews.require_code_owner_reviews=true` |
| `dismiss_stale_reviews` | `github-policy.required_pull_request_reviews.dismiss_stale_reviews=true` |
| `require_last_push_approval` | `github-policy.required_pull_request_reviews.require_last_push_approval=true` |
| `conversation_resolution` | `github-policy.required_conversation_resolution=true` |
| `enforce_admins` | `github-policy.enforce_admins=true` |
| `bypass_actors` | `github-policy.required_pull_request_reviews.bypass_pull_request_allowances={"users":[],"teams":[],"apps":[]}` |
| `force_push` | `github-policy.allow_force_pushes=false` |
| `branch_deletion` | `github-policy.allow_deletions=false` |
| `private_vulnerability_reporting` | `github-policy.private_vulnerability_reporting.enabled=true` |
| `existing_environments_only` | `github-policy.environment_protection.existing_environments_only=true` |
| `create_missing_environments` | `github-policy.environment_protection.create_missing_environments=false` |
| `environment_required_reviewer` | `github-policy.environment_protection.required_reviewer="guguce-google"` |
| `environment_prevent_self_review` | `github-policy.environment_protection.prevent_self_review=true` |
| `auto_merge` | `github-policy.auto_merge.enabled=false` |

The technical branch-protection floor is one current independent approval. It
does not replace the higher manual P0 requirement in `CONTRIBUTING.md`: P0
changes still require two humans, including the applicable owner. GitHub
showing the technical floor as satisfied is therefore not sufficient evidence
for a P0 merge.

## Required status checks

The existing application-bound status-check contract must remain exactly:

1. `Lint, security, and schema checks`
2. `Python tests`
3. `Validate deployment manifest schema`
4. `Terraform validate (no AWS)`
5. `Verify clean clone reproducibility`
6. `Microservices validation gate`

Unexpected, missing, duplicated, or silently unbound checks fail closed. The
independent-approval rollout must preserve the observed GitHub App binding for
each check and must not convert dynamic matrix jobs into required contexts.

## Environment and repository-setting boundaries

GUG-119 may inspect only already-existing Route B GitHub Environments. It does
not authorize creating, renaming, or deleting an Environment. A missing
Environment, an unavailable candidate reviewer, an inability to prevent
self-review, or conflicting inherited configuration is a blocker.

Private vulnerability reporting and auto-merge are repository settings on
separate endpoints from classic branch protection. Environment protection is
also a separate endpoint family. A branch-protection PUT must not claim or
silently mutate those controls. Each target needs its own reviewed plan,
separate authorization when writable, and fresh readback. The vulnerability
reporting route is not operable until enablement and triage ownership are both
verified.

## Acceptance and negative tests

Before any remote mutation, retain synthetic/offline evidence that:

- self-approval does not satisfy the independent-review requirement;
- an approval made stale by a material push does not satisfy it;
- an unavailable, unattested, or mismatched reviewer blocks;
- unresolved conversations block;
- any bypass actor, admin bypass, lower approval count, disabled required
  check, force-push allowance, or branch-deletion allowance is rejected;
- missing, unexpected, duplicated, or unbound required checks are rejected;
- a missing Environment is reported as blocked and is not created;
- the deterministic generator preserves supported remote fields and rejects
  ambiguous or unknown inputs; and
- rollback refuses to overwrite third-party drift or an unknown outcome.

The final remote-after evidence must be read back from every affected endpoint
and compared with the reviewed target. A green PR, merged policy, API response,
or administrator assertion alone is not a pass.

## Production status

Production remains **NO-GO**. Repository governance work does not authorize AWS
access, Terraform apply, deployment, customer-data processing, or any production
mutation.
