# Durable founder bootstrap PEP

GUG-211 implements the live enforcement point required by the bounded GUG-209
exception. It is only for the first non-production backend bootstrap in the
dedicated platform-authority account. New customers do not receive this
exception; they use the normal GUG-206/GUG-125 workflow and their own terminal
deployment roles.

## Ownership and trust boundaries

| Component | Owner | Authority |
|---|---|---|
| S3 organization Block Public Access policy | Organizations management account | Exact authority account only |
| Founder PEP StackSet | Organizations management account | Exact authority account and `us-east-1`; automatic deployment disabled |
| Seed operator | `ScanalyzeFounderPepSeed` in management | Exact S3 policy/StackSet APIs only |
| Identity administrator | `ScanalyzeFounderPepIdentityAdmin` in management | Tagged GUG-211 permission sets and exact authority account only |
| Durable PEP ledger | Dedicated authority account | One exception ID per item; create-only/CAS |
| Founder Plan role | Temporary Identity Center permission set | One Change Set creation/review; no execution |
| Founder Apply role | Temporary Identity Center permission set | One exact execution; no Plan or governance mutation |
| Authority backend | Dedicated authority account | Four canonical S3/KMS CloudFormation resources |

Audit, shared-services, customer accounts, and destination deployment roles are
not part of this trust chain.

## Repository artifacts

- `bootstrap/cfn-platform-authority-founder-pep.yaml`: retained DynamoDB seed.
- `tooling/founder_bootstrap_pep.py`: immutable intent, state machine, policy
  renderer, AWS CLI store, and effect-after-CAS orchestration.
- `scripts/deployment/founder-bootstrap-pep-seed.py`: management preflight and
  separately flagged organization seed.
- `scripts/deployment/founder-bootstrap-pep.py`: private intent/policy, ledger,
  deny-only shell creation, direct-user activation/revocation, durable close,
  retirement, Plan and Apply orchestration.
- `policies/iam/platform-authority-founder-live-*-role.json`: disjoint,
  time-bound live policies.
- `policies/iam/platform-authority-founder-pep-management-seed-role.json`:
  one-purpose management session policy with no IAM, Identity Center,
  customer, Change Set execution, or production authority.
  Its `organizations:TagResource` grant exists only because AWS requires that
  dependent permission for tagged `CreatePolicy`; the same statement binds it
  to the exact S3 policy type, request-tag values and tag-key set and grants no
  standalone update or untag operation.
- `policies/iam/platform-authority-founder-pep-identity-admin-role.json`:
  management-account template limited to the single Identity Center instance,
  tagged GUG-211 permission sets and authority account `042360977644`; it has
  no Identity Store, group, IAM, Organizations, customer, or production writes.
- `schemas/platform-authority-founder-pep-*.v1.schema.json`: typed evidence.

## Invariants

1. Exact account `042360977644`, Region `us-east-1`, non-production only.
2. One known management account seeds the root; no delegated/shared authority.
3. Effective organization/account S3 BPA is all true before Plan and Apply.
4. One private intent exists before Plan start and binds both live SSO sessions.
5. A protected, PITR-enabled DynamoDB table exists before temporary authority.
6. Plan and Apply use disjoint permission sets and non-overlapping time windows.
   They are direct `USER` assignments; group creation or membership is not part
   of the exception.
7. CAS is committed before every CloudFormation mutation.
8. Exact Change Set name, ARN, tags, template digest, state and four-resource
   inventory are re-read; request values never establish authority.
9. Unknown, stale, legacy, missing, conflicting, or foreign evidence denies.
10. Any ambiguous response is terminal `UNCERTAIN`; no retry or new exception.
11. Plan is revoked only after its expiry and before Apply starts. Apply is
    revoked and durably closed before its expiry; both time-deny policies stay
    provisioned through `deny_retain_until` and are retired afterward.
12. Raw operational evidence never enters Git, Linear, CI logs, or NotebookLM.
13. Production and customer deployment remain out of scope.
14. Remove or quarantine every standing broad administrator assignment during
    the live window; only the exact task-specific permission set may be used.
15. Generic `AWSAdministratorAccess` sessions are rejected. The two management
    permission sets above must be created/assigned in a separate reviewed
    bootstrap change before the GUG-211 live run.

The DynamoDB compare-and-swap is a reviewed workflow control, not a claim that
IAM can force every possible `PutItem` caller to include the condition
expression. A malicious account administrator remains outside this PEP trust
boundary. See ADR-039 and the threat-model delta before authorizing any live
window.

## Customer portability

The founder seed is a one-time platform control, not a per-customer component.
After it closes, the authority account stores reviewed execution state for the
portable GUG-125 engine. Each customer deployment still binds its own customer
ID, deployment ID, AWS account, Region, environment, immutable release, saved
plan, terminal role, health proof, and rollback evidence. No customer inherits
the founder operator, exception, table item, or Identity Center assignment.

## Status

- Implemented: repository package in the reviewed GUG-211 commit.
- Locally validated: only named passing gates.
- CI validated: pending exact-commit checks until published.
- Live validated: no.
- Production: **NO-GO**.
