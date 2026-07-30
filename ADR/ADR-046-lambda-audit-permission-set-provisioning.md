# ADR-046: Lambda Audit Permission-Set Provisioning and Exact Readback

- **Status:** Accepted for bounded non-production implementation
- **Date:** 2026-07-21
- **Work package:** GUG-220
- **Amends:** ADR-045
- **Depends on:** GUG-219
- **Production:** **NO-GO**

## Context

GUG-219 defines a deterministic Lambda-authority allowlist producer and a
dedicated Identity Center collector contract, but deliberately performs no
Identity Center mutation. The approved collector therefore cannot obtain an
authenticated session until its permission set is materialized, assigned and
provisioned in the dedicated platform-authority account.

A generic read-only or administrator permission set is not an acceptable
substitute. Neither a local profile name nor a successful Identity Center API
response proves that the account-local `AWSReservedSSO_*` role has the exact
effective authority required by GUG-219. Provisioning is asynchronous and may
produce an ambiguous result if the response is lost, times out or cannot be
read back completely.

The current operating roster contains one human. A direct assignment to that
single operator is permitted only as a bounded bootstrap mechanism for
report-only collection. It is not independent approval and cannot satisfy the
two-human control required by GUG-215.

## Decision

### 1. Materialize one exact permission-set contract

The permission-set name is exactly:

```text
ScanalyzeAuthorityLambdaAudit
```

Its contract is closed:

- session duration is exactly `PT1H`;
- the only permission document is the canonical rendering of
  `policies/iam/platform-authority-lambda-invocation-inventory-role.json`;
- AWS-managed policy attachments are empty;
- customer-managed policy references are empty;
- the permissions boundary is absent;
- `DenyUnreviewedActions` explicitly denies every action outside the exact
  reviewed read-only set, including actions granted by resource policies;
- `lambda:GetPolicy` is explicitly denied outside the exact broker and its
  qualifiers, and resource-scoped Lambda list actions are allowed only for
  function ARNs in the authority account and explicitly denied elsewhere;
- `Resource: "*"` remains only for Lambda discovery actions that AWS does not
  support at resource level;
- `sts:AssumeRole` is explicitly denied, preventing same-account
  resource-policy trust from creating a secondary-role relay;
- Lambda invocation and IAM/Lambda mutation remain explicitly denied; and
- deployment, customer-workload and production authority are absent.

The template and rendered canonical SHA-256 digests are computed locally and
bound into the private intent before mutation. The intent also binds the exact
40-hex repository `source_commit`. Planning accepts only an existing ancestor
commit whose GUG-219 template, policies and runtime plus the GUG-220 core and
CLI bytes equal the current checkout. Apply and reconcile repeat this check;
dirty, missing or rebound security-critical sources fail closed. The policy is
rendered once, checked against both intent digests and the source commit, then
that same sealed object is used for partial state, mutation and readback with
no worktree re-read. Request fields, prior provider
objects, role suffixes, profile aliases and administrator policy contents
cannot amend the contract.

Each intent is also bound to the live Identity Center control plane through
canonical digests of the exact `InstanceArn`, `IdentityStoreId` and authority-
account AWS SSO SAML provider ARN observed during planning. It has an explicit
`created_at` and `expires_at`, with a
maximum validity of 15 minutes. The implementation revalidates both live
bindings, source and expiry immediately before every protected mutation and
again before final evidence; an
expired or rebound intent cannot be refreshed in place.

The intent also contains the canonical digest of the explicit private
execution-ledger directory. Both `plan` and `apply` require
`--execution-ledger-directory`, and `apply` must resolve to the same directory
binding. Only the fixed owner-local
`~/.scanalyze-private-evidence/gug-220-live-v2` path is accepted. The directory
is outside the repository, owned by the current effective user, is not a
symlink and has mode exactly `0700`. One stable
`gug220-lambda-audit-provisioning.execution-ledger.v1.json` marker covers the
entire work package and target; changing intent, principal, policy or directory
cannot open a second mutation window.

Any GUG-220 intent v1 created before these source, live-binding and expiry fields
became mandatory is obsolete. It is not migration input and cannot authorize
mutation or readback. A new read-only plan must create a new intent in a new
create-only private evidence location.

### 2. Scope provisioning to one approved target

The permission set is provisioned only to the dedicated platform-authority
account in `us-east-1` pinned by reviewed deployment constants. Those account
identifiers are not secrets and already form part of the versioned authority
contract; generated intents, receipts, logs, Linear comments and NotebookLM
evidence contain only their canonical digests.

Exactly one direct Identity Center `USER` assignment is allowed during the
single-operator bootstrap period. The principal identifier is obtained from an
exact, paginated Identity Store lookup and retained only in private evidence.
Group assignment, duplicate users, foreign accounts and inferred identities
are rejected.

The assignment does not represent approval. Public evidence must state
`independent_review_present = false` while the roster contains one human.

### 3. Separate planning, mutation and readback

The workflow has three explicit phases:

```text
read-only plan
  -> exact authorized mutation
  -> independent exact readback
```

The read-only plan proves the active Identity Center instance, exact target,
permission-set collision state, canonical policy digests and exact single
principal before producing a private create-only intent.

The mutation phase may create the exact permission set when absent, install
the exact inline policy, create the exact direct assignment and provision the
permission set only to the approved account. It does not create groups, attach
managed policies, install a boundary or alter any other permission set or
assignment.

Before the first AWS write, the implementation uses one fixed ledger filename
for the GUG-220 target, creates the digest-sealed
`platform_authority_lambda_audit_execution_ledger` with `O_EXCL`, and reserves
the final receipt path with the same exclusive-create boundary. The ledger
records `MUTATION_WINDOW_CONSUMED`, an attempt limit of one and
`mutation_retry_authorized = false`. An existing ledger fails closed as
`EXECUTION_LEDGER_ALREADY_CONSUMED`; it is never deleted, overwritten or
treated as permission to continue.

Immediately before each of create-permission-set, put-inline-policy,
create-assignment and provision, the implementation refreshes the complete
inventory and revalidates principal, live control-plane bindings, source bytes
and intent expiry. It recomputes state without enlarging the reserved action
set. A policy or assignment change causally requires a subsequent explicit
provision even if the account already appeared provisioned before that write.

Installing or changing the inline policy always requires an explicit
`ProvisionPermissionSet` request for the approved target, even when Identity
Center already reports that target as provisioned. Existing provisioning state
does not prove that the account-local role contains the new policy bytes.

The readback phase requires:

- exactly one Identity Center instance and that instance is `ACTIVE`;
- exact name, description and `PT1H` duration;
- exact canonical inline-policy digest;
- zero managed/customer-managed attachments and no boundary;
- exactly one authorized direct `USER` assignment in the target account;
- successful provisioning status for only that account;
- exactly one corresponding account-local Identity Center IAM role;
- role trust bound to the exact planned SAML provider ARN, not merely a
  same-account provider-shaped ARN, and exact inline-policy equality; and
- no attached role policy or role permissions boundary.

Every Identity Center and IAM list surface uses complete pagination with token
replay detection. A later IAM page cannot hide an attachment, boundary,
additional role or policy from the verifier.

Only complete readback produces `READBACK_VERIFIED`. The receipt must contain
non-null canonical digests of both the exact permission-set ARN and exact IAM
role ARN, and `account_assignment_verified`,
`permission_set_provisioning_verified` and `collector_role_verified` must all
be `true`. A successful mutation API response alone does not.

### 4. Treat ambiguous mutation outcomes as terminal for writes

Timeout, transport loss, incomplete pagination, unknown asynchronous status or
conflicting provider state moves the operation to
`UNCERTAIN_RECONCILE_ONLY`. The same mutation is never retried.

Once an AWS write may have started, any timeout, `OSError`, provider error or
post-write readback failure also produces the reserved
`UNCERTAIN_RECONCILE_ONLY` receipt. The consumed ledger remains authoritative;
the operator may reconcile read-only but cannot retry the intent.

If persistence of that reserved receipt fails, the CLI emits sanitized public
`UNCERTAIN_RECONCILE_ONLY` status with a null receipt digest; the consumed
ledger remains the durable no-retry evidence. A read-only reconciliation with
incomplete evidence emits `READBACK_INCOMPLETE`, with no mutation attempt
claim, instead of conflating observation failure with deterministic drift.

Reconciliation may call only `List`, `Get` and `Describe` APIs and must compare
the observed state with the frozen intent. Missing, extra or conflicting state
is `BLOCKED_DRIFT`; operators do not repair it by inference.

### 5. Keep operational evidence private

The exact account identifier, Identity Store principal identifier, assignment
identifier, permission-set ARN, generated IAM role ARN and suffix, STS session
ARN, raw SAML provider ARN, provider responses and effective policies are private operational
evidence. Files are written outside the repository with an owner-only
directory (`0700`), exact file mode `0600`, exclusive creation and no symlink
following. Private inputs are opened from a file descriptor with
`O_NOFOLLOW`, then verified with `fstat` as a regular file owned by the current
effective user with mode exactly `0600`; a path-only precheck is insufficient.

Repository fixtures use synthetic values. Public closeout may contain only
sanitized state, counts, canonical digests and explicit governance limits.

### 6. Hand off only to report-only collection

After `READBACK_VERIFIED`, an independently authenticated session for the
dedicated permission set may be bound privately to the GUG-219 collector.
Candidate A, deterministic materialization and Candidate B remain read-only.

If the GUG-217 Lambda authority surface is not deployed or any prerequisite is
missing, the sequence stops as blocked. GUG-220 does not deploy that surface,
invoke Lambda, exchange tokens, create STS provided contexts or retire a
Change Set.

A clean Candidate B remains `REVIEW_SAFE_REPORT_ONLY`. GUG-215 retirement is
still blocked until two different humans can satisfy classifier and approver
duties.

### 7. Record the live partial outcome and defer repair to GUG-221

The first authorized GUG-220 live execution consumed its one-shot ledger and
ended `UNCERTAIN_RECONCILE_ONLY`. A duplicate invocation was rejected before
an AWS write. Subsequent read-only reconciliation established the sanitized
partial state: the exact collector permission set exists, while its inline
policy, direct assignment, target provisioning and account-local collector
role are absent or unverified.

This outcome does not reopen GUG-220. Its ledger remains consumed and must not
be deleted, replaced or reused. GUG-221 / ADR-047 defines a separately reviewed
repair behind private versioned Lambda aliases. The human invoker has no raw
Identity Center authority; a provider-backed DynamoDB CAS barrier precedes
exactly the three missing effects and complete SSO/IAM readback. Until GUG-221
reaches a durable `REPAIR_VERIFIED` or `RECONCILE_VERIFIED` result, the GUG-219 collector handoff remains
blocked. Production remains **NO-GO**.

## Consequences

- The GUG-219 collector can be attributed to one exact least-privilege
  Identity Center permission set instead of generic read-only access.
- The public repository remains portable across customers and accounts because
  live identifiers stay in the approved private target binding.
- Direct single-user bootstrap remains visible as a governance exception, not
  approval separation.
- Provider ambiguity cannot cause an automatic duplicate or broadened retry.
- Provisioning evidence and Lambda-authority evidence remain separate records.
- Production, customer deployment and Change Set retirement remain blocked.
- The observed partial live state requires GUG-221; GUG-220 cannot repair or
  retry it.

## Alternatives rejected

- **Use generic ReadOnlyAccess:** it lacks the exact complete account
  authorization graph and broadens the trusted computing base.
- **Use administrator access for collection:** it grants effect authority and
  invalidates least-privilege evidence.
- **Assign a group during one-person bootstrap:** no approved audit-only group
  exists and creating one would expand the authorized change.
- **Infer the principal from an email or local profile:** neither is an
  immutable Identity Store binding.
- **Trust provisioning success without IAM readback:** asynchronous
  provisioning and account-local drift remain unproven.
- **Retry after a timeout:** the first attempt may have succeeded.
- **Treat two sessions for one person as two reviewers:** credentials do not
  create human independence.

## Failure and reconciliation

Missing authorization, wrong account or Region, multiple active Identity
Center instances, duplicate name, unexpected assignment, attachment or
boundary, incomplete pagination, policy digest mismatch, inaccessible IAM
role, expired intent, live Instance/Identity Store digest mismatch, obsolete
pre-hardening intent, ambiguous asynchronous status or foreign provisioned
target blocks the workflow.

After an ambiguous mutation, record the private intent digest and perform only
read-only reconciliation. A subsequent repair requires a new reviewed change
authorization and a new intent; do not resume the prior mutation automatically.

## Rollback

Repository rollback is a reviewed revert of GUG-220. Cloud rollback is not
implicit: removing an assignment, deprovisioning a target or deleting the
permission set is a separate Identity Center mutation requiring its own exact
authorization, readback and ambiguity handling.

If readback discovers broader-than-approved authority, stop all collection,
invalidate the private collector binding and open a separately authorized
containment package. Do not use GUG-220 to mutate unrelated state.

## Evidence classification

| Class | Status |
|---|---|
| Repository contracts, tests and documentation | Implemented only on the exact reviewed GUG-220 commit |
| Local validation | Named local gates only |
| CI validation | Required checks for the exact commit only |
| Identity Center mutation | Live validated only after exact authorized execution and complete readback |
| Dedicated collector session | Eligible only after `READBACK_VERIFIED` and fresh STS validation |
| Candidate A/B | Read-only report evidence only |
| Independent human approval | **Blocked** while one human is on the roster |
| GUG-215 retirement | **Blocked** until two different humans are available |
| Production | **NO-GO** |

## Typed artifact inventory

- `schemas/platform-authority-lambda-audit-provisioning-intent.v1.schema.json`
- `schemas/platform-authority-lambda-audit-execution-ledger.v1.schema.json`
- `schemas/platform-authority-lambda-audit-provisioning-receipt.v1.schema.json`

The GUG-221 repair artifacts are deliberately separate and are not valid
substitutes for any GUG-220 artifact.

The intent authorizes a bounded candidate window, the ledger consumes it
before effect, and the receipt classifies the observed outcome. None may be
used as a substitute for another.

## References

- [ADR-045](ADR-045-reviewed-lambda-authority-allowlist-and-collector.md)
- [Deployment contract](../docs/deployment/platform-authority-lambda-audit-permission-set.md)
- [Operations runbook](../docs/operations/platform-authority-lambda-audit-permission-set.md)
- [Threat-model delta](../docs/security/gug-220-lambda-audit-permission-set-threat-model-delta.md)
- [ADR-047 repair boundary](ADR-047-lambda-audit-provisioning-repair.md)
