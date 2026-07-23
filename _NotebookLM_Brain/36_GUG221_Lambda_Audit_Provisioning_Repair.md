# GUG-221 — Server-Side Lambda Audit Provisioning Repair PEP

## Executive statement

GUG-221 defines a new, non-production server-side policy-enforcement point for
one exact partial `ScanalyzeAuthorityLambdaAudit` state. It never retries or
resets GUG-220.

The human operator cannot call the Identity Center repair APIs. The operator
may invoke only exact private, published Lambda aliases with the literal empty
JSON object `{}`. All authority comes from reviewed immutable server
configuration, six separated IAM roles and a provider-backed DynamoDB Plan/
compare-and-swap record created before the first effect.

No AWS deployment or live repair is evidenced by this repository package.
Production remains **NO-GO**.

## Why the server-side PEP is required

IAM can restrict actions and resource ARNs, but cannot by itself prove the
complete repair state, exact policy digest, ordered predecessor, one-shot
execution or final provider result. A host-local ledger also cannot prevent a
second workstation from replaying the repair.

Direct human possession of the three Identity Center writes would bypass those
controls. GUG-221 therefore moves the write authority behind a private,
version-pinned Lambda PEP and gives the human only exact alias invocation.

## Human contract

`ScanalyzeLambdaAuditRepair` can invoke only:

- durable-gate `plan-v1`;
- one-shot `repair-v1`; and
- read-only `reconcile-v1`.

Every event must equal `{}`. The request cannot select the account, Region,
principal, permission set, policy, repair ID, source, time window or operation.
Unqualified functions, `$LATEST`, function URLs, non-empty events and
asynchronous invocation are rejected or absent.

The human permission set has no Identity Center, Identity Store, IAM, STS role-
assumption or DynamoDB write authority.

## Plan, repair and reconcile separation

The authority account ending in `7644` contains separate Plan, repair and
reconcile functions, published versions and execution roles, plus one exact
path-scoped invocation-authority inspector.

- Plan may only create the exact `PLAN_VERIFIED` record and assume the
  management readback role.
- Repair may only update and consume that record and assume the management
  mutation service role. It cannot create Plan evidence.
- Reconcile cannot write the record or Identity Center and assumes only the
  management readback role.
- All three functions may assume only the inspector for complete account-wide
  IAM/Lambda reads. The inspector cannot invoke, mutate or chain roles.

The management account ending in `1433` exposes two Lambda-only service roles.
The mutation role permits required reads plus exactly:

```text
sso:PutInlinePolicyToPermissionSet
sso:CreateAccountAssignment
sso:ProvisionPermissionSet
```

The readback role permits no mutation. For management-first creation, both
trusts use the authority-account root as a resolvable principal but constrain
it with the exact account and `ArnEquals aws:PrincipalArn` for the one matching
Lambda execution role. Both sides also require `sts:SetSourceIdentity` on the
same exact assume edge. Neither trusts a human SSO role or unconstrained
wildcard principal.

`lambda:InvokeFunction` cannot be restricted by IAM to synchronous invocation.
The reviewed wrapper therefore sends a synchronous-only `ClientContext`
marker, runtime requires it before any provider or ledger access, and every
alias has `MaximumRetryAttempts=0`, `MaximumEventAgeInSeconds=60` and no async
destination. An asynchronously delivered request lacks the marker and fails
closed before a protected effect. The marker proves synchronous transport
only; it carries no target, policy, principal, mode or mutation authority.

## Immutable binding

The published version binds the reviewed source/package, mode/alias, accounts,
`us-east-1`, repair ID, at-most-15-minute window, instance/store, immutable
`USER`, permission-set ARN/name/tags, collector and service-policy digests,
GUG-220 ledger digest, SAML provider, KMS mode/key and service roles.

Profile names, emails, session names and payload data are not authority.

## Reviewed source and signed artifact

The Lambda ZIP is a closed sixteen-entry archive: fifteen tracked runtime and
policy files plus one generated SDK lock. It includes eight standalone IAM
contracts and the GUG-218 authority collector/analyzer used for effective-role
and invocation-graph readback. The builder validates the local
tools against the exact reviewed commit and packages source bytes read directly
from the Git object database, so `assume-unchanged` and a worktree time-of-check
to time-of-use replacement cannot substitute runtime code.

A separate read-only verifier requires that commit to be current protected
GitHub `main`, the exact merged-PR tree and the exact required successful checks
from the GitHub Actions App. It then reads the successful AWS Signer job and
the exact versioned S3 source and signed objects directly, requires mandatory
SHA-256, one job-ID-named signed version and the exact closed ZIP entry set.
Operator-supplied manifests, downloaded archives, AWS response JSON, ETags and
`latest` object reads are not authority. The unsigned digest cannot be used as
a CloudFormation code digest.

The Change Sets are sequential, never a dual-stack atomic handoff. Phase A
fresh-enumerates GUG-220 twice with fixed read-only sessions, verifies no
pending operation, derives only ten delegation parameters, and verifies only
the management CREATE Change Set plus its CloudTrail creation event. After a
separately authorized execution, exact live readback requires the deterministic
`ClientRequestToken`, one exact CloudTrail `ExecuteChangeSet` event and complete
terminal StackEvents lineage before it supplies the provider-created repair-
invoker ARN. Phase B refreshes both GUG-220 and Phase A before
deriving/verifying the 29-value PEP Change Set. A contract cannot carry raw
principal, instance/store, SAML/KMS, collector/invoker ARN, ledger digest or
repair ID. This package creates or executes neither Change Set.

Sequential Phase B readback preserves but does not bind the observation-only
`evaluated_at` fields on the outer live receipt and nested Phase A execution
trace. All provider events, tokens, actors, terminal resources, digests and
verifier identities remain immutable. Post-invocation metadata, response or
receipt failures are always uncertain and force `reconcile-v1`; they are never
presented as a safe pre-invocation blocker.

## Provider-backed durable Plan and one-shot claim

Plan proves the exact eligible state and account-wide invocation graph, then
performs the only DynamoDB conditional create using `attribute_not_exists` for
the exact repair ID and intent. The record begins at `PLAN_VERIFIED` /
`PLAN_STATE_VERIFIED` with zero effect counters and binds the planned-state
digest plus Plan and repair versions.

Repair cannot call `PutItem`. It must re-prove the same state and invocation
graph, then consume that exact record through `UpdateItem` CAS into `CLAIMED` /
`BEFORE_FIRST_EFFECT`. Every later transition is compare-and-swap over the
immutable binding, planned state, expected stage and counters.

The table is retained, deletion protected, KMS encrypted and point-in-time
recoverable. Its resource policy permits only Plan `PutItem` and repair
`UpdateItem`, and denies unsupported or foreign writes. A host-local file is
supporting evidence only and cannot authorize or reopen a repair.

## Exact repair sequence

After the durable claim, the PEP may perform only:

1. install the sealed collector inline policy;
2. create the exact direct `USER` assignment to the authority account; and
3. provision that permission set to that account.

Before each call, the PEP refreshes complete provider state and validates the
exact predecessor. There are no mutation retries. Reserved concurrency one is
defense in depth; DynamoDB CAS remains the authoritative replay control.

The runtime has a reviewed budget: Plan/reconcile 300 seconds, repair 600
seconds, and 1024 MiB each. Repair requires 660 seconds left in the immutable
window before preflight and 480 seconds of Lambda runtime before consuming the
Plan. Its five authority epochs are initial, one post-CAS/pre-effect epoch per
effect, and final. Account-inventory calls and polling preserve 60 seconds;
provider dispatch requires 75 seconds. The local invoker is correspondingly
bounded to 315/330 seconds for Plan/reconcile and 615/630 for repair.

Any response loss, timeout, unknown asynchronous status, failed post-effect
CAS or incomplete post-effect evidence becomes `UNCERTAIN_RECONCILE_ONLY`. No
mutation may retry or resume. The only next operation is the exact read-only
reconcile alias. A failed CAS before provider dispatch proves no external
effect was attempted and returns `BLOCKED` with `REVIEW_BLOCKER` instead of
overclaiming uncertainty.

## Final evidence

Verified state requires complete Identity Center and authority-account IAM
readback: exact metadata/tags/policy, one direct `USER`, only the reviewed
target, no attachment/boundary, one materialized collector role and one
materialized repair-invoker role under their distinct `AWSReservedSSO_*`
prefixes, exact SAML trust/audience and exact role inline policy with no extra
authority.

Final readback lists provisioned accounts without a status filter, enumerates
assignments for every observed account, lists every `IN_PROGRESS` assignment-
creation, assignment-deletion and permission-set-provisioning request and then
describes each request ID. Any operation bound to either exact permission set
blocks verification.

An API success response, waiter or expected role prefix is not sufficient.
Incomplete pagination or access is blocked, never inferred.

The PEP also self-verifies its local control plane before Plan creation, before
the Plan-to-repair transition, before every
provider dispatch and during final readback: exact alias-to-version mapping,
code hash, code-signing configuration and signing-profile version, concurrency,
async settings, absence of Lambda resource policies, function URLs and event
sources, DynamoDB ARN/SSE/PITR/deletion/resource policy/TTL, and KMS identity,
rotation, alias, tags and key policy. Effective IAM readback compares three
authority execution roles, the invocation inspector and two management service
roles with the bundled policy contracts, including exact trust, path, inline
policy, zero managed attachments and boundary state. Sensitive role actions are
also conditioned on the exact `lambda:SourceFunctionArn`, preventing another
Lambda from reusing any execution role outside the PEP.

Because that AWS condition is unqualified, runtime also paginates the complete
regional function inventory with all versions plus the exact version and alias
sets for all three reviewed functions. Only `$LATEST`, one reviewed published
version per function and the three reviewed aliases may exist. Extra versions,
aliases, target drift, protected-role reuse or incomplete inventory block before
ledger access or effect.

Local function exclusivity is not caller authentication. On every provider
snapshot, the runtime assumes the exact inspector and reuses the GUG-218
provider-derived collector semantics across all enabled Regions and complete
IAM authorization details. Exactly one reviewed SSO invoker role and three
qualified alias edges may exist. Foreign/unknown edges, mutation authority,
missing coverage, stale evidence or graph drift blocks before ledger access or
effect.

## Single-operator limitation

The current roster contains one person. That person may perform sequential
non-production logins after an exact authorization, but multiple sessions do
not create an independent reviewer. Independent approval and production
separation of duties remain blocked.

## Post-merge hardening amendment

Seven independent review findings were reconciled without expanding authority.
SSO Admin and IAM inventory now use bounded, operation-capability-aware AWS CLI
pagination with `NextToken`/`--starting-token`, exact page limits and replay
rejection; `list-tags-for-resource` omits the unsupported `--page-size`. Runtime
readback binds distinct exact descriptions for each operational `$LATEST`
function and immutable version. The evidence validator accepts the same
durable `PLAN_VERIFIED` ledger and receipt matrix already produced and required
by the runtime, invoker and JSON schemas, reconstructs and hashes the immutable
initial Plan binding for every ledger state, and rejects modified or legacy
unproven Plan evidence. This amendment is
implemented and locally testable only; it is not live validation or permission
to invoke the PEP.

`ClientContext` proves synchronous transport only; the handler does not
authenticate that named person. Caller attribution remains in the exclusive
Identity Center assignment, IAM invoke edge, CloudTrail and account-wide
Lambda authority inventory. The package also binds, but does not vendor, the
Lambda-managed AWS SDK, so a fresh `PLAN_VERIFIED` plus an administrative
change freeze is required immediately before repair.

## Evidence state

| Evidence | State |
|---|---|
| Server-side PEP architecture, IaC, policies, contracts, tests and docs | **Implemented** only on the exact reviewed commit |
| Named local checks | **Locally validated** only when recorded passing for that commit |
| Required GitHub checks | **CI validated** only when green for that commit |
| Management/authority stacks and aliases | **Not live validated** |
| DynamoDB durable claim and repair | **Not executed** |
| Final SSO/IAM readback | **Not live validated** |
| Candidate A/B validation | **Blocked** pending `RECONCILE_VERIFIED` plus a dedicated collector SSO session |
| Independent human approval | **Blocked** |
| Production | **NO-GO** |

## Explicit exclusions

GUG-221 does not authorize AWS deployment, CloudFormation execution, direct
Identity Center edits, Lambda live invocation, Terraform Apply, Change Set
retirement, customer deployment, migration, destruction, redrive or
production.

Legacy or customer-data migration is **not applicable** to GUG-221: this work
repairs only one partial non-production control-plane permission-set state and
does not read or transform customer documents. The next program gate remains
GUG-117 after reviewed merge, `main` verification and separately authorized
live non-production evidence; GUG-117 is not closed by repository or CI proof.

## Do not ingest

Do not ingest live principal IDs, complete ARNs, SAML providers, KMS keys,
session identities, rendered policies, private intents, ledger items,
provider responses, receipts, AWS caches, logs or screenshots. This document
is the sanitized NotebookLM source.

## Authoritative references

- [ADR-047](../ADR/ADR-047-lambda-audit-provisioning-repair.md)
- [Deployment contract](../docs/deployment/platform-authority-lambda-audit-provisioning-repair.md)
- [Operations runbook](../docs/operations/platform-authority-lambda-audit-provisioning-repair.md)
- [Threat-model delta](../docs/security/gug-221-lambda-audit-provisioning-repair-threat-model-delta.md)
