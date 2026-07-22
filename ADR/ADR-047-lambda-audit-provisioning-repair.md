# ADR-047: Server-Side PEP for Lambda Audit Provisioning Repair

- **Status:** Accepted for repository implementation and non-production review
- **Date:** 2026-07-21
- **Work package:** GUG-221
- **Amends:** ADR-046
- **Depends on:** GUG-219 and GUG-220
- **Production:** **NO-GO**

## Context

GUG-220 consumed its one-shot execution window at an ambiguous AWS IAM Identity
Center boundary. Sanitized read-only reconciliation found an exact partial
state: `ScanalyzeAuthorityLambdaAudit` exists, while its reviewed inline
policy, direct `USER` assignment, target-account provisioning and account-local
collector role are absent or unverified. The GUG-220 ledger remains evidence of
the prior attempt and is never reset, deleted, overwritten or reused.

A direct human repair session is not a sufficient policy-enforcement point.
IAM can restrict actions and resources, but it cannot prove the complete
payload, ordered predecessor states, policy digest, principal identity,
one-shot execution or post-effect evidence needed by GUG-221. A host-local
file also cannot prevent replay from another workstation. Giving the human
session the three Identity Center mutations would therefore leave a bypass
around the runtime contract.

The current operating roster has one person. Separate profiles, roles or login
windows used by that person are not independent human approval.

## Decision

### 1. Put the authoritative PEP behind private, versioned Lambda aliases

The human permission set is `ScanalyzeLambdaAuditRepair`. It may invoke only
these exact private aliases in the authority account ending in `7644`, Region
`us-east-1`:

```text
scanalyze-authority-lambda-audit-plan:plan-v1
scanalyze-authority-lambda-audit-repair:repair-v1
scanalyze-authority-lambda-audit-reconcile:reconcile-v1
```

Every invocation payload must be exactly the empty JSON object `{}`. Request
headers, environment overrides, function names without qualifiers, arbitrary
aliases and request-supplied identifiers are non-authoritative. Functions have
no URL, public permission or event source. Because `lambda:InvokeFunction`
cannot be IAM-conditioned by invocation type, each alias has an explicit
asynchronous configuration with zero retries, a 60-second maximum event age
and no destination. Runtime additionally requires the reviewed synchronous-
only `ClientContext` marker before reading provider state or claiming the
ledger; asynchronous invocation cannot carry that marker and therefore cannot
reach a protected effect. The marker proves transport only: it does not select
an account, principal, permission set, policy, mode or action and is never an
authorization credential. Each alias points to a pinned published version whose
code hash, code-signing configuration and immutable environment are reviewed.

The human permission set has no `sso:*`, `identitystore:*`, `iam:*`,
`sts:AssumeRole` or DynamoDB mutation authority. A human can request a reviewed
operation; only the server-side PEP can evaluate and perform it.

### 2. Separate Plan, repair and reconciliation execution authorities

The authority account contains distinct Plan, repair and reconcile Lambda
functions, published versions, aliases and execution roles.

- The Plan execution role may only create the exact durable `PLAN_VERIFIED`
  record with `dynamodb:PutItem`, assume the management readback service role
  and read the authority control plane.
- The repair execution role may only advance that existing record with
  `dynamodb:UpdateItem` and assume the management mutation service role. It
  cannot create a record, so direct invocation cannot bypass Plan.
- The reconcile execution role has no DynamoDB write or Identity Center
  mutation authority. It assumes only the management readback service role and
  reads the exact authority-account IAM state required for evidence.
- A fourth authority-account role, the path-scoped invocation-authority
  inspector, is assumable only by those three execution roles. It can inventory
  the complete account-wide IAM and Lambda invocation graph but explicitly
  cannot invoke Lambda, mutate IAM or Lambda, or chain to another role.
- `repair-v1` is the only Identity Center mutation path.

The management account ending in `1433` contains two non-human service roles:

```text
ScanalyzeLambdaAuditRepairMutationServiceRole
ScanalyzeLambdaAuditRepairReadbackServiceRole
```

Their trust policies use the authority-account root only as a stable,
pre-creatable principal and require both the exact authority account and
`ArnEquals aws:PrincipalArn` for the corresponding Lambda execution role. This
breaks the management-first bootstrap cycle without allowing another root,
role, SSO session or IAM user to assume them. Both the caller policies and
target trusts bind `sts:SetSourceIdentity` to the same exact `sts:AssumeRole`
edge for durable attribution.
The mutation role exposes only the required reads and these three effects:

```text
sso:PutInlinePolicyToPermissionSet
sso:CreateAccountAssignment
sso:ProvisionPermissionSet
```

The readback role exposes only reviewed `List`, `Get` and `Describe` surfaces.
Neither role permits permission-set creation/deletion, assignment deletion,
managed-policy attachment, permissions-boundary mutation, relay, Lambda
invocation or customer/production deployment.

The complete service control plane has six roles: Plan, repair, reconcile,
invocation inspector, management mutation and management readback. The
materialized human SSO role is a separate invoke-only principal.

### 3. Derive authority exclusively from immutable server configuration

The pinned Lambda version binds the exact source commit, repair ID, validity
window, Identity Center instance, Identity Store, immutable `USER`, collector
permission-set ARN/name/tags, authority and management accounts, Region,
collector policy digest, repair-invoker policy digest, GUG-220 ledger digest, SAML
provider, KMS mode/key and service-role ARNs.

The PEP validates its qualified invocation ARN, local Lambda execution role,
numeric function version, alias-to-mode mapping and a validity window of at
most 15 minutes. It rejects missing, malformed, expired or conflicting
configuration. The empty event cannot select an account, principal, permission
set, policy, mode or action.

Because `lambda:SourceFunctionArn` is intentionally unqualified, the PEP also
enumerates the complete regional Lambda function inventory with all versions,
then independently enumerates every version and alias of all three reviewed
functions. It requires only `$LATEST` plus the one reviewed published version,
only the three reviewed aliases, exact alias targets, and exclusive use of the
three protected execution roles by the three reviewed functions. Any
additional version, alias, role reuse, missing page or malformed pagination
blocks before ledger access or provider dispatch.

The Lambda runtime does not receive the original IAM caller identity. It must
therefore assume the exact invocation-authority inspector role and use the
GUG-218 collector semantics to prove the complete account-wide IAM/Lambda
graph for all three aliases on every provider snapshot. Exactly one reviewed
`AWSReservedSSO_ScanalyzeLambdaAuditRepair_*` role and exactly three qualified
invoke edges may exist; foreign or unknown edges, mutation authority,
incomplete coverage, stale evidence or graph drift between snapshots blocks
before ledger access or a protected effect. `ClientContext` remains transport
evidence only and is never accepted as caller authorization.

### 3A. Bind deployment to a clean commit and one exact signed object version

Code signing alone proves that a ZIP was signed by an allowed publisher; it
does not prove that the ZIP contains the reviewed source. The deployment chain
therefore has two independent fail-closed anchors:

1. a deterministic builder proves a clean exact Git commit, tracked source
   bytes, a closed sixteen-entry archive and an internal lock for the exact
   managed SDK versions; and
2. a read-only verifier rebuilds that package, reads the Signer job and exact
   S3 source/signed versions directly from AWS, requires versioning and
   SHA-256, rejects overwrites/delete markers/additional executable entries,
   and emits the only eligible CloudFormation parameter tuple.

Operator-supplied downloaded ZIPs, manifests, provider JSON, ETags and
`latest` reads are not authority. The signed destination key must end in the
exact Signer job ID and have exactly one version. Both Lambda functions must
use the same signed bucket, key, version and final signed `CodeSha256`. The
unsigned digest can never be substituted into the Change Set.

### 3B. Enforce a two-phase Change Set dependency boundary

The management delegation must exist before its provider-created repair
permission-set ARN can be an authority input to the authority PEP. GUG-221
therefore never emits or verifies both CREATE Change Sets concurrently.

Phase A uses only the fixed management and authority `ReadOnlyAccess` sessions
to enumerate the consumed GUG-220 chain twice. It derives the Identity Center
instance, store, encryption mode/key, exact principal, exact partial collector
permission set, SAML provider and absent collector role from AWS. Pending
assignment/provisioning operations are checked before and after each snapshot;
the two complete provider-state digests must agree. An operator-authored or
self-digested evidence file is never authority. The provider receipt and ten
delegation parameters are private, mode `0600`, create-only artifacts. The
deployment contract carries only source/window/creator choices and cannot
carry raw provider identifiers or GUG-220 authority.

After separately authorized execution of Phase A, exact stack, template,
outputs, resources, permission-set policy/tags/attachments/boundary/global
assignment state and management service roles are read back. The readback also
requires the immutable review receipt, its deterministic `ClientRequestToken`,
one exact CloudTrail `ExecuteChangeSet` event by the contract-bound executor,
and complete terminal `DescribeStackEvents` lineage carrying that token. A
state-equivalent stack without the reviewed execution lineage is rejected.
Only that live receipt supplies the repair-invoker ARN to Phase B. Phase B
refreshes both the GUG-220 provider snapshot and the complete Phase A live
state, then combines the provider-derived values with the provider-refreshed
signed-artifact tuple to verify the 29-value PEP CREATE Change Set.

The Phase A execution receipt preserves `evaluated_at` as observation evidence,
but its immutable binding digest excludes only that field. Phase B likewise
normalizes only the outer and nested observation timestamps before comparing
the supplied and freshly collected live receipts. All CloudTrail events,
StackEvents, actors, tokens, digests and verifier identities remain bound; a
later read-only observation cannot create false drift.

Each Change Set independently requires its canonical UUID-bearing ARN/name,
exact stack, `CREATE`/`CREATE_COMPLETE`/`AVAILABLE`, rollback-on-failure,
empty rollback triggers/notifications, no `RoleARN`, no import/nested/deployment
mode, exact unmasked parameters/tags/template/resource inventory and one exact
CloudTrail `CreateChangeSet` event. The tool contains no Create, Execute or
Delete operation. Repository and read-only evidence remain **NO-GO**.

### 4. Require a durable Plan record before repair

`plan-v1` first proves the exact eligible provider state and complete
invocation-authority graph, then performs the only allowed DynamoDB conditional
create for the exact repair ID and intent digest:

```text
ConditionExpression: attribute_not_exists(repair_id)
status: PLAN_VERIFIED
stage: PLAN_STATE_VERIFIED
effects_attempted: 0
effects_completed: 0
```

The table is KMS encrypted, deletion protected, point-in-time recovery enabled
and retained on stack replacement/deletion. Its resource policy denies writes
except the exact Plan role for `PutItem` and the exact repair role for
`UpdateItem`; unsupported write APIs are denied to both. `repair-v1` cannot
create the item. It must re-prove the same provider-state and invocation graph,
then atomically consume the exact `PLAN_VERIFIED` record by transitioning it to
`CLAIMED` / `BEFORE_FIRST_EFFECT`. Subsequent stage transitions use
compare-and-swap conditions over repair ID, intent, source, Plan and repair
versions, planned-state digest, prior stage and effect counters.

Failure to create or read back the Plan record means no mutation begins. A
missing, conflicting, malformed, stale or already-consumed Plan is not adopted.
The provider-backed Plan/repair state machine is the live replay barrier;
host-local evidence is not mutation authority and cannot open another execution
window.

### 5. Preserve exact ordering and make ambiguity terminal

After the repair function atomically consumes the durable Plan, the PEP
re-reads the complete live state and exact invocation graph before every effect
and permits only:

1. the sealed collector inline policy;
2. the exact direct `USER` assignment to the authority account; and
3. explicit provisioning of that permission set to that account.

Any unexpected policy, principal, group, account, boundary, attachment,
pagination gap, role or predecessor state stops the sequence. There are no SDK
or orchestration retries for mutation. Provider-backed alias configuration
sets Lambda asynchronous retries to zero, bounds event age to 60 seconds and
has no destination. An async request can still be delivered and the service
may duplicate queued events, so the missing synchronous `ClientContext` marker
and durable CAS remain mandatory controls. Reserved concurrency limits the
repair function to one concurrent execution, but concurrency control does not
replace DynamoDB CAS.

The runtime budget is part of the authorization contract, not an availability
tuning knob. Plan and reconcile run with a 300-second timeout; repair runs with
600 seconds; all three use 1024 MiB. Repair requires at least 660 seconds left
in the immutable 15-minute window before preflight and at least 480 seconds of
Lambda runtime immediately before consuming `PLAN_VERIFIED`. It takes exactly
five complete authority epochs: initial, one immediately after each
`ATTEMPTING_n` CAS and before its provider effect, and final. Every account-wide
inventory provider call checks for a 60-second fail-closed reserve. Provider
dispatch requires 75 seconds and polling preserves 60 seconds so an ambiguous
result can still be committed to the durable ledger.

A timeout, transport loss, unknown asynchronous result, a failed post-effect
CAS transition or incomplete post-effect evidence becomes:

```text
UNCERTAIN_RECONCILE_ONLY
```

No mutation is retried or resumed. Only `reconcile-v1` may be invoked next.
A failed CAS before dispatch proves that no provider effect was attempted and
therefore returns `BLOCKED` with `REVIEW_BLOCKER`; it does not overclaim an
uncertain external write.

### 6. Require independent final SSO and IAM readback

Final success requires fresh read-only evidence from both boundaries:

- Identity Center: exact instance/store, collector metadata/tags, canonical
  inline policy, one direct `USER`, only the authority target, and no managed or
  customer-managed attachment or permissions boundary. Provisioned accounts
  are listed without status filtering, assignments are enumerated for every
  observed account using the current Organizations `State` contract (never the
  retired `Status` field), and every `IN_PROGRESS` assignment-creation,
  assignment-deletion and permission-set-provisioning request ID is described
  before requiring no operation bound to either exact permission set.
- Authority-account IAM: exactly one materialized collector role and one
  materialized repair-invoker role under their distinct reviewed
  `AWSReservedSSO_*` prefixes, exact SAML trust/audience and inline-policy name
  and digest for each, and no extra inline or managed policy, boundary or relay
  path.
- DynamoDB: the exact durable intent and monotonic effect attribution.

A successful API response, waiter, expected name prefix or Lambda completion is
not final evidence. Missing access or incomplete pagination yields a blocked or
incomplete result, never a verified receipt.

### 7. Keep governance and evidence claims explicit

The same person may perform the operational logins while the team has one
member, but that is a documented single-operator constraint. It does not
satisfy independent approval, separation of duties or production release
requirements.

Repository implementation, local validation, CI validation and live AWS
validation are separate evidence classes. This ADR authorizes none of the AWS
mutations described above. Deployment of either stack, invocation of any live
alias and repair of provider state require separate, exact authorization.

## Consequences

- Human credentials cannot call the Identity Center repair APIs directly.
- The server-side PEP, immutable version configuration and durable CAS record
  jointly bind the only mutation path.
- The deployment artifact is reproducible from a reviewed commit and the
  Change Set cannot consume an operator-asserted or extra-entry signed ZIP.
- Plan, repair and reconciliation cannot share write authority; repair cannot
  create or replace Plan evidence.
- The exact account-wide invocation graph is a runtime precondition on every
  snapshot, not an operator assertion or an offline report.
- An ambiguous effect is terminal for mutation and remains attributable to the
  durable claim.
- The design can be reproduced per installation by supplying reviewed bindings
  without accepting request-derived authority.
- The ZIP intentionally binds, but does not vendor, the Lambda-managed
  `boto3`/`botocore` versions. A managed-runtime update therefore blocks
  fail-closed. A fresh `PLAN_VERIFIED` receipt immediately before repair is a
  mandatory operational control until the SDK is vendored in a separately
  reviewed package or layer.
- The synchronous `ClientContext` proves transport only. The handler does not
  authenticate a named human; human attribution remains an outer IAM/Identity
  Center control and must be corroborated by the account-wide Lambda authority
  inventory.
- Runtime calls set deterministic `SourceIdentity`, but target trusts do not
  yet require its presence; this is a forensic-attribution hardening gap.
- DynamoDB cannot enforce the signed handler's exact `ConditionExpression`
  through IAM. The empty payload, exact aliases, code signing, role isolation,
  `lambda:SourceFunctionArn` and complete CAS remain the enforcement set.
- A guard failure after `ATTEMPTING_n` and before provider dispatch consumes
  the repair conservatively. Reconciliation and a new reviewed repair are
  required; the original ledger is never replayed.
- A single operator remains a governance blocker for independent approval.
- Production remains **NO-GO**.

## Alternatives rejected

- **Direct SSO executor with three Identity Center writes:** bypasses payload,
  sequence, digest and durable replay enforcement.
- **Host-local create-only ledger:** cannot coordinate or resist replay across
  workstations and is not provider-backed.
- **One Lambda/role for Plan, repair and reconcile:** lets read-only recovery or
  Plan creation inherit mutation authority and permits repair to bypass the
  durable Plan gate.
- **Human-supplied repair payload:** turns request data into authority.
- **Unqualified Lambda ARN or function URL:** permits code/version drift or an
  unintended public invocation path.
- **Automatic retry after timeout:** the provider may have completed the write.
- **Treat two sessions held by one person as two approvals:** technical session
  separation is not independent human review.

## Failure, containment and rollback

Before the durable Plan-to-repair transition, any failure is Identity Center
mutation-free. After that transition or a
possibly started provider call, stop all mutation and invoke only the exact
read-only reconcile alias. Preserve the table record and private evidence.

Cloud rollback is not implicit. Assignment deletion, deprovisioning, policy
removal, permission-set deletion, table deletion or stack deletion are separate
destructive operations requiring another issue, authorization and readback.
Repository rollback is a reviewed revert; deployed versioned aliases must not
be repointed without a separately reviewed change.

## Evidence classification

| Evidence class | Current status |
|---|---|
| Server-side PEP, IaC, policies, contracts, tests and documentation | **Implemented** only on the exact reviewed repository commit |
| Named local gates | **Locally validated** only when their recorded results pass for that commit |
| Required GitHub checks | **CI validated** only after completion for that exact commit |
| Authority and management stacks | **Not live validated**; no AWS deployment performed by GUG-221 repository work |
| Durable DynamoDB Plan/repair state machine | **Not executed** |
| Final collector SSO/IAM readback | **Not live validated** |
| Candidate A/B validation | **Blocked** until `RECONCILE_VERIFIED` and a dedicated collector SSO session are independently evidenced |
| Independent human approval | **Blocked** while one person is on the roster |
| Production | **NO-GO** |

## References

- [Deployment contract](../docs/deployment/platform-authority-lambda-audit-provisioning-repair.md)
- [Operations runbook](../docs/operations/platform-authority-lambda-audit-provisioning-repair.md)
- [Threat-model delta](../docs/security/gug-221-lambda-audit-provisioning-repair-threat-model-delta.md)
- [ADR-046](ADR-046-lambda-audit-permission-set-provisioning.md)
