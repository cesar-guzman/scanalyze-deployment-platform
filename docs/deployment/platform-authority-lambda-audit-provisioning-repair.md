# GUG-221 server-side Lambda audit provisioning repair

## Purpose

GUG-221 defines a fail-closed, server-side policy-enforcement point (PEP) for
repairing one exact partial `ScanalyzeAuthorityLambdaAudit` permission-set
state. It is a new operation and never a retry of GUG-220.

This repository package is portable: every installation supplies its own
reviewed Identity Center, principal, permission-set, SAML, KMS and account
bindings through immutable deployment configuration. No live identifier or
request value can widen the contract.

Repository implementation does not authorize AWS deployment or invocation.
Production remains **NO-GO**.

## Eligible starting state

The Plan provider preflight may classify the state as repairable only when all
of these facts are complete and exact. Its later durable `PutItem` is described
separately and is not an Identity Center mutation:

| Surface | Required state |
|---|---|
| Collector permission set | `ScanalyzeAuthorityLambdaAudit` exists with reviewed metadata and tags |
| Inline collector policy | Absent |
| Direct assignment | Absent |
| Provisioned targets | Absent |
| Account-local collector role | Absent |
| Managed policy attachments | None |
| Customer-managed references | None |
| Permissions boundary | None |
| Foreign or group principals | None |
| GUG-220 evidence | Original ledger remains consumed and unchanged |

Absence inferred from denied access, incomplete pagination, stale data or a
similar name is not evidence. Any difference produces `BLOCKED` or incomplete
readback, not a repair plan.

## Two-account authority model

### Authority account ending in `7644`

The authority stack contains:

- separate private Plan, repair and reconcile Lambdas;
- published, code-hash-pinned versions and exact `plan-v1`, `repair-v1` and
  `reconcile-v1` aliases;
- separate Plan, repair and reconcile execution roles;
- one path-scoped invocation-authority inspector role assumable only by those
  three execution roles;
- a KMS-encrypted, point-in-time-recoverable, deletion-protected DynamoDB
  ledger with retain policies; and
- no function URL, public Lambda permission or event source, plus exact
  alias-level async configuration with zero retries, 60-second event age and
  no destination.

The Plan role is the only principal allowed to create the durable record and
has only `dynamodb:PutItem`. The repair role has only `dynamodb:UpdateItem`, so
it cannot fabricate or replace Plan evidence. The reconcile role cannot write
the ledger. The table resource policy denies unsupported write APIs and every
write by any other principal.

The invocation-authority inspector has account-wide IAM/Lambda inventory reads
needed to prove the exact invocation graph. It explicitly denies Lambda invoke,
IAM/Lambda mutation and role chaining. The three functions use it only through
one exact `sts:AssumeRole`/`sts:SetSourceIdentity` edge.

### Management account ending in `1433`

The delegation stack contains:

- `ScanalyzeLambdaAuditRepairMutationServiceRole`, usable only by the exact
  authority-account repair execution role;
- `ScanalyzeLambdaAuditRepairReadbackServiceRole`, usable only by the exact
  authority-account reconcile execution role; and
- the human `ScanalyzeLambdaAuditRepair` permission set, assigned to the
  reviewed `USER` only in the authority account.

The deployed control plane therefore has six service roles: Plan, repair,
reconcile, invocation inspector, management mutation and management readback.
The materialized human SSO role is a separate invoke-only principal and is not
one of those service roles.

The mutation service role has the minimum read surfaces plus exactly:

```text
sso:PutInlinePolicyToPermissionSet
sso:CreateAccountAssignment
sso:ProvisionPermissionSet
```

The readback service role has no Identity Center mutation. To permit the
management stack to be created first, each trust policy uses the authority
account root as the stable principal and immediately constrains it with both
`aws:PrincipalAccount` and `ArnEquals aws:PrincipalArn` for the one exact
Lambda execution-role ARN. The caller policy is restricted to the matching
service-role ARN. Both sides grant `sts:SetSourceIdentity` only with that exact
`sts:AssumeRole` edge, preserving immutable repair attribution. Neither
service role trusts a human SSO role or an unconstrained wildcard principal.

## Human invocation boundary

The human permission set can only call these exact qualified aliases:

```text
arn:aws:lambda:us-east-1:042360977644:function:scanalyze-authority-lambda-audit-plan:plan-v1
arn:aws:lambda:us-east-1:042360977644:function:scanalyze-authority-lambda-audit-repair:repair-v1
arn:aws:lambda:us-east-1:042360977644:function:scanalyze-authority-lambda-audit-reconcile:reconcile-v1
```

The request body is always:

```json
{}
```

Any non-empty object, scalar, array or null is rejected. The request cannot
carry a mode, account, Region, principal, ARN, policy, repair ID, source commit
or validity window. The alias selects the mode; the pinned Lambda version and
its immutable environment provide every authoritative binding.

The human role explicitly lacks Identity Center, Identity Store, IAM, STS role
assumption and DynamoDB write authority. Direct CLI execution of the three
repair mutations is outside this architecture.

## Immutable server binding

Each published version must bind and validate:

- source commit and code package hash;
- three numeric Lambda versions and exact alias-to-mode mapping;
- authority and management accounts and `us-east-1`;
- repair ID and a validity interval no greater than 15 minutes;
- active Identity Center instance and Identity Store;
- exact collector permission-set ARN/name/tags;
- exact immutable `USER` principal and authority target;
- canonical collector and human repair-invoker policy digests;
- original GUG-220 ledger digest;
- exact SAML provider and audience;
- Identity Center KMS mode and, when applicable, exact CMK ARN/context; and
- exact mutation and readback service-role ARNs.

The Lambda verifies its qualified invocation ARN and local execution role. A
profile name, session name, email address or environment supplied by the
caller is not authority.

## Deterministic signed-artifact boundary

The deployable Lambda artifact is closed over exactly fifteen tracked source
files plus `gug221_runtime_lock.json`. The tracked set includes eight
standalone IAM policy contracts, the GUG-218 inventory/analyzer modules and the
closed verifiers that render and compare effective authority. The
package builder accepts only a clean
40-character Git `HEAD`, proves its local builder/verifier tools and every
source are tracked and byte-identical to that commit, then packages source
bytes directly from `git show` rather than rereading the worktree. It fixes ZIP
order/metadata and binds the exact
expected `boto3` and `botocore` versions. Output is create-only, owner-only and
outside the repository. The unsigned archive and its digest are build evidence;
they are never valid CloudFormation code parameters.

The current package does not vendor those SDK modules. A Lambda-managed SDK
change is therefore an intentional fail-closed outage, not an implicit
upgrade. A fresh `PLAN_VERIFIED` receipt must confirm the reviewed versions
immediately before repair; vendoring them requires a separate reviewed package
or layer change.

AWS Lambda code signing proves signature integrity and the allowed publisher,
but it does not prove that the input was the reviewed source. GUG-221 therefore
requires a second, read-only verifier to rebuild the package from the same clean
commit and independently converge all of these facts:

- the commit is both the local `origin/main` and the current protected GitHub
  `main`, is the exact merged-PR commit, has the same tree as the reviewed PR
  head, and all six required checks are green from the GitHub Actions App under
  the exact live branch-protection policy;
- exact authority-account `AWSReadOnlyAccess` SSO caller and `us-east-1`;
- successful AWS Signer job, exact owner/invoker/platform/profile version and
  unexpired signature;
- exact source bucket/key/version returned by `DescribeSigningJob`;
- versioning enabled and mandatory S3 SHA-256 on both source and signed object;
- signed key ending in the exact Signer job ID, exactly one object version, no
  delete marker and exact-version `HeadObject` plus `GetObject` readback;
- byte-for-byte equality between the source object and the deterministic local
  rebuild; and
- a readable signed ZIP with exactly the sixteen reviewed entries, no duplicate,
  encrypted, symlink or additional executable entry.

The verifier accepts no operator-supplied AWS readback JSON or downloaded ZIP.
It obtains GitHub evidence through authenticated read-only API calls and rejects
a stale local main ref, a homonymous check from another App, protection drift,
an unmerged commit or a different PR/merge tree.
It emits one create-only private receipt whose twelve CloudFormation parameters
bind all three functions to the same signed S3 bucket, key, version and final
signed `CodeSha256`, plus the clean commit, SDK versions and signing-profile
version.
Only that signed digest may reach CloudFormation.

The signed receipt is necessary but not sufficient for Phase B. The private
deployment contract intentionally excludes principal, instance/store, SAML,
KMS, collector/invoker permission-set ARNs, policy digests, GUG-220 ledger
digest and repair ID. Those values are derived from the immutable GUG-220
chain plus fresh provider readback; the repair ID is deterministic.
It does bind separate exact Phase A creator and executor session ARNs. The
review receipt derives one deterministic `ClientRequestToken` from the exact
Change Set ARN, UUID, stack ARN, reviewed template and parameter handoff.

The order is strict. Phase A snapshots the GUG-220 partial state twice through
only `042360977644_ReadOnlyAccess` and `839393571433_ReadOnlyAccess`, with
pending-operation checks before and after each snapshot, then emits ten
delegation parameters. After a separately authorized Phase A execution, exact
live stack/Identity Center/IAM readback produces the only eligible
repair-invoker ARN. Phase B revalidates that state and only then emits/verifies
the 29 PEP parameters. A copied or self-digested provider JSON cannot authorize
either verifier.

Those fixed profiles are discovery-only operator sessions, not service or
mutation roles. The pre-Phase-A collector uses only `sts:GetCallerIdentity`;
SSO Admin `ListInstances`, `DescribeInstance`, permission-set metadata/tags,
policy/attachment/boundary, global assignment, provisioning and pending-status
List/Get APIs; Identity Store `ListUsers`/`DescribeUser`; Organizations
`ListAccounts`; authority IAM `ListSAMLProviders`, `GetSAMLProvider` and
`ListRoles`; and `kms:DescribeKey` only when `DescribeInstance` returns a
customer-managed key. APIs whose AWS authorization model requires
`Resource: "*"` are confined to these fixed read-only sessions. They are not
added to the repair mutation role, the management service roles or either
CloudFormation template.

Both CREATE Change Set verifiers also bind the exact CloudTrail
`CreateChangeSet` request and reject a role ARN, import, nested stacks,
deployment mode, notifications, rollback drift, masked parameters, template
drift, pagination gaps or foreign resources. The GUG-220 ledger digest retains
its `sha256:` type in evidence and is normalized to 64 lowercase hex only at
the CloudFormation/broker parameter boundary.

Phase A live readback additionally requires the original review receipt. It
accepts exactly one CloudTrail `ExecuteChangeSet` event from the contract-bound
executor whose request contains the UUID-bearing Change Set ARN, exact stack
ARN and derived `ClientRequestToken`. Complete `DescribeStackEvents`
pagination must bind every terminal resource and the root stack to that same
token. A state-equivalent stack, manually selected token, foreign actor,
duplicate execution event, incomplete event page or missing terminal event is
not accepted as execution provenance. The execution trace receipt is
create-only, private evidence and remains non-authoritative and **NO-GO**.

The signed-artifact binding digest covers every receipt field except the
provider observation timestamp `evaluated_at`. Phase B requires canonical
equality of all remaining fields between the private receipt and the fresh
Signer/S3/GitHub readback, then records that stable digest. A refreshed clock
therefore cannot break an otherwise identical handoff, while any artifact,
version, checksum, source-review or verifier-identity drift still blocks.

The same narrow rule applies to the Phase A execution trace: its nested
`evaluated_at` remains in the evidence file but is excluded from the immutable
execution binding and from sequential live-readback equality. Execute/stack
event times, event digests, actor, deterministic token, terminal resources and
verifier identity are never normalized away.

Building, uploading, signing and deploying remain distinct operations requiring
separate authorization. This repository change performs none of them.

Before Plan record creation, before the Plan-to-repair transition, before each
protected dispatch and at final readback, runtime
also revalidates the complete local PEP control plane: the alias/version/code
and signing tuple; concurrency and async settings; absence of Lambda resource
policies, URLs and event sources; DynamoDB identity, encryption, PITR,
deletion/resource policy and disabled TTL; KMS identity, rotation, alias, tags
and key policy; and exact effective IAM for the three authority execution
roles, the invocation-authority inspector and both management service roles.
Sensitive authority-role calls are conditioned
on their exact `lambda:SourceFunctionArn`, so a foreign Lambda cannot reuse the
role as an alternate PEP.

The `SourceFunctionArn` condition is unqualified by AWS design, so runtime does
not treat it as sufficient on its own. It completely paginates the regional
`ListFunctions` inventory with all versions, the version inventory for each
reviewed function and all three alias inventories. Only `$LATEST`, the single
reviewed published version and the exact `plan-v1`, `repair-v1` and
`reconcile-v1` aliases may exist; the protected roles may be used by no other
function. Any extra version or alias, changed target, role reuse, incomplete
page or duplicate inventory item blocks the PEP before ledger access or a
protected effect.

That local proof is necessary but not sufficient. For every provider snapshot,
the function assumes the exact inspector role and reuses the GUG-218
provider-derived collector semantics across all enabled Regions and complete
IAM authorization details. It requires one reviewed materialized invoker role,
exactly three qualified invocation edges, zero foreign/unknown edges and zero
mutation authority. The authority-graph digest must remain stable across the
operation. Missing coverage, access denial, stale evidence or graph drift is
`BLOCKED` before ledger access or effect.

## Durable Plan and replay barrier

Only `plan-v1` may create the provider-backed ledger. After proving the exact
eligible state and invocation graph, it performs a conditional create
equivalent to:

```text
attribute_not_exists(repair_id)
```

The Plan record binds the repair ID, intent digest, source commit, original
GUG-220 ledger digest, both accounts, Region, Plan and repair versions, validity
window, planned-state digest and counters. It begins at `PLAN_VERIFIED` /
`PLAN_STATE_VERIFIED` with zero attempted and completed effects.

`repair-v1` cannot call `PutItem`. It must observe that exact, unconsumed record,
re-prove the same provider-state and invocation-graph digests, and use
`UpdateItem` compare-and-swap to enter `CLAIMED` / `BEFORE_FIRST_EFFECT`.
Every later transition also binds the expected repair, intent, source, Plan and
repair versions, planned state, stage and counters. A missing, existing,
ambiguous, stale or unreadable record stops mutation. No direct repair call,
second workstation, Lambda retry or alternate intent can acquire another
execution window.

Local files and the older host-local schema are supporting offline evidence
only. They are not the live replay barrier and do not authorize AWS writes.

## Server-side state machine

```text
plan-v1 {}
  -> validate pinned version/configuration/time
  -> complete SSO + IAM + account-wide invocation-authority preflight
  -> DynamoDB conditional PutItem of exact PLAN_VERIFIED record
  -> PLAN_VERIFIED | BLOCKED

repair-v1 {}
  -> validate pinned version/configuration/time
  -> prove exact partial state and stable invocation-authority graph
  -> require exact PLAN_VERIFIED record and CAS to CLAIMED
  -> PutInlinePolicyToPermissionSet
  -> CAS stage transition + complete predecessor readback
  -> CreateAccountAssignment
  -> CAS stage transition + complete predecessor readback
  -> ProvisionPermissionSet
  -> CAS final attribution + complete SSO/IAM readback
  -> REPAIR_VERIFIED

any possibly started or unattributable effect
  -> UNCERTAIN_RECONCILE_ONLY
  -> no retry or resume

reconcile-v1 {}
  -> read-only ledger, SSO, IAM and invocation-authority inspection
  -> RECONCILE_VERIFIED | BLOCKED
```

There is no transition from `UNCERTAIN_RECONCILE_ONLY` back into repair.

The deployable runtime uses fixed operational budgets: Plan and reconcile are
300 seconds, repair is 600 seconds, and each function has 1024 MiB. A repair
must still have 660 seconds in its immutable window before preflight and 480
seconds of Lambda runtime before the Plan-to-Claimed CAS. The repair performs
five complete authority snapshots: initial, one immediately after each of the
three `ATTEMPTING_n` transitions and before provider dispatch, and final.
Every account-inventory provider call fails closed at the 60-second reserve;
provider dispatch requires 75 seconds and async polling keeps 60 seconds for
durable uncertainty attribution. These limits are validated against both the
CloudFormation template and the local invoker's 315/330-second read/process
timeouts for Plan/reconcile and 615/630 seconds for repair.

## Mutation rules

Before each of the three calls, the PEP refreshes complete state and requires
the exact predecessor. It never adopts unexpected progress or overwrites
foreign state.

SDK mutation retries are disabled. Lambda has no event source or unqualified
invocation authority. Direct `lambda:InvokeFunction` cannot be restricted by
IAM to `RequestResponse`, so the wrapper supplies a reviewed synchronous-only
`ClientContext` marker and runtime rejects its absence before any protected
effect. Every alias also has provider-backed async configuration with zero
retries, maximum event age 60 seconds and no destination. Reserved concurrency
is one. Timeout, response loss, provider error, unknown async status, failed
CAS or incomplete pagination is terminal for mutation.

The marker does not authenticate a named human. Human attribution remains in
the exclusive Identity Center assignment, IAM invoke edge and CloudTrail; an
account-wide Lambda authority inventory and an administrative change freeze
are required from final plan through `RECONCILE_VERIFIED`.

## Final readback

Verified repair requires all of the following:

1. exact Identity Center instance and Identity Store;
2. active management-owned Identity Center instance plus exact collector
   metadata, tags, `PT1H` session duration and absent RelayState;
3. exact repair-invoker metadata, tags, `PT1H` session duration, absent
   RelayState and canonical invocation-only inline-policy digest;
4. exact canonical collector inline-policy digest;
5. no managed/customer-managed policies or permission boundary on either
   permission set;
6. exactly one direct `USER` assignment and no group assignment for each
   reviewed permission set;
7. provisioning to only the authority account ending in `7644`;
8. exactly one account-local `AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_*`
   collector role and one
   `AWSReservedSSO_ScanalyzeLambdaAuditRepair_*` invoker role;
9. exact SAML provider, audience and action set
   (`sts:AssumeRoleWithSAML` plus `sts:TagSession`) for both roles;
10. exact account-local inline-policy name and digest for both roles; and
11. no extra inline/managed policy, permissions boundary or relay path on
    either role.

All list surfaces require complete pagination with token replay detection.
Final proof lists `IN_PROGRESS` assignment-creation, assignment-deletion and
permission-set-provisioning requests for the exact instance, then describes
every returned request ID before deciding whether it applies to either exact
permission set. A relevant operation blocks verification. Account enumeration
is run without a provisioning-status filter, validates the current
Organizations `State` field rather than the retired `Status` field, and reads
assignments for every observed account before exact-target validation.
Readback comes from the dedicated management readback service role plus the
authority-account IAM reader. A mutation response, waiter or expected role
prefix alone cannot produce `REPAIR_VERIFIED`.

## Infrastructure and policy artifacts

| Artifact | Purpose |
|---|---|
| `bootstrap/cfn-platform-authority-lambda-audit-repair-pep.yaml` | Authority-account Plan/repair/reconcile functions, versions, aliases, four local IAM roles, KMS and durable ledger |
| `bootstrap/cfn-platform-authority-lambda-audit-repair-delegation.yaml` | Management service roles, human invoker permission set and exact assignment |
| `tooling/platform_authority_lambda_audit_repair_broker.py` | Pure empty-event, configuration, state, ledger and receipt contracts |
| `tooling/platform_authority_lambda_audit_repair_package.py` | Clean-commit deterministic package and runtime lock |
| `tooling/platform_authority_lambda_audit_repair_signed_artifact.py` | Direct read-only Signer/S3 verification and exact signed CFN handoff |
| `tooling/platform_authority_lambda_audit_repair_change_set.py` | Create-only 29+10 parameter handoff and read-only exact comparator for both Change Sets |
| `policies/iam/platform-authority-lambda-audit-repair-invoker-role.json` | Exact human alias invocation only |
| `policies/iam/platform-authority-lambda-audit-plan-authority-execution-role.json` | Plan-only readback and create-only durable-record boundary |
| `policies/iam/platform-authority-lambda-audit-repair-authority-execution-role.json` | Authority repair execution and durable CAS boundary |
| `policies/iam/platform-authority-lambda-audit-reconcile-authority-execution-role.json` | Authority read-only reconciliation boundary |
| `policies/iam/platform-authority-lambda-audit-repair-invocation-inspector-role.json` | Account-wide invocation-graph inventory with invoke/mutation/relay explicit denies |
| `policies/iam/platform-authority-lambda-audit-repair-mutation-service-role.json` | Exact management mutation service role |
| `policies/iam/platform-authority-lambda-audit-repair-readback-service-role.json` | Management read-only service role |

Existing GUG-221 schemas and fixtures remain typed offline evidence. They do
not grant direct human mutation authority and cannot replace the server-side
ledger or PEP.

## Readback compatibility invariants

- SSO Admin and IAM inventory use the AWS CLI paginator contract, not raw
  service request fields. Each bounded request supplies `--max-items` and,
  when the service operation exposes a page-size member, an equal
  `--page-size`; `list-tags-for-resource` explicitly omits unsupported
  `--page-size`. Every operation resumes only through `--starting-token`,
  consumes only `NextToken`, and rejects token replay or a truncated IAM
  response that lacks the CLI continuation token.
- No inventory helper may combine `--no-paginate` with a manual continuation,
  pass `--next-token`, or expose a raw IAM `Marker` as a CLI option.
- The operational `$LATEST` description and immutable version description are
  separately exact for Plan, repair and reconcile. CloudFormation and runtime
  tests bind all six values.
- `PLAN_VERIFIED` is valid only as
  `PLAN_STATE_VERIFIED` with zero effects, matching planned/current state,
  no claim timestamps and one durable ledger digest. Its public receipt must
  use `PROVEN_BY_DURABLE_LEDGER` and require `INVOKE_REPAIR_ALIAS`.
- The semantic validator reconstructs the immutable initial Plan binding from
  every ledger state and recomputes its raw lowercase SHA-256. CAS transition
  fields remain governed by the exact status/stage/counter matrix; modified
  binding data is rejected offline before it can be cited as evidence.
- A null-ledger, `UNPROVEN` or terminal `NONE` Plan receipt is legacy-invalid
  and cannot cross the schema/evidence boundary.

## Portability contract

For a new customer or authority installation, generate a new immutable binding
and deploy separate stacks under reviewed account/Region inputs. Never copy
principal IDs, permission-set ARNs, SAML providers, KMS keys, policy digests,
repair IDs or ledger records from another installation. The semantic role
names and fail-closed invariants are reusable; live identifiers are not.

## Evidence boundary

| Class | Meaning |
|---|---|
| **Implemented** | Artifacts exist on one exact repository commit |
| **Locally validated** | Named tests/checks passed for that commit |
| **CI validated** | Required GitHub checks passed for that commit |
| **Live validated** | Both stacks, aliases, durable Plan/repair state, invocation graph and final SSO/IAM state were independently read back in AWS |

No live validation or AWS mutation is part of this documentation update.
Independent approval is also not satisfied while one person holds all
operational sessions. Candidate A and Candidate B remain blocked until an exact
`RECONCILE_VERIFIED` receipt and a dedicated collector SSO session are both
independently evidenced. Production remains **NO-GO**.

## References

- [ADR-047](../../ADR/ADR-047-lambda-audit-provisioning-repair.md)
- [Operations runbook](../operations/platform-authority-lambda-audit-provisioning-repair.md)
- [Threat-model delta](../security/gug-221-lambda-audit-provisioning-repair-threat-model-delta.md)
- [AWS Lambda code signing workflow](https://docs.aws.amazon.com/lambda/latest/dg/governance-code-signing.html)
- [AWS Lambda signature validation](https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html)
- [AWS Signer signing jobs for Lambda](https://docs.aws.amazon.com/signer/latest/developerguide/signing-jobs-lambda.html)
- [AWS Signer `DescribeSigningJob`](https://docs.aws.amazon.com/signer/latest/api/API_DescribeSigningJob.html)
