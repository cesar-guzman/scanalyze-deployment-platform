# GUG-365 threat model: bounded retirement-entrypoint service role

## Scope and objective

This model covers the repository contract for creating the fixed GUG-363
CloudFormation service role, five workload roles, dedicated factory role,
retained ledger, two inert signed functions and managed
permissions boundaries that cap them outside the GUG-363 stack. It covers deterministic
offline compilation, separated policy/foundation/function/factory/activation
authority, one-attempt IAM and broker-enforced DynamoDB prerequisite writes,
exact readback and
reconcile-only recovery.

It excludes GUG-357 `CreateStack`, the operator `iam:PassRole` grant, broker
invocation, GUG-215 `DeleteChangeSet`, GUG-206, updates, deletes, repairs,
customer data and production.

The security objective is to prevent an alternate CloudFormation template or a
broadened identity policy from granting authority beyond the reviewed GUG-357
graph, while retaining a narrowly reviewable create-only bootstrap path.

## Principal attack path

If workload roles were created by CloudFormation, an operator with the exact
`CreateStack` and `PassRole` edge could bypass the wrapper and submit another
role-policy document. The final design eliminates that path: GUG-363 cannot
create or mutate IAM roles or the retained ledger.

The controls are:

1. role/class-specific boundaries on every precreated workload role;
2. zero IAM and DynamoDB resources in the GUG-363 stack;
3. a separate service-role boundary that caps the provider allowlist;
4. no IAM, DynamoDB policy, update or delete actions in the service role or
   human Foundation authority;
5. non-overlapping policy, foundation, inert-function, factory activate/invoke/
   revoke, fresh-configuration, main activation and forward-disabled
   revocation authorities;
6. an independently packaged/signed immutable factory with event `{}` and the
   table schema/resource policy compiled into source;
7. explicit proof-policy deny-all plus a causal factory receipt and consistent
   empty-ledger `Scan` gate;
8. no CloudFormation action in any GUG-365 authority and only one exact
   proof-bound role PassRole edge in each of the two disjoint function-factory
   authorities;
9. a fresh, short-lived, digest-bound owner checkpoint and consumed ledger; and
10. exact provider readback before the bundle can be handed to GUG-357.

## Threats and failure behavior

| Threat | Control | Failure behavior |
|---|---|---|
| Plan or GUG-363 source is replaced | Validate the GUG-363 plan and an independently supplied expected digest; bind source commit/tree/template | Fail before AWS client construction |
| Unsigned object enters provider policy | Compiler projects only `signed_destination`; closed S3 version and KMS bindings | Plan validation failure |
| Human or Lambda assumes the service role | Trust has one CloudFormation service principal and one `sts:AssumeRole` action | Readback drift; no certification |
| Alternate template attempts to create or mutate a role, table or broker configuration | The stack service role has no IAM, DynamoDB, PassRole, CreateFunction, UpdateFunctionCode, UpdateFunctionConfiguration, S3 or KMS authority; all prerequisites are precreated | AWS deny for those surfaces; structural regression tests must pass |
| Alternate template publishes an extra version or creates an extra alias during the bounded stack-create window | Lambda does not expose condition keys that bind `PublishVersion` to one version number or `CreateAlias` to one alias name. The operator has only the exact one-attempt stack create, URLs and permissions remain scoped to the three reviewed alias ARNs, and the separately authorized revocator returns the service role to the explicit deny-all proof boundary immediately after conclusive certification | Treat any extra version/alias as drift; no completion before proof-bound revocation and exact final inventory |
| Human Foundation session installs an attacker-chosen resource policy | Foundation has zero DynamoDB permissions; only the reviewed signed factory code holds its exact table authority | AWS deny; plan validation failure if any human DDB action returns |
| Factory package is replaced or the GUG-215 broker ZIP is reused | Dedicated manifest/source-set/archive/CodeSha/signed-version/CSC bindings and isolated ZIP handler-import test | Stop before Function Factory |
| Factory is invoked asynchronously, twice or with attacker input | Operation contract fixes qualified version, `RequestResponse`, payload `{}`, retries zero and consumes the attempt ledger first; runtime rejects any non-empty event | Ambiguous call revokes first and enters read-only reconcile; no reinvocation |
| A pre-existing exact table is adopted through the factory | `ALREADY_EXACT` is no-touch and never satisfies the causal `CREATED|CREATED_RECONCILED` activation checkpoint | Owner recovery required; main roles stay proof-bound |
| Factory role remains active | Dedicated revoker changes boundary to proof first, detaches second, expires the invoker and performs stable readback | Main activator remains blocked |
| Function factory bakes a stale single-operator window | Function is precreated inert with an empty environment; GUG-357 replaces the entire map atomically under a fresh checkpoint and observed RevisionId | No activation or CreateStack before post-expiry exact evidence |
| A later identity policy is attached to a workload role | The exact role/class-specific permissions boundary remains the maximum authority | Extra attachment is readback drift; boundary still caps effective actions |
| Boundary is swapped between roles | Exact role-to-boundary mapping and `CreateRole` conditions | Plan/readback failure |
| One union boundary exposes broker authority | Separate broker/classifier/approver/proof policies | Policy contract failure |
| Human assumes a tampered broker role | Broker effect permissions require the exact Lambda source function | AWS deny; live simulation required |
| GUG-365 executor pivots to deployment | Every executor has no CloudFormation, AssumeRole or broker invoke; each disjoint function factory has only its one exact proof-bound PassRole | AWS deny and authorization failure |
| One provisioning session accumulates create and activation authority | Each phase document is the sole identity grant and identical maximum-permissions cap; complete inventory, fresh unchained session, no overlap/reuse | `STOP_NO_MUTATION` before the first write |
| Foundation-created roles become effective before review | Every role is created under the explicit deny-all proof boundary; activation is separate and service role activates last | IAM deny until the activation checkpoint completes |
| Retained ledger contains pre-existing rows | Signed factory requires a consistent count-only `Scan` returning zero before and after certification | Activation blocked; preserve for recovery |
| Incident operator uses revocation to resume or broaden state | Revocator can only set four roles back to proof and verifies proof default `v1`, only `v1`, and exact deny-all digest before and after | Proof drift is `STOP_NO_REVOCATION`; new forward checkpoint required |
| PITR update races asynchronous table creation | The signed factory uses a bounded read-only waiter requiring exact `ACTIVE` between the atomic table/policy create and single PITR write | Timeout is reconcile-only; factory is revoked and never reinvoked |
| Generic admin profile is substituted | Exact short-lived profile/caller and policy evidence are checkpoint-bound | Stop before ledger claim |
| Existing partial bundle is adopted or repaired | Two stable read snapshots; closed no-touch/drift classifications | `DRIFT_BLOCKED_NO_REPAIR` |
| A write response is lost | Ledger consumed before write; one attempt; SDK retries disabled | `UNCERTAIN_RECONCILE_ONLY` |
| Later operation runs after authorization expiry | Revalidate authorization before every ordered write | Stop with partial state preserved |
| Managed policy exceeds IAM size limit | Canonical rendered document size gate | Offline failure |
| Passing tests is reported as live completion | Separate repository, authorization, API and readback evidence classes | Live remains `NOT_PROVEN` |

## Mandatory negative tests

- wrong account, Region, plan digest, source tree, role or boundary name;
- either unsigned S3 source, unversioned object, reused broker artifact or
  mismatched factory package/KMS/CSC binding;
- service-role trust containing a human, federated, Lambda or wildcard
  principal/action;
- missing, swapped or union child boundary;
- `Action: "*"`, `Resource: "*"`, unrelated IAM mutation, S3 write, Signer,
  SSO, CloudFormation, update or delete in a rendered allow statement;
- any IAM or DynamoDB resource in the GUG-363 template;
- invocation boundary permitting another qualifier, public Function URL or
  foreign principal;
- human-session broker effect without the exact Lambda source function;
- pre-existing exact, partial and drifted snapshots;
- access denied or timeout misclassified as absence;
- authorization expiry, replay, host mismatch and consumed ledger;
- additive executor grants, missing identical cap, group grants, role chaining,
  proof-policy drift, or revocation without pre/post proof verification;
- ambiguous CreatePolicy/CreateRole/CreateFunction/qualified factory invoke/
  CreateTable/AttachRolePolicy or
  boundary-swap responses; phase-authority overlap or same-session reuse; and
- any automatic retry, repair, deletion or rollback path.

## Residual risks

- IAM policy simulation and static review do not replace live provider
  readback; service-specific condition keys must be proved before use.
- Direct IAM create APIs cannot enforce a policy-document digest server-side.
  The short-lived executor, exact target ARNs, ledger and readback are the
  bootstrap governance boundary.
- A role or managed policy can drift after certification; GUG-357 must collect
  a fresh stable snapshot immediately before its own checkpoint.
- Managed-policy and role creation can be eventually consistent.
- A partial create may leave non-effect-capable IAM artifacts requiring a new,
  explicitly destructive recovery lane.
- IAM cannot condition `lambda:InvokeFunction` on `RequestResponse` or payload
  `{}`. The reviewed runner, one consumed call ledger, immutable version,
  proof-first revocation and never-reinvoke rule are the accepted non-production
  boundary; stronger at-most-once semantics would require a pre-existing
  server-side lock/broker.
- IAM cannot condition `lambda:PublishVersion` on a version number or
  `lambda:CreateAlias` on an alias name. Those provider actions therefore
  remain a bounded single-operator/non-production residual during the exact
  stack-create window. Completion requires exact version/alias inventory and
  immediate proof-bound service-role revocation; the claim that every
  alternate-template Lambda mutation is server-side denied is intentionally
  not made.

None of these residuals is accepted for production.
