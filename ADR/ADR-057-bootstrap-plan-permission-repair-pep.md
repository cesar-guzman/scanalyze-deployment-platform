# ADR-057: Bootstrap Plan Permission Repair PEP

- **Status:** Proposed repository implementation; deployment not executed
- **Date:** 2026-08-30
- **Implementation issue:** GUG-376
- **AWS live validation:** Bounded read-only inventory only; repair not executed
- **AWS mutations:** None
- **Production:** **NO-GO**

## Context

The normal `ScanalyzeAuthorityBootstrapPlan` permission set is expected to
render the canonical policy in
`policies/iam/platform-authority-bootstrap-plan-role.json`. Live read-only
evidence showed a narrower predecessor: it differs from that canonical policy
only by the absence of the isolated
`ListOnlyExactBootstrapChangeSets` statement. The missing
`cloudformation:ListChangeSets` authority blocks the normal GUG-214 recovery
preflight.

Granting `sso:PutInlinePolicyToPermissionSet` directly to a human or to the
broken Plan role would create a circular and arbitrarily broad IAM update
surface. Reusing the GUG-221 PEP would also be invalid: its ledger, functions,
roles and policy are bound to the separate
`ScanalyzeAuthorityLambdaAudit` collector repair.

## Decision

### 0. Require the closed GUG-376 artifact foundation

The PEP package, template and signed-artifact attestor accept only the exact
GUG-376 artifact foundation defined by ADR-058. Before the temporary artifact
bootstrap assignment is removed, every producer must validate the same sealed
`artifact_foundation_publish_binding`: clean merged source, terminal foundation
and access-update readbacks, exact route/delegation S3 versions, KMS key,
Signer profile version and Lambda code-signing configuration. Product CLIs do
not auto-discover or fall back to GUG-363/GUG-365 storage.

The bootstrap principal ID, Signer profile version, and exact route and
delegation object-version IDs are causal identifiers, not secrets. Their
CloudFormation parameters therefore are not `NoEcho`. Both Change Set
attestation and terminal stack readback require one unique parameter key and
the exact sealed value; masked, missing, duplicated or substituted values fail
closed and cannot prove this foundation.

The normal route cannot be opened merely because that publication binding
exists. It additionally requires the post-revocation
`artifact_bootstrap_route_release`, which proves zero bridge assignments,
expiry of the `PT1H` credential boundary and the complete template,
signed-artifact and broker-seed receipt set. This keeps the PEP deployment
causally downstream of the closed publication authority without making the
publication process circular.

### 1. Repair only one exact predecessor

The Plan function renders the desired document from reviewed source using
`BootstrapBinding` and `render_bootstrap_iam_policy()`. It derives the sole
eligible predecessor by removing exactly this statement:

```text
Sid      = ListOnlyExactBootstrapChangeSets
Action   = cloudformation:ListChangeSets
Resource = arn:aws:cloudformation:us-east-1:042360977644:
           stack/scanalyze-platform-authority-state-backend/*
```

The live document must canonically equal that predecessor. A different Change
Set name, a second missing or additional statement, changed permission-set
metadata, attachment, boundary, assignment, provisioned account or generated
IAM role is `BLOCKED_PREDECESSOR_DRIFT`. The repair does not normalize or adopt
any other state.

### 2. Separate human invocation from SSO mutation

The management-account delegation stack creates an invoke-only
`ScanalyzeBootstrapPlanRepair` permission set. It can invoke only the exact
qualified `plan-v1`, `repair-v1` and `reconcile-v1` aliases in the authority
account. It has no Identity Center, Identity Store, IAM, STS role-assumption or
DynamoDB write authority.

Its temporary `USER` assignment is governed by the required, no-default
`RepairInvokerAssignmentEnabled` parameter. The initial reviewed Change Set
must set it to `true`. A later update of the same stack with the same reviewed
template bytes and every other parameter unchanged sets it to `false`, causing
CloudFormation to remove only `RepairInvokerAssignment` while retaining the
permission set and both cross-account service roles.

The authority-account PEP stack contains separate versioned Plan, repair and
reconcile functions, disjoint execution roles, an invocation-authority
inspector, a KMS-encrypted retained ledger, code-signing enforcement and exact
alias-level asynchronous settings. No function URL, public permission, event
source, destination or automatic retry is allowed. Every invocation event is
exactly `{}`; deployment configuration and signed source supply all authority
bindings.

The management mutation role is assumable only by the exact authority repair
execution role. Its only writes are:

```text
sso:PutInlinePolicyToPermissionSet
sso:ProvisionPermissionSet
```

The separately trusted readback role has no mutations. Neither role trusts a
human SSO principal, a wildcard principal or another service role.

### 3. Enforce two ordered, at-most-once effects

The durable sequence is:

1. Plan observes the full state and creates `PLAN_VERIFIED` with a conditional
   `PutItem`.
2. Repair consumes that record with compare-and-swap.
3. Repair records an attempting state before
   `PutInlinePolicyToPermissionSet`, dispatches exactly once with SDK retries
   disabled, then performs exact readback.
4. Repair records the second attempting state before
   `ProvisionPermissionSet`, dispatches exactly once, polls within the reviewed
   budget and performs full Identity Center and generated-role readback.
5. Only exact convergence can produce `REPAIR_VERIFIED`.

A timeout, lost response, provider exception after dispatch, ledger commit
failure or indeterminate readback produces `UNCERTAIN_RECONCILE_ONLY` only when
that terminal state is durably sealed and read back. If its CAS cannot be
proven, no public receipt is emitted, `UNCERTAINTY_LEDGER_UNPROVEN` is returned
and replay remains blocked by the attempting state. Repair never resumes from
uncertainty. Reconcile is provider-read-only. Only an original, terminal
`REPAIR_VERIFIED` ledger with exact final state can create one append-only
`#reconcile-v1` attestation; uncertain ledgers cannot create that closeout
proof.

### 4. Preserve immutable source and evidence bindings

The private intent and ledger bind the reviewed source commit and bundle,
template bytes, exact predecessor and target policy digests, Change Set name,
instance/store, permission set, assignment, provisioned accounts, generated
role, invocation graph, versions/aliases, accounts, Region, repair ID and a
window of at most fifteen minutes.

An offline materializer derives `ImmutableConfigurationDigest` from the closed
operator-controlled runtime projection. The digest is recomputed by each
handler before SDK use and participates in all three Lambda Version
descriptions, so configuration-only stack updates publish new versions instead
of leaving aliases on stale environments. Explicit `FunctionUpdate` runtime
management is established before version publication and read back at runtime.
The template and runtime also enforce the 4,096-byte UTF-8 environment limit.

Public receipts contain only canonical digests, counters and classification.
They do not contain an account ID, ARN, principal, Change Set name, request ID,
policy document, profile or private path. They always state
`retry_permitted=false` and `production_status=NO-GO` until a separate
certification promotes a completed live result.

### 5. Keep bootstrap authority external and explicit

This repository cannot manufacture the authority needed to deploy its own
repair PEP. The existing Plan role is too narrow, read-only roles cannot
deploy, and the founder PEP roles are resource- and work-package-bound to their
own control plane.

Deployment therefore uses the separately reviewed temporary route in ADR-058.
One explicit management-account administrator seed creates time-bound Identity
Center Creator and Executor assignments. The broad session ends before either
target Change Set is created. Creator cannot execute, each Executor is bound to
one account and exact Change Sets, provider actions require CloudFormation
forward access, and the target Change Sets carry no persistent `RoleARN`.
Broad administrator access is never the delegation, PEP or repair executor.

### 6. Bind provider ports only inside the reviewed artifact

The checked-in runtime defines the typed Identity Center and durable-ledger
ports plus the complete two-effect state machine. A separate AWS wrapper
installs concrete zero-retry adapters only in the deterministic, source-closed
Lambda package. The three Lambda handlers validate the exact empty event,
published version, qualified alias, immutable environment and mode-specific
entry budget.
Plan and reconcile require more than 60,000 milliseconds remaining; repair
requires more than 480,000 milliseconds before it may consume the durable Plan.
The immutable intent window independently requires at least 660 seconds before
repair can claim the Plan and more than 75 seconds immediately before either
write.
The wrapper validates the runtime lock and exact managed-SDK versions before
the first SDK client, then proves local/assumed identities, all six effective
IAM roles, published Lambda controls, invocation graph, DynamoDB/KMS controls
and complete Identity Center state. It preserves zero SDK retries, bounded
pagination/polling, phase-specific service roles, source/artifact bindings and
provider-read-only reconcile. It requires more than 75,000 milliseconds
immediately before either mutation and more than 60,000 milliseconds before every provider
read or provisioning poll, leaving time to seal uncertainty. Reconcile has no
Identity Center, IAM or Lambda mutation authority. Its only write is a
conditional DynamoDB `PutItem` to the exact suffixed attestation key, followed
by strongly consistent readback; the table policy binds Plan and reconcile to
their disjoint keys.

The package and signed-artifact tools bind exact Git-object bytes, the runtime
lock, handlers, source-set digest, ZIP digest, S3 versions, Signer job and
CloudFormation parameters. They do not upload, sign, deploy or invoke. Those
remain separately authorized operations after merge.

## Consequences

- The repository can review and test the complete least-privilege repair
  control plane without granting a human raw SSO mutation authority.
- The normal Plan policy remains a single source-rendered document; no second
  desired-policy copy is introduced.
- The temporary bootstrap route is separately revocable and leaves no
  CloudFormation service role attached to either target stack.
- GUG-221, GUG-215 and GUG-274 keep their existing identities and effects.
- A repository implementation or green CI does not prove deployment, repair,
  staging certification or production readiness.
- Production remains **NO-GO** until both stacks are deployed/read back through
  an approved bootstrap route, the exact repair converges, GUG-214 succeeds
  under a fresh Plan session, and the remaining production gates close.

## Rollback and recovery

Before deployment, rollback is a Git revert.

After deployment but before repair, revoke the temporary human assignment with
the exact management-stack update defined above and verify that its Change Set
removes only `RepairInvokerAssignment`. Read back the parameter/output as
`false`, zero temporary assignments and no pending deletion while retaining the
permission set, service roles, ledger, keys, versions and logs for evidence.
After either SSO effect is dispatched, do not repeat it from local tooling or
delete the ledger. Invoke the provider-read-only reconcile alias, preserve
CloudTrail/provider evidence and obtain a new reviewed recovery decision.

The desired final policy is not rolled back merely to recreate the known-bad
predecessor. A policy rollback is a separate reviewed Identity Center change.

```text
REPOSITORY_EXECUTABLE_CONTROL_PLANE=IMPLEMENTED_FOR_REVIEW
RUNTIME_PORTS=BOUND_IN_SOURCE_CLOSED_PACKAGE
SIGNED_ARTIFACT=NOT_BUILT
AWS_CALLS=9
AWS_MUTATIONS=0
DEPLOYMENT=NOT_EXECUTED
REPAIR=NOT_EXECUTED
PRODUCTION=NO-GO
```

## References

- [ADR-034](ADR-034-dedicated-platform-authority-account-bootstrap.md)
- [ADR-041](ADR-041-retained-change-set-retirement.md)
- [ADR-047](ADR-047-lambda-audit-provisioning-repair.md)
- [ADR-058](ADR-058-gug376-temporary-changeset-route.md)
- [Deployment contract](../docs/deployment/platform-authority-bootstrap-plan-permission-repair.md)
- [Operations runbook](../docs/operations/platform-authority-bootstrap-plan-permission-repair.md)
