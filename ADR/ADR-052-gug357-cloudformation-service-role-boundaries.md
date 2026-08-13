# ADR-052: Bounded CloudFormation Service Role for the GUG-357 Entrypoint

- **Status:** Proposed repository contract; not deployed
- **Date:** 2026-08-12
- **Implementation issue:** GUG-365
- **Blocked live issue:** GUG-357
- **Amends:** ADR-051 service-role prerequisite and raw-client residual risk
- **AWS live validation:** None
- **Production:** **NO-GO**

## Context

ADR-051 fixes one pre-existing CloudFormation service role for the direct,
one-attempt creation of the dedicated GUG-357 retirement entrypoint stack. A
fresh read-only GUG-357 preflight proved that the role does not exist. It also
exposed a structural flaw in the original prerequisite: allowing the GUG-363
stack to create five IAM roles would require dangerous `iam:CreateRole` and
policy-document mutation authority in its permanent service role.

Restricting those actions to exact role ARNs does not restrict the trust or
inline-policy documents supplied to IAM. A caller that can bypass the reviewed
wrapper and submit a different template could otherwise give one of the five
roles broader authority. The service role is also retained on the stack and can
be reused by a principal that later receives stack-operation authority. A
fresh digest and operational wrapper are important evidence controls, but they
are not a server-side policy-content boundary.

Therefore an explicitly reviewed absence of permissions boundaries is not an
acceptable GUG-365 outcome. The current unbounded template is **NO-GO** for
live materialization.

## Decision

### 1. Materialize one closed IAM prerequisite bundle

GUG-365 owns a create-only bundle containing:

1. one managed permissions boundary for the fixed CloudFormation service role;
2. one managed boundary for the broker execution role;
3. one managed boundary for the classifier invoker;
4. one managed boundary for the approver invoker;
5. one deny-all boundary shared by both proof roles;
6. one policy/boundary for a dedicated one-shot ledger factory;
7. the fixed CloudFormation service role with CloudFormation-only trust;
8. the broker, two invoker, two proof and dedicated factory roles;
9. the exact signed broker function, initially inert with an empty environment;
10. a separately packaged and signed immutable ledger-factory function; and
11. the retained, deletion-protected DynamoDB ledger created atomically by
    that factory with its exact resource policy.

The managed policies use path `/scanalyze/platform-authority/`. Each persistent
effect-capable role has zero inline policies and uses its exact managed policy
both as boundary and only attached identity policy. The factory role is
temporarily activated with its exact policy, then returned to the explicit
deny-all proof boundary and detached before the main roles can activate. The
GUG-363 template references fixed role ARNs and the fixed ledger name; it
creates neither IAM nor DynamoDB resources.

No boundary is attached to a human or Identity Center role. GUG-365 does not
create the GUG-357 operator permission set or its `iam:PassRole` grant.

### 2. Compile from the exact GUG-363 plan

The GUG-365 plan accepts only a validated GUG-363 plan plus a separately
supplied expected plan digest. It has no free-form AWS resource overrides.
The compiler binds:

- exact GUG-363 source commit, tree and template digest plus the stable
  pre-function binding that excludes ephemeral authorization values;
- fixed account, `us-east-1`, dedicated stack and service-role identity;
- the exact fourteen-resource graph;
- only the signed S3 destination bucket, key and version;
- the exact KMS key and Code Signing Config from that signed destination; and
- every rendered trust, boundary, service-role policy and ordered operation
  digest; and
- the dedicated factory package manifest, signed object version, code digest,
  signer evidence and enforcing Code Signing Config.

The unsigned Signer source never appears in an effect-capable service-role
statement. The GUG-365 plan states `deployment_authorized=false`; its digest is
integrity evidence only.

### 3. Precreate roles, ledger and inert broker outside CloudFormation

GUG-365 materializes the service role, broker, two invokers, two proof roles,
a dedicated factory role and both exact signed functions as a closed
prerequisite bundle. Inline policies are forbidden. The factory role is
proof-bound and empty until a separate activator attaches its exact policy and
makes that policy its boundary. A different, invoke-only session calls one
immutable qualified version synchronously with event `{}`. The signed runtime
contains the table name, schema, tags and deny-writes-outside-broker policy;
it submits them together in its sole `CreateTable` call, waits read-only for
`ACTIVE`, enables exact 35-day PITR once, and emits a sanitized receipt. A
third session moves the role back to proof first and detaches its policy
second. Only a causal `CREATED` or `CREATED_RECONCILED` receipt with one create
and one PITR call can unlock main activation; `ALREADY_EXACT` is no-touch and
requires owner recovery.

The GUG-363 stack references fixed role ARNs and the fixed ledger name. It
contains no `AWS::IAM::*`, `AWS::DynamoDB::*` or `AWS::Lambda::Function`,
requires no IAM capability acknowledgement and cannot mutate IAM, the ledger
policy or the function configuration.

### 4. Keep provisioning phases and stack execution disjoint

GUG-365 divides future provisioning among `POLICY_FACTORY`,
`FOUNDATION_FACTORY`, the main `FUNCTION_FACTORY`, a separate
`LEDGER_FACTORY_FUNCTION_FACTORY`, three disjoint ledger-factory
activate/invoke/revoke sessions and the main `ACTIVATOR`; GUG-357 owns a fresh
`FUNCTION_CONFIGURATOR` between inert-function certification and activation.
Each phase has a separate exact policy,
checkpoint and session; authority overlap and same-session reuse are forbidden.
The exact phase document must also be the session's sole identity grant and its
identical maximum-permissions boundary/session cap; using it as an additive
policy on a broader profile is forbidden and fails before any mutation.
The phases create six policies, create all seven roles initially under the
proof boundary, create the two exact signed functions in separate sessions,
materialize/certify the ledger through the immutable factory, revoke the factory, and finally
attach/swap only the plan-bound main policies and boundaries. The human
foundation authority has no DynamoDB action. None has a
CloudFormation action, `sts:AssumeRole`, broker invocation, update, repair or
delete authority; each function-factory session has only its one exact
proof-bound role PassRole edge required by its one `CreateFunction` call.

The future GUG-357 executor may perform the separately reviewed dedicated
`CreateStack` request and pass only the fixed service role to CloudFormation.
It has no direct IAM provider writes. A profile used for GUG-206 Plan duties or
generic administration is ineligible for either lane.

`lambda:PublishVersion` and `lambda:CreateAlias` require the unqualified
function ARN and have no request condition that binds a version number or
alias name. They are therefore not represented as a server-side exact-name
guarantee. They are accepted only for the bounded single-operator
non-production create window: the GUG-357 operator can issue only the one
reviewed `CreateStack`, final inventory must contain exactly the reviewed
version and aliases, and a separately authorized GUG-365 revocation must move
the retained service role back to the explicit deny-all proof boundary before
live certification can complete. Any extra version or alias is drift and
blocks completion.

### 5. Make the live path create-only and fail closed

Before any AWS mutation, the exact repository change must be reviewed, merged,
green at the exact head, and revalidated on current `main`. A new owner
checkpoint must bind the exact non-production account, Region, short-lived
profile/caller, plan and policy digests, ordered operations, expiry and
reconcile-only recovery.

The planned order is the managed-policy phase, the foundation phase (seven role
creates under the initial deny-all proof boundary), separate creation and
certification of each signed function, factory-only activation, one synchronous immutable
factory invocation, factory contraction (proof boundary first, detach second),
fresh broker configuration, and finally main activation with exact attachments
and boundary swaps. Main activation is temporary for the reviewed GUG-357
stack-create window. After a conclusive create and exact provider inventory,
the forward-disabled revocator must return the retained service role to proof;
an ambiguous stack outcome enters read-only reconciliation before any
revocation decision.
Final state has zero inline policies. Each operation has an attempt limit of
one and SDK retries are disabled. A durable/private attempt ledger is consumed
for each authorized phase. Authorization is revalidated before every later
write, and a new checkpoint/session is required between phases.

The durable ledger is create-only and roots the exact plan, bundle, executor,
host and ordered request sequence. Its runner is an injected-callback
enforcement library, not an AWS adapter and not a source of live authority. A
CAS transition records the next exact operation before the callback; a second
transition records its single result and receipt before progress. A restart or
unknown callback result cannot repeat the write and is restricted to read-only
reconciliation. Classifiers require the independently supplied initial-root
and terminal-receipt bindings, so a resealed replay or naked digest equality
cannot prove causal execution.

An existing exact table reported by a fresh factory invocation is no-touch and
is not eligible to unlock activation without the exact causal ledger from the
original creation attempt. Any other existing exact bundle is also no-touch.
Any partial or drifted bundle is
`DRIFT_BLOCKED_NO_REPAIR`. A timeout or malformed response after an attempted
write is `UNCERTAIN_RECONCILE_ONLY`; the materializer never retries, repairs,
deletes or rolls back IAM state.

Before any revocation write, and again after all four writes, the revocator
must prove the shared proof policy still has default version `v1`, only version
`v1`, and the exact explicit deny-all document digest. Otherwise it performs no
boundary change.

## Rejected alternatives

- **No workload boundary.** Rejected because `CreatePolicy` cannot enforce a
  repository document digest server-side and a later identity-policy change
  would otherwise be an unbounded privilege-escalation path. The separated
  policy factory, deny-all foundation, activator and forward-disabled
  revocator keep those authorities disjoint and make final drift observable.
- **One union workload boundary.** Rejected because every child role would gain
  the maximum authority of every other child role.
- **A boundary on only the service role.** Rejected because permissions
  boundaries do not propagate to roles the principal creates.
- **Generic administrator provisioning.** Rejected because it is not
  issue-scoped, least privilege or separable from unrelated authority.
- **CloudFormation creating its own service role.** Rejected as circular.
- **Automatic cleanup after a partial create.** Rejected because delete/repair
  would widen authority and could destroy causal evidence.

## Consequences

- GUG-365 has a larger, explicit prerequisite bundle than the originally
  described role-only lifecycle.
- The GUG-363 template digest changes and a new GUG-363 plan must be built from
  the reviewed merged tree. Historical plans remain evidence only.
- GUG-357 remains blocked until the whole bundle is live-certified and then
  freshly re-read inside its own checkpoint.
- Repository tests and policy review do not prove AWS condition-key behavior;
  exact policy simulation and live readback remain mandatory before use.
- No change in this ADR authorizes GUG-357 `CreateStack`, broker invocation,
  GUG-215 `DeleteChangeSet`, GUG-206 execution, production, or destructive
  cleanup.

## Evidence classification

- Repository source and tests: `REPOSITORY_VALIDATED_NO_LIVE_EXECUTION` only.
- Current live role state: `LIVE_READ_ONLY_VERIFIED_ABSENT`.
- GUG-365 IAM materialization: `NOT_AUTHORIZED` until a fresh exact checkpoint.
- GUG-357 and GUG-215 effects: `BLOCKED`.
- Production: **NO-GO**.

## References

- [ADR-051](ADR-051-direct-retirement-entrypoint-materialization.md)
- [GUG-365 deployment contract](../docs/deployment/platform-authority-retirement-entrypoint-service-role.md)
- [GUG-365 operations runbook](../docs/operations/platform-authority-retirement-entrypoint-service-role.md)
- [GUG-365 threat model](../docs/security/gug365-retirement-entrypoint-service-role-threat-model.md)
- [AWS CloudFormation service roles](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html)
- [AWS IAM permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
