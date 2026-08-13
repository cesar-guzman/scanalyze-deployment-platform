# GUG-357 temporary Identity Center audit permission set

## Status and boundary

This package is **repository-only preparation** for a temporary, strictly
read-only IAM Identity Center audit permission set. It does not create a
permission set, assign a principal, provision a role, call AWS, invoke the
retirement broker, deploy CloudFormation, or authorize production.

The proposed contract is:

| Field | Exact value |
| --- | --- |
| Permission set | `ScanalyzeGug357IdentityAudit` |
| Assignment account | repository-defined management account, digest-bound in public evidence |
| Principal | exactly one direct `USER` auditor, distinct from both runtime users; never a `GROUP` |
| Allowed operator set | exactly that auditor, represented publicly by an immutable set digest |
| Region | `us-east-1` |
| Session duration | `PT1H` |
| Preparation-intent lifetime | 15 minutes |
| Absolute policy lifetime | at most 4 hours from exact `audit_not_before` |
| Environment | management control plane only |
| Production | `NO-GO` |

The auditor does not become, and must not be counted as, either GUG-357 human
`APPROVER` or GUG-357 human `EXECUTOR`. Those two duties, their immutable user
bindings, and their attestations remain `NOT_DEFINED` / `NOT_PROVEN`.

## Package contents

- `policies/iam/platform-authority-gug357-identity-center-audit-role.json`
  is a placeholder template rendered only from exact private identifiers.
- `tooling/platform_authority_gug357_identity_center_audit.py` is a pure
  renderer and validator. It has no AWS, network, process, create, assign,
  provision, or revoke capability.
- `schemas/platform-authority-gug357-identity-center-audit-intent.v1.schema.json`
  defines the sanitized digest-only preparation intent.
- `tests/test_deployment/test_gug357_identity_center_audit_permission_set.py`
  proves action equality, scoping, expiry, sanitization, and negative cases.

No CloudFormation or Terraform materializer for this audit permission set is
included. Adding one would be a separate provider and mutation decision, not a
continuation of this offline preparation authorization. GUG-363 adds a separate
materializer for the ADR-050/GUG-215 retirement PEP entrypoint; it does not
create, assign, provision or revoke `ScanalyzeGug357IdentityAudit`.

## Private bindings required before review

The renderer fails closed until an authorized private evidence root supplies
all of the following exact values:

- organization IAM Identity Center instance ARN in the management account;
- exact management-account and authority-account IDs, verified against the
  repository-defined public digests;
- Identity Store ARN;
- exact GUG-217 identity-context application ARN;
- exact permission set ARNs for `ScanalyzeAuthorityRetireClass` and
  `ScanalyzeAuthorityRetireApprove`;
- exact, distinct Identity Store user ARNs assigned to those runtime duties;
- exact immutable UserId for the single temporary auditor;
- exact reviewed `main` commit and absolute UTC `audit_not_before` /
  `audit_not_after` timestamps.

Raw account identifiers, ARNs, UserIds, emails, AWS responses, profiles,
session data, and rendered policies remain private. Linear, PR descriptions,
CI summaries, and other public artifacts may carry only the sanitized intent,
immutable SHA-256 digests, classifications, and counts.

The intent's `intent_digest` is a deterministic integrity checksum, not a
signature or authenticity proof. A future live gate must receive the exact
expected digest through a separate owner authorization (or a separately
reviewed signed envelope) and must verify the reviewed commit against Git; the
intent cannot authorize itself by recomputing its own checksum.

## Effective read authority

The policy allows only:

- `sts:GetCallerIdentity` for caller confirmation;
- exact-instance and exact-permission-set IAM Identity Center reads;
- exact authority-account assignment and provisioning-status reads;
- exact application configuration, assignment, authentication-method, grant,
  and access-scope reads;
- `DescribeUser` for the two exact runtime users; alternate-identifier lookup
  with `GetUserId` is deliberately excluded;

No KMS action is authorized. If a customer-managed encryption key causes an
access denial, the audit stops; decrypt authority requires a separate owner
decision and separately reviewed package.

The only wildcard resources are `sts:GetCallerIdentity` and
`sso:ListInstances`, because those APIs do not support narrower resource
scoping. `ListAccountsForProvisionedPermissionSet` can enumerate every account
where either of the two exact runtime permission sets is provisioned; that
bounded cross-account result is required to prove there is no foreign
provisioning and must remain private. Every allow has the same absolute start
and expiry. Explicit denies
reject all actions before the start, reject identity reads outside `us-east-1`,
and reject all actions at expiry. The closed-session deny exempts only a fixed
set of legacy authorization aliases needed to avoid AWS dual-authorization
conflicts on older instances. Those aliases are not granted by any `Allow`;
live readback must prove that no other identity policy grants them. No managed
policy, customer managed policy reference, permissions boundary, relay state,
group assignment, or role chaining is part of the permission set.

AWS documents that `sts:GetCallerIdentity` can still return the caller's own
identity even when an explicit deny applies. That disclosure grants no resource
authority; all Identity Center and Identity Store reads remain bounded by
the start/expiry controls.

The session source must be the permission set's direct SSO session. Identity-
enhanced sessions, `sts:SetContext`, `ProvidedContexts`, `AssumeRole`, relay
state, and any additional identity policy are prohibited. This prevents an
independent identity-context policy deny from overriding the audit reads.

Tags document intent but do not enforce expiry. The `aws:CurrentTime` policy
conditions enforce the absolute access limit even if cleanup is delayed.

## Offline validation

From an isolated GUG-357 worktree:

```bash
python3 -m pytest -q \
  tests/test_deployment/test_gug357_identity_center_audit_permission_set.py
python3 tooling/validate_policy.py --policies-dir policies/iam
python3 tooling/validate_schema.py \
  --schemas-dir schemas \
  --fixtures-dir fixtures \
  --filter platform-authority
make platform-authority-bootstrap-check
```

These commands do not contact AWS. A passing result proves repository
contracts only; it does not prove live permissions, assignments, human
independence, deployment, revocation, staging, customer, or production state.

## Relationship to the GUG-363 retirement entrypoint

[ADR-051](../../ADR/ADR-051-direct-retirement-entrypoint-materialization.md)
and the
[GUG-363 deployment contract](../deployment/platform-authority-retirement-entrypoint-materialization.md)
define a separate, direct, one-attempt `CreateStack` mechanism for the dedicated
non-production retirement PEP stack. The GUG-363 plan is offline and states
`deployment_authorized=false`; this GUG-357 package does not authorize its
`apply` command.

Before GUG-357 could issue the fresh execution authorization required by that
mechanism, read-only evidence must prove:

1. the dedicated stack is absent or already exact and therefore no-touch;
2. the pre-existing authority-account role
   `scanalyze-platform-authority-gug363-cfn-materializer` has the exact reviewed
   trust, effective policies, permissions boundary and tags;
3. the execution operator has no direct IAM/Lambda/DynamoDB/Logs provider
   writes and may pass only that one role for the dedicated stack;
4. the role ARN is bound to the exact plan and maximum-fifteen-minute
   authorization, which also binds `service_role_evidence_digest`,
   `operator_authority_evidence_digest`, `live_before_state_digest` and the
   overall `live_checkpoint_digest`; and
5. the resulting stack readback returns the same exact `RoleARN` and closed
   fourteen-resource single-operator graph; the retained ledger, both
   precreated functions, all five workload roles and the proof-bound/detached
   factory role remain externally materialized GUG-365 prerequisites.

The current temporary audit policy intentionally exposes Identity Center and
Identity Store reads only. It does not expose `iam:GetRole`, policy inventory or
caller-policy/PassRole inspection, so it cannot prove items 2–4. That is a live
blocker requiring a separate explicitly reviewed read-only evidence path. Do
not broaden the auditor, use administrator access or treat the execution
operator as an independent auditor.

## Separate future creation gate

Materialization remains prohibited until the owner provides a new, exact
authorization bound to:

1. the reviewed commit and policy-template digest;
2. the rendered-policy and sanitized-intent digests;
3. the exact management account, Region, instance, store, application, runtime
   permission sets, runtime users, auditor, start, and expiry;
4. one independently reviewed creation plan;
5. an approved private evidence root and execution owner;
6. the exact allowed mutations and an explicit rollback/revocation plan.

Do not substitute a similarly named profile, permission set, application,
principal, or account. Do not use administrator, sandbox deploy/destroy,
services, customer, Audit, Log Archive, static key, or long-lived credentials.

## Required readback and stop rules

If creation is separately authorized later, success must be proven by exact
readback of the permission-set name, session duration, inline-policy digest,
empty managed policies, empty customer-managed references, absent boundary,
exact tags, exactly one direct `USER` assignment to management, direct SSO
session source, zero other identity policies on the permission set or generated
role, and terminal provisioning state. Any timeout, duplicate, group, foreign account, drift,
ambiguous response, missing page, repeated pagination token, or access denial
is `RECONCILE_ONLY`; never retry a write blindly.

The audit itself may establish technical assignment and immutable-ID facts. It
cannot prove that two credentials belong to two real humans, that sessions are
not shared, or that the humans are independent. Separate attestations are
required for those claims.

## Required revocation and recovery

Revocation is a separate authorized phase. Its terminal proof must show:

1. the exact direct assignment was deleted and reached terminal success;
2. the temporary permission set was deleted;
3. no assignment, provisioning, or pending operation remains;
4. the generated `AWSReservedSSO_*` role is absent after reconciliation;
5. the final observed session expiry is recorded, because an already issued
   session can remain usable until its own expiry, bounded by `audit_not_after`;
6. only sanitized receipt digests and final classifications were published.

If any deletion outcome is unknown, stop as `RECONCILE_ONLY`. Do not recreate,
reassign, re-provision, or delete a different resource to make the state look
clean.

## Owner decisions still required

- accept or revise the proposed permission-set name, 15-minute intent lifetime,
  `PT1H` session, and 4-hour hard maximum;
- select the one immutable auditor UserId;
- provide the exact private account and resource bindings;
- establish the separate GUG-357 `APPROVER` / `EXECUTOR` contract and two human
  attestations;
- select independent security/design reviewers;
- authorize, later and separately, the exact creation and exact revocation
  mutations.
- authorize, separately from this audit-permission package, any GUG-363
  service-role/PassRole evidence collection and the one exact execution
  checkpoint; neither is currently proved.
