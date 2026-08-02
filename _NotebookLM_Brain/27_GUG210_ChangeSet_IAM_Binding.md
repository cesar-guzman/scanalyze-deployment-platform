# GUG-210 — Change Set IAM Binding

## Problem

The normal platform-authority policies used Change Set ARNs as the IAM
resources for Create and Execute. AWS authorizes those actions against the
stack resource and exposes the exact Change Set name as a condition key. The
policy renderer already selected that model, but Apply still sent the full ARN
as `--change-set-name`; policy and mutation request therefore did not share one
canonical representation.

## Implemented contract

- Plan and Apply use the canonical stack ARN.
- `cloudformation:ChangeSetName` must equal one canonical predeclared name.
- A single pure parser validates the complete controlled ARN and returns an
  immutable typed identity; policy rendering and Apply use its bare name.
- Create requires exact `managed_by`, `service`, and `work_package` tags.
- `TagResource` is restricted to Change Set creation and those exact tags.
- Plan and Apply mutation actions remain disjoint.
- Plan reads the exact Change Set's `Original` template by full ARN and requires
  equality with the local template before persisting its digest; Apply later
  revalidates that local digest and the same UUID-bearing ARN without gaining
  `GetTemplate` authority.
- The full Change Set ARN and UUID remain controlled PEP evidence and are
  revalidated after Public Access Block and the final empty-stack check. That
  full-ARN readback is the last CloudFormation call before the one-shot Execute
  request.
- Execute sends the derived bare Change Set name together with the exact stack;
  no caller-supplied name and no mutation retry are accepted.
- Before an AWS client exists, Apply rejects duplicate-key JSON, bad digests,
  invalid record semantics even after redigesting, binding/template drift,
  expired evidence and malformed or foreign ARNs.
- The historical normal `cancel` entry point is compatibility-only and fails
  locally with `NORMAL_CANCEL_RETIRED` before identity, Plan, ledger, or AWS
  access. GUG-215 remains the sole Change Set retirement authority.

## Fail-closed cases

Missing or malformed ARN/name/UUID, a bare input name, foreign
partition/account/region, ARN/name mismatch, wildcard resource expansion,
incomplete tags, mixed Plan/Apply actions, stale Plan, a live same-name
replacement against the reviewed ARN, or an unredigested ARN alteration all
deny the flow before Execute. Ambiguous Execute results are reconciled with
read-only checks rather than a second mutation request.

A coordinated rewrite of both local artifacts to another valid same-name UUID,
followed by recomputation of both unkeyed digests, is not locally distinguishable
without an external trust root. Controlled custody of the reviewed Plan and
approval is therefore a prerequisite, not a property proved by these digests.

## Validation contract

Tests must prove policy/argv parity, malformed and cross-boundary ARN rejection,
local evidence rejection before client construction, Plan-time original
template readback by full ARN, the repeated full-ARN identity readback after the
preceding AWS mutation, one Execute request with no retry, and a zero-AWS legacy
cancel path with sanitized output. The repository policy JSON and schemas do
not change for this correction. Publication also requires explicit owner
disposition of the artifact-authenticity boundary above.

## Evidence boundary

Repository implementation and local tests are not permission-set assignment,
AWS execution, Terraform apply, deployment, staging certification, or
production validation. The tests use synthetic clients and fake executables;
no AWS command is run. GUG-206, GUG-215, GUG-125, GUG-117 and GUG-128 remain
separate gates. Production is **NO-GO**.
