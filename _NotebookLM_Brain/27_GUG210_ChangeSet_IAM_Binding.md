# GUG-210 — Change Set IAM Binding

## Problem

The normal platform-authority policies used Change Set ARNs as the IAM
resources for Create, Delete, and Execute. AWS authorizes those actions against
the stack resource and exposes the exact Change Set name as a condition key.

## Implemented contract

- Plan and Apply use the canonical stack ARN.
- `cloudformation:ChangeSetName` must equal one canonical predeclared name.
- Create requires exact `managed_by`, `service`, and `work_package` tags.
- `TagResource` is restricted to Change Set creation and those exact tags.
- Plan and Apply mutation actions remain disjoint.
- The full Change Set ARN and UUID remain controlled PEP evidence and are
  revalidated before any external effect.

## Fail-closed cases

Missing or malformed name, foreign account/region, ARN/name mismatch,
Change Set ARN authorization, wildcard resource expansion, incomplete tags,
mixed Plan/Apply actions, stale plan, or altered full ARN all deny the flow.

## Evidence boundary

Repository implementation and local tests are not permission-set assignment,
AWS execution, Terraform apply, deployment, staging certification, or
production validation. GUG-206, GUG-125, GUG-117 and GUG-128 remain separate
gates. Production is **NO-GO**.
