# ADR-038: CloudFormation Change Set IAM Binding

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-17
- **Work package:** GUG-210
- **Parent:** GUG-206
- **Baseline:** `dc94eb51258a15e4960a0d154a42d6d5410528b0`
- **AWS live validation:** Not performed
- **Production:** **NO-GO**

## Context

The normal platform-authority Plan and Apply policies attempted to authorize
`CreateChangeSet`, `DeleteChangeSet`, and `ExecuteChangeSet` with a Change Set
ARN. AWS exposes the Change Set ARN as evidence, but these three actions use
the stack resource for IAM authorization. The former policy could therefore
deny a valid reviewed operation for the wrong reason and did not express the
supported name-level restriction.

## Decision

All three actions use only the canonical stack resource:

`arn:<partition>:cloudformation:<region>:<account>:stack/scanalyze-platform-authority-state-backend/*`

Each statement also requires exact equality on
`cloudformation:ChangeSetName`. Plan renders a canonical name before the
permission set is assigned, and the live `plan` command must receive that same
name. Apply derives the name from the digest-validated full ARN in the plan.

`CreateChangeSet` additionally requires the exact reviewed request tags and
tag-key set. The separate `TagResource` grant is limited to creation through
`cloudformation:CreateAction=CreateChangeSet`, the canonical stack and exact
Change Set name, and the same tag contract.

IAM name binding is necessary but does not identify the UUID-bearing instance.
Immediately before execution, the PEP must still use the full Change Set ARN
from the signed plan and compare its UUID, stack, name, status, execution
status, template digest, resource inventory, expiry, approval, and caller
binding. The normal two-person Plan/Apply separation is unchanged.

## Rejected alternatives

- Authorize the Change Set ARN for these actions: unsupported service resource
  semantics.
- Use a wildcard Change Set name: permits an unreviewed sibling Change Set.
- Trust only the name: a deleted and recreated name could identify another
  instance; the PEP must retain the full ARN and UUID.
- Omit creation tags: weakens inventory and evidence binding.

## Consequences

- Policy rendering fails closed on unsupported resource shapes, missing names,
  mismatched ARN/name tuples, incomplete tags, or mixed Plan/Apply authority.
- A new Change Set requires a newly rendered Plan policy and a new reviewed
  plan; operators cannot edit the name in place.
- No AWS, Identity Center, Change Set, Terraform, deployment, or production
  action is authorized by this ADR.

## Rollback

Revert the repository change and keep both permission sets unassigned. Do not
restore the prior Change Set ARN authorization or execute an existing Change
Set under an ambiguous policy.
