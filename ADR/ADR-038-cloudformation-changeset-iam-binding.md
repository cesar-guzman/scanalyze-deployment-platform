# ADR-038: CloudFormation Change Set IAM Binding

- **Status:** Accepted for stack-plus-name IAM binding; request-parity amendment pending reviewed merge
- **Date:** 2026-07-17
- **Work package:** GUG-210
- **Parent:** GUG-206
- **Baseline:** `dc94eb51258a15e4960a0d154a42d6d5410528b0`
- **AWS live validation:** Not performed
- **Production:** **NO-GO**

## Context

The normal platform-authority Plan and Apply policies originally attempted to
authorize `CreateChangeSet`, `DeleteChangeSet`, and `ExecuteChangeSet` with a
Change Set ARN. AWS exposes the Change Set ARN as evidence, but these actions
authorize against the stack resource and support the
`cloudformation:ChangeSetName` condition. The former policy could therefore
deny a valid reviewed operation for the wrong reason and did not express the
supported name-level restriction.

The stack-plus-name correction reached `main`, but a request/policy drift
remained: the Apply policy condition contained the canonical bare name while
the normal execution adapter sent the full ARN as the `ChangeSetName` request
parameter. AWS accepts either request shape, but repository evidence did not
prove that the IAM condition and the runtime request converged. The normal CLI
also retained a direct `cancel` adapter after ADR-041 made the GUG-215 broker
the sole `DeleteChangeSet` authority.

## Decision

Normal `CreateChangeSet` and `ExecuteChangeSet` use only the canonical stack
resource:

`arn:<partition>:cloudformation:<region>:<account>:stack/scanalyze-platform-authority-state-backend/*`

Each statement also requires exact equality on
`cloudformation:ChangeSetName`. Plan renders a canonical name before the
permission set is assigned, and the live `plan` command must receive that same
name. One standard-library pure helper validates the full ARN's partition,
Region, account, canonical name and UUID-shaped ID against the immutable
bootstrap binding and returns an immutable typed identity containing the full
ARN, name, UUID and coordinates. Both Apply policy rendering and the execution
request use the bare name from that identity; callers cannot supply a second
name.

`CreateChangeSet` additionally requires the exact reviewed request tags and
tag-key set. The separate `TagResource` grant is limited to creation through
`cloudformation:CreateAction=CreateChangeSet`, the canonical stack and exact
Change Set name, and the same tag contract.

IAM name binding is necessary but does not identify the UUID-bearing instance.
Plan uses its existing exact-stack `GetTemplate` authority to fetch the
`Original` template by the newly created full Change Set ARN, requires exact
textual equality with the local bootstrap template, and persists that digest.
This binds the digest to the UUID-bearing object rather than merely hashing a
later local file.

Before constructing an AWS client, Apply loads duplicate-key-rejecting Plan and
approval JSON, verifies their digests, immutable bindings, template digest and
validity windows, and parses the full Change Set ARN. Locally invalid evidence
therefore cannot trigger identity discovery or another AWS request.
Immediately before execution, the PEP still describes by the full Change Set
ARN from the digest-validated plan and compares its UUID, stack, name, status,
execution status, tags and resource inventory. It repeats that full-ARN
readback after the account-level public-access-block effect and the exact empty
review-shell check, then revalidates the local template digest, approval window
and approved executor. Because a replacement Change Set has a different ARN,
the Plan-time original-template read plus Apply-time exact-ARN read is the
repository's equivalent immutable guarantee only while the reviewed Plan and
approval remain under controlled custody; their unkeyed digests prove internal
integrity, not authenticity. It does not claim an Apply-time `GetTemplate` read.
The full-ARN readback is the last CloudFormation call before it sends the
derived bare name plus exact stack to `ExecuteChangeSet`. The normal two-person
Plan/Apply separation is unchanged, and each AWS CLI request is configured for
one attempt so a transport ambiguity cannot retry the mutation.

ADR-041 supersedes direct normal retirement. The normal Plan policy keeps its
explicit `DeleteChangeSet` deny, and the compatibility `cancel` command fails
locally with a stable sanitized diagnostic before constructing an AWS client,
reading a Plan, writing a ledger, or making any AWS call. Only the separately
reviewed GUG-215 broker may receive `DeleteChangeSet` authority.

## Rejected alternatives

- Authorize the Change Set ARN for these actions: unsupported service resource
  semantics.
- Use a wildcard Change Set name: permits an unreviewed sibling Change Set.
- Trust only the name: a deleted and recreated name could identify another
  instance; the PEP must retain the full ARN and UUID.
- Send the full ARN to the mutation while the IAM condition is rendered from
  the bare name: leaves request authorization dependent on unproved provider
  interpretation.
- Restore normal Plan-role deletion or hide it behind a flag: bypasses the
  GUG-215 service-owned ledger, independent humans and one-attempt boundary.
- Omit creation tags: weakens inventory and evidence binding.

## Consequences

- Policy rendering fails closed on unsupported resource shapes, missing names,
  mismatched ARN/name tuples, incomplete tags, or mixed Plan/Apply authority.
- Apply rejects every locally provable Plan, approval, expiry and ARN failure
  before an AWS client is constructed, then repeats authorization against the
  live approved executor immediately before the one-shot mutation.
- A new Change Set requires a newly rendered Plan policy and a new reviewed
  plan; operators cannot edit the name in place.
- The persisted Plan schema remains version 1 because the full ARN evidence
  contract is unchanged. No dependency, IAM policy or CloudFormation template
  changes are required.
- No AWS, Identity Center, Change Set, Terraform, deployment, or production
  action is authorized by this ADR.

## Rollback

Revert the request-parity implementation, tests and documentation atomically
through a reviewed PR while keeping both permission sets unassigned. Do not
restore full-ARN mutation arguments, prior Change Set ARN authorization,
direct normal cancellation, or caller-selected names.
