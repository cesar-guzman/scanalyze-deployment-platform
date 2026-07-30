# ADR-036: Identity Center Permission-Set Name Contract

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-16
- **Work package:** GUG-208
- **Parent:** GUG-206
- **Baseline:** `e7f6a540bd94f89c92e320d96205e4057f4753d7`
- **AWS live validation:** Rejected create only; no resource created
- **Production:** **NO-GO**

## Context

The GUG-206 bootstrap documented and enforced
`ScanalyzePlatformAuthorityBootstrapPlan` and
`ScanalyzePlatformAuthorityBootstrapApply`. Both names exceed the IAM Identity
Center maximum of 32 characters. The first authorized Plan permission-set
create failed atomically at the service validation boundary; readback
confirmed that no permission set or assignment was created. Apply was not
attempted.

This is a portability contract failure. A runtime-only alias or operator-chosen
abbreviation would diverge from the exact `AWSReservedSSO_*` role validation
and could confuse Plan and Apply authority.

## Decision

The only canonical names are:

- `ScanalyzeAuthorityBootstrapPlan` (31 characters);
- `ScanalyzeAuthorityBootstrapApply` (32 characters).

The bootstrap CLI validates every permission-set name against the portable
ASCII contract `^[A-Za-z0-9_+=,.@-]{1,32}$` before evaluating the caller role.
It then requires the exact account-local role form
`AWSReservedSSO_<canonical-name>_<16-hex-suffix>`. Case variants, prefixes,
suffixes, legacy names, customer/environment labels, and cross-role use fail
closed.

The Plan and Apply identities remain disjoint. A corrected name does not
authorize assignment, CloudFormation, backend creation, destination-account
access, deployment, or production. After merge and main verification, any AWS
retry requires fresh approval naming the corrected permission set exactly.

## Alternatives rejected

- **Silently truncate the old names:** creates implicit authority and makes
  repository/runtime behavior depend on an operator convention.
- **Accept both old and new names:** the old names cannot be created and an
  alias fallback weakens exact principal validation.
- **Use customer- or environment-specific suffixes:** can exceed the limit and
  breaks the one portable bootstrap contract.
- **Trust `AWS_PROFILE`:** profile labels are local input, not authenticated
  principal evidence.
- **Create a manual IAM role:** bypasses the governed Identity Center session
  and group-assignment model.

## Consequences

- Every customer authority account uses the same service-valid names.
- Documentation, tests, and runtime enforcement share one exact contract.
- Previously rendered IAM policy remains structurally usable because the
  permission-set name does not alter its statements or resource bindings.
- GUG-206 remains blocked until the hotfix is reviewed, merged, verified on
  `main`, and the corrected live action is separately authorized.

## Rollback

Before merge, discard the GUG-208 branch. After merge but before any live
retry, revert the hotfix and keep GUG-206 blocked. Never restore the overlength
names or create an operator-selected alias. If a corrected resource is later
partially created, inventory it read-only and follow the reviewed GUG-206
recovery boundary rather than retrying or deleting ad hoc.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Local GUG-208 worktree; commit and review pending |
| Locally validated | 29 focused tests, security 6/6, repository 1136 passed, contract matrix 114/114, provider validate 12/12 |
| CI validated | Pending exact commit |
| Live validated | No; the rejected request created no resource |
| AWS writes | One rejected create request; no resource or assignment |
| Production | **NO-GO** |
