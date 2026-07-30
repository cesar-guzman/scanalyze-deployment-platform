# GUG-219 — Reviewed Lambda Authority Allowlist and Collector

## Executive statement

GUG-219 creates the deterministic, fail-closed bridge between the reviewed
GUG-217 Lambda retirement design and the GUG-218 account-wide authority
inventory. It uses one in-process STS-validated, self-sealed candidate capture to materialize a frozen
allowlist and separate release anchor, then requires a fresh second capture for
report-only evaluation.

It does not authorize Identity Center changes, Lambda invocation, Change Set
operations, deployment or production.

## Why two captures are required

The first authenticated observation contains live provider facts that cannot
be safely guessed, including the actual Identity Center role suffix and exact
published Lambda metadata. But an observation cannot define the expected graph
and then certify itself.

The safe sequence is:

```text
candidate A
  -> enforce reviewed graph invariants and bind GUG-217 source-byte digests
  -> deterministic private allowlist
  -> separate private release anchor
  -> freeze digests
  -> pre-authenticated B profile; immediate STS revalidation; distinct nonce/snapshot
  -> exact GUG-218 report-only comparison
```

Hard-coded reviewed role, alias, action, condition and deny invariants constrain
the fourteen-edge graph constructed from policies observed in A. Exact source-
file digests are bound, but the template is not parsed to derive the graph and
build-once archive byte equality is not proven. Candidate A cannot add an
allowed edge. Candidate B cannot reuse A's nonce, pages or snapshot. Session
names are normalized, so credential-session uniqueness is an operational
record rather than machine evidence.

## Dedicated collector

The portable permission-set name is:

```text
ScanalyzeAuthorityLambdaAudit
```

It contains only the exact GUG-218 inline read policy. It has no AWS-managed
policies, customer-managed policy references or permissions boundary.
`DenyUnreviewedActions` blocks every action outside the exact reviewed read
set, including resource-policy grants. It also explicitly denies
`sts:AssumeRole`; the STS deny prevents same-account trust from creating a
secondary-role relay.
`DenyGetPolicyOutsideExactBroker` limits `lambda:GetPolicy` to the broker and
its qualifiers. `DenyFunctionReadsOutsideAuthorityAccount` denies the
resource-scoped Lambda list actions outside authority-account function ARNs;
only discovery actions without resource-level support retain
`Resource: "*"`.

The local AWS profile is only a credential selector. STS proves the account and
actual principal. The opaque `AWSReservedSSO_*` suffix must come from a
separately authorized Identity Center/IAM readback; it is never inferred from
a profile, user or another account. Public evidence contains only its
canonical digest.

GUG-219 documents and validates this contract but does not provision or assign
the permission set.

GUG-220 owns that separately authorized provisioning boundary. Its intent is
valid for no more than 15 minutes and binds digests of the live Identity Center
`InstanceArn`, `IdentityStoreId` and exact authority SAML provider ARN plus an
existing reviewed source commit with byte-equal critical runtime; older
pre-hardening intents are obsolete.
An inline-policy change forces explicit target reprovisioning. The handoff is
eligible only when exact readback supplies non-null permission-set and role ARN
digests and verifies assignment, provisioning and the account-local role.
Private inputs use descriptor-based `O_NOFOLLOW`, current-owner and exact
`0600` checks.

The first authorized GUG-220 window is now consumed. Sanitized reconciliation
found the collector permission set present but its policy, assignment,
provisioning and collector role absent or unverified. That state is not a
collector handoff and GUG-220 cannot be retried. GUG-221 must repair the exact
partial state through the invoke-only `ScanalyzeLambdaAuditRepair` boundary
and private server-side PEP, then complete Identity Center/IAM readback before
Candidate A.

## Independent digest channel

The allowlist contains its own canonical digest. A different typed release
anchor binds that digest to reviewed source bytes, observed runtime digests,
target and collector contract. GUG-218 receives the release-anchor digest
through a distinct input. A protected channel is an operational prerequisite,
not something GUG-219 establishes with the current one-person roster.

Using one document, path or command-line value for both checks is only
self-consistency and is rejected. Operational records are create-only, owner-
only and outside Git, CI, Linear, NotebookLM and logs.

## Fail-closed rules

- Synthetic fixtures cannot enter `aws-readonly`.
- Candidate A is never a rollout-candidate receipt.
- Live observations never broaden the reviewed source graph.
- Missing or conflicting source, observed runtime or provider evidence blocks;
  independent build-once provenance remains a separate rollout gate.
- Generic ReadOnly, administrator, root, IAM-user and foreign roles are not the
  dedicated collector.
- Managed policies, a permissions boundary or extra inline authority block.
- Profile names and session names do not establish authority.
- The actual Identity Center role suffix must match the frozen binding.
- Allowlist and release anchor must be distinct immutable records.
- Capture B must be fresh and complete.
- A matching B is report-only, not preventive enforcement.
- Multiple sessions owned by one person are not independent approval.
- Repository and CI success are not live or production validation.

## Current one-person roster

The current operator may implement the package and, with explicit read-only
authorization, run candidate A, materialize the private records and run B. The
evidence must state that one person performed those duties and that independent
review is absent.

No approval, deployment authorization or production-readiness claim can be
derived until a different human reviews the frozen binding and result.

## Evidence state

| Evidence | State |
|---|---|
| Materializer/contracts/tests/docs | Implemented only on reviewed GUG-219 commit |
| Local validation | Named gates only |
| CI validation | Exact required checks only |
| Candidate A | In-process STS-validated, self-sealed private materialization input only; not AWS-signed |
| Allowlist/release anchor | Private candidate trust material |
| Candidate B | Later report-only observation if bundle passes |
| GUG-220 provisioning | Partial/uncertain; original ledger consumed |
| GUG-221 repair | Blocked until separately authorized and verified |
| Independent reviewer | **Blocked** while one human is on the roster |
| Deployment and production | **NO-GO** |

## Post-merge handoff

After main and CI verification, any permission-set provisioning requires a
separate authorized change and effective-policy readback. Candidate A and B
each require their own explicit read-only window. Only sanitized status, counts
and digests may leave the private evidence boundary.

Never feed GUG-219 a GUG-220 intent produced before the 15-minute TTL and live
Instance/Identity Store digest bindings became mandatory.
Never feed it the observed partial GUG-220 state or a GUG-221 receipt without
complete collector readback.

A different human reviewer and separately reviewed preventive/deployment
controls remain mandatory before any production decision.

## Operational references

Use [ADR-045](../ADR/ADR-045-reviewed-lambda-authority-allowlist-and-collector.md),
the [deployment contract](../docs/deployment/platform-authority-lambda-invocation-materialization.md),
the [runbook](../docs/operations/platform-authority-lambda-invocation-materialization.md)
and the [threat-model delta](../docs/security/gug-219-lambda-authority-materialization-threat-model-delta.md)
as the authoritative GUG-219 documentation package.

Use [GUG-221](36_GUG221_Lambda_Audit_Provisioning_Repair.md) for the sanitized
repair boundary; raw repair evidence never enters NotebookLM.
