# ADR-045: Reviewed Lambda Authority Allowlist and Dedicated Collector

- **Status:** Accepted for repository implementation; AWS use requires separate authorization
- **Date:** 2026-07-20
- **Work package:** GUG-219
- **Amends:** ADR-044
- **Depends on:** GUG-217 and GUG-218
- **Production:** **NO-GO**

## Context

GUG-218 can validate a complete IAM and Lambda snapshot against an exact,
closed authority graph, but it deliberately does not manufacture the reviewed
allowlist that establishes that graph. Its committed allowlist is synthetic
test data. A caller that copied the embedded digest from that same file would
prove only self-consistency, not that the allowlist came from reviewed
GUG-217 source bytes and an exact live binding. Independent build-once
artifact provenance and byte equality remain a separate rollout gate.

The generic account read-only permission set is also insufficient for the
GUG-218 collector because the collector requires the complete account
authorization graph. Broadening that generic role would make unrelated users
part of the trusted computing base and would not bind collection to one
reviewed principal.

The current operating roster contains one human. That operator may implement
the repository controls and, under separate authorization, perform report-only
read operations. Multiple profiles or sessions belonging to that one person
do not provide independent approval.

## Decision

### 1. Use a two-capture materialization model

GUG-219 separates materialization from evaluation:

```text
reviewed GUG-217 source-byte digests
  + exact target binding + dedicated collector contract
  + in-process STS-validated read-only candidate capture A
      -> deterministic allowlist
      -> separately consumable release anchor
      -> frozen immutable digests
      -> new authenticated read-only capture B
      -> GUG-218 report-only evaluation
```

Candidate A is never a clean-rollout receipt. It supplies only provider facts
that cannot be safely inferred before an AWS observation, such as the actual
Identity Center role suffix and published Lambda metadata. The expected
function, aliases, roles, actions, conditions and fourteen authority-edge
shapes are constrained by hard-coded reviewed invariants. The materializer
constructs edges from the exact policies observed in candidate A and binds the
current GUG-217 template and policy-file digests; it does not parse those
source files to derive the graph independently. Candidate A cannot add an edge
or legalize drift. GUG-219 also does not prove that an independently published
build-once archive contains the bytes represented by Lambda `CodeSha256`.

Candidate A uses a GUG-219 materialization-capture entry point built on the
GUG-218 read-only adapter. It is authorized by the exact target and collector
contracts, not by a synthetic allowlist, and it cannot emit a GUG-218 safe
status. The normal GUG-218 `aws-readonly` evaluation remains unavailable until
the allowlist and release anchor have been frozen.

The materializer binds:

- the exact reviewed GUG-217 CloudFormation template digest;
- the canonical digest of the complete ordered GUG-217 policy bundle;
- the broker code digest observed in candidate A;
- the broker published-configuration digest observed in candidate A;
- the exact authority account, partition, Region and function;
- the three exact aliases `classify`, `retire` and `reconcile`;
- the exact classifier and approver invocation/trust graph;
- the dedicated collector contract and canonical principal digest; and
- the canonical self-digest and collector binding of candidate A.

The persisted candidate is self-sealed, not an AWS-signed attestation. Its
provenance depends on in-process STS validation, private custody and review.
Both producer and consumer verify that the caller-supplied source commit
exists, is reachable from the checked-out `HEAD`, and contains the exact
materializer, adapter, wrapper, template and policy bytes. The release binds
that commit together with the exact template/policy digests and separately
supplied release digest.

The same canonical inputs must always produce byte-identical records. A
current clock, filesystem order, YAML map order, AWS profile name or session
name is not a materialization input. Any timestamp in the record comes from an
immutable reviewed source or explicit trusted capture metadata and is included
in the canonical digest.

Operational procedure pre-authenticates a separate local B profile before A,
then repeats STS principal validation immediately before capture B. This avoids
placing an interactive SSO flow inside the bounded release window. Machine
validation deliberately normalizes away the session name, so it proves the
same exact canonical role, a new opaque scan nonce, a distinct snapshot and
later chronology; it cannot prove credential-session uniqueness. B is
evaluated against the frozen allowlist and separately obtained release-anchor
digest. Candidate A must not be replayed, resealed or relabeled as B.

The live sequence is intentionally short-lived:

```text
A_completed < release_created <= B_started <= B_decision
             < release_expires < A_expires
```

Both captures and the release have at most five-minute freshness windows. The
operational feasibility of this sequence is not live-validated by GUG-219.

### 2. Publish the allowlist digest through a separate release anchor

The allowlist retains its canonical self-digest. A separate typed release
anchor binds that allowlist digest to the reviewed source-byte, observed
runtime, target and
collector-contract digests. Its own canonical digest is the value supplied to
the GUG-218 `aws-readonly` boundary through a distinct input. A protected
release channel and independent operator are operational requirements; the
repository cannot establish either while the roster contains one person.

The allowlist and release anchor must be different record types, different
files and different input arguments. The wrapper rejects the same path, inode
or document being used for both. Reading the allowlist's own digest and passing
it back on the same command line does not establish an independent anchor.

When the current one-person roster materializes both records, the separation
is cryptographic and procedural only. The evidence must explicitly state that
independent human approval is absent; no approval status may be emitted.

### 3. Use one dedicated Identity Center collector contract

The canonical permission-set name is:

```text
ScanalyzeAuthorityLambdaAudit
```

It is AWS-valid and within the 32-byte Identity Center limit. Its permission
contract contains exactly the inline policy from:

```text
policies/iam/platform-authority-lambda-invocation-inventory-role.json
```

The desired permission set has:

- a bounded `PT1H` session duration;
- no AWS-managed policy;
- no customer-managed policy reference;
- no permissions boundary;
- an explicit `DenyUnreviewedActions` `NotAction` boundary whose exception set
  is exactly the reviewed read-only action set, so no account-local resource
  policy can add an unreviewed service action;
- `lambda:GetPolicy` is explicitly denied outside the exact broker function
  and qualifiers, while function-scoped Lambda list actions are allowed only
  on function ARNs in the authority account and explicitly denied everywhere
  else; only Lambda discovery actions without resource-level support use
  `Resource: "*"`;
- an explicit `Deny` for `sts:AssumeRole`, so same-account resource-based
  trust cannot turn the collector session into a secondary-role relay;
- no Lambda invocation permission;
- no IAM or Lambda mutation permission; and
- no production or deployment authority.

Provisioning or assigning this permission set is not authorized by GUG-219.
Any future provisioning requires an exact, separately approved Identity Center
change and readback of its assignment, provisioning status, session duration,
relay state and attachments. The GUG-219 collector does not call Identity
Center APIs; it consumes a private binding and validates the resulting IAM/STS
role, trust, inline policy, managed-policy absence and boundary absence.

GUG-220 and ADR-046 define that separate bounded provisioning and exact
readback package. Its single direct-user assignment is a bootstrap mechanism,
not independent approval; GUG-219 continues to consume only the verified
private collector binding. The GUG-220 intent is live-bound by canonical
digests of the Identity Center `InstanceArn`, `IdentityStoreId` and the exact
account-local AWS SSO SAML provider ARN, expires no more than 15 minutes after
creation, binds an existing reviewed source commit with byte-equal critical
GUG-219/GUG-220 sources, and is revalidated before every mutation and final
evidence. One sealed policy object is consumed without worktree re-read. An
intent created before those fields became mandatory is obsolete. Installing or
changing the collector inline policy forces target reprovisioning, and
`READBACK_VERIFIED` requires non-null digests for both the permission-set and
role ARNs plus positive assignment, provisioning and role verification.
The exact inline policy includes `DenyUnreviewedActions`,
`DenyGetPolicyOutsideExactBroker`,
`DenyFunctionReadsOutsideAuthorityAccount` and `DenyRoleChaining`; relying on
the absence of
an identity-policy `Allow` is insufficient because a same-account role trust
can otherwise grant a role session `sts:AssumeRole` through a resource policy.
The role trust must name the exact SAML provider observed during planning; a
different same-account `AWSSO_*_DO_NOT_DELETE` provider is rejected.

`AWS_PROFILE` is only a local credential-provider selector. It is not recorded
in the allowlist and never establishes authority. After `sts:GetCallerIdentity`,
the collector must validate the exact account and canonical assumed-role
principal before any EC2, IAM or Lambda read.

Identity Center creates an account-local role whose name contains an actual,
opaque `AWSReservedSSO_..._<suffix>` value. A separately authorized Identity
Center/IAM readback must discover that suffix; it is never guessed from the
permission-set name, profile, user or a previous account. GUG-219 consumes the
exact role ARN in a private binding and cross-validates its IAM and normalized
STS forms. Public records bind canonical digests for both. Session names are
removed before comparison, so this binding cannot demonstrate a distinct SSO
credential session.

### 4. Store operational material privately and fail closed

Candidate A, the materialized live allowlist, release anchor,
collector binding and raw AWS evidence are operational trust material. They
must be written create-only, without following symlinks, owner-only, and
outside the repository. They must not enter Git, CI artifacts, Linear,
NotebookLM, chat, logs or support bundles.

GUG-220 private inputs are accepted only through descriptor-based
`O_NOFOLLOW` reads followed by `fstat` verification of a regular file owned by
the current effective user with mode exactly `0600`. A path-only check does not
establish evidence custody.

The current GUG-218 wrapper keeps raw B in memory and emits only sanitized
inventory and receipt records. Retaining B later would require separate
authorization and the same private-evidence boundary.

Committed fixtures are explicitly synthetic and can exercise only offline
paths. The `aws-readonly` path rejects repository-local inputs and requires
distinct owner-only files plus a separately supplied release digest before
starting collection. Persisted snapshots are not provider-signed, so custody
and review remain part of the trust boundary.

### 5. Every outcome remains report-only

A complete capture B that exactly matches the frozen graph may produce the
GUG-218 status `REVIEW_SAFE_REPORT_ONLY`. This is evidence for review only. It
does not authorize Identity Center mutation, Lambda invocation, token exchange,
STS context creation, Change Set retirement, Terraform Apply, customer
deployment or production.

With one current human, the operator may materialize and collect report-only
evidence but cannot satisfy independent approval. The missing reviewer is an
explicit blocker, not a role that the same person may emulate with another
profile.

## Consequences

- GUG-218 receives a deterministic producer and an independent digest channel.
- A committed synthetic fixture cannot be passed directly to the live path.
- The collector obtains the minimum complete read surface without broadening a
  generic read-only role.
- The live Identity Center suffix and STS principal representation are bound
  explicitly rather than inferred.
- Candidate A cannot certify itself; only a fresh B can be compared with the
  frozen allowlist.
- One-person operation remains useful for report-only preparation while its
  governance limitation remains visible.
- Additional Identity Center provisioning, preventive guardrails, deployment
  and production remain separate work packages.

## Alternatives rejected

- **Use the committed synthetic allowlist:** test data is not a reviewed live
  trust root.
- **Copy the allowlist self-digest into the CLI:** this proves no independent
  provenance.
- **Use one capture to build and validate the allowlist:** the same observation
  would define its own expected result.
- **Allow candidate A to define graph edges:** current drift could be silently
  legalized.
- **Attach the collector policy to generic ReadOnly:** expands authority and
  loses exact-principal attribution.
- **Bind by profile name:** profiles are local aliases and can point to a
  different account or role.
- **Predict the Identity Center suffix:** suffixes are opaque, account-local and
  can change after reprovisioning.
- **Treat two sessions owned by one person as two reviewers:** session
  separation is not human independence.

## Failure and reconciliation

Missing source material, mismatched digests, incomplete pagination, duplicate
JSON keys, unexpected GUG-219 record fields, unreviewed Lambda configuration
fields, wrong principal, reused nonce, stale capture, foreign edge or ambiguous
AWS response blocks the workflow. An ambiguous collection is
reconciled read-only under a new authorization window; it is never retried as
the same capture and never rewritten into a clean result.

If candidate A becomes invalid before B, discard the candidate release anchor
and start a new A-to-materialization sequence. Do not edit an existing
allowlist or release anchor in place.

## Rollback

Repository rollback reverts the GUG-219 implementation through a reviewed PR.
This package performs no cloud mutation, so repository rollback has no AWS
cleanup step.

Operational files are invalidated and then retained or destroyed only under
the approved private-evidence retention procedure. Revoking a future
permission-set assignment or deleting a future permission set is outside this
package and requires separately authorized rollback.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Repository artifacts only on the exact reviewed GUG-219 commit |
| Locally validated | Named local gates only for that exact commit |
| CI validated | Established only by required checks for the exact commit |
| Candidate A | In-process STS-validated, self-sealed materialization input; not AWS-signed and never approval evidence |
| Materialized allowlist/release anchor | Private candidate trust material; not approval |
| Candidate B | Fresh authenticated report-only evidence if the full GUG-218 bundle passes |
| Identity Center provisioning | **Not performed / not authorized** |
| Lambda, token, STS-context or Change Set effect | **Not performed / not authorized** |
| Independent approval | **Blocked** while one human is on the roster |
| Production | **NO-GO** |

## Post-merge sequence

1. Verify the merged commit and required checks on `main`.
2. Obtain separate authorization for any Identity Center provisioning and
   assignment of the exact collector contract through GUG-220.
3. Separately read back the effective permission-set contract and actual
   `AWSReservedSSO_*` role before collection.
4. Obtain an explicit read-only window and perform candidate A.
5. Within candidate A's five-minute validity, materialize the allowlist and
   release anchor privately, freeze their digests and begin B before expiry.
6. Record that independent approval is absent while the roster has one human.
7. Obtain a new read-only window and perform fresh capture B.
8. Validate the complete GUG-218 evidence bundle and publish only sanitized
   status/count/digest evidence.
9. Add a different human reviewer before any future rollout approval.
10. Complete separately reviewed preventive guardrail, non-production rollout
    and production-readiness packages. Production remains **NO-GO**.

## References

- [ADR-044](ADR-044-account-wide-lambda-invocation-authority.md)
- [GUG-218 deployment contract](../docs/deployment/platform-authority-lambda-invocation-authority.md)
- [GUG-218 operations runbook](../docs/operations/platform-authority-lambda-invocation-authority.md)
- [ADR-046](ADR-046-lambda-audit-permission-set-provisioning.md)
- [IAM Identity Center permission sets](https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsetsconcept.html)
