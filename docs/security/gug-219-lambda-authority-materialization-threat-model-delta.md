# GUG-219 threat-model delta: Lambda authority materialization

## Scope

This delta covers the deterministic producer for the GUG-218 reviewed
allowlist, its separate release anchor, the dedicated Identity Center collector
contract and the candidate-A/fresh-B read-only sequence. It does not cover
Identity Center provisioning, a preventive organization guardrail, Lambda
invocation, Change Set retirement, deployment or production.

Production is **NO-GO**.

## Assets

- reviewed GUG-217 template and ordered policy bundle;
- candidate-A observed broker code/configuration digests; independent
  build-once provenance remains a separate gate;
- exact account, partition, Region, function, alias and role binding;
- dedicated collector effective-policy and principal binding;
- private candidate A and in-memory candidate B;
- deterministic fourteen-edge allowlist and self-digest;
- separately consumable release anchor and digest; and
- sanitized GUG-218 report-only evidence.

## Trust boundaries

### Reviewed-source boundary

Hard-coded reviewed invariants constrain the graph constructed from policies
observed in A, and exact repository source-file digests are bound separately.
The materializer does not derive the graph by parsing the template or prove
archive byte equality. Missing source evidence is a blocker rather than
permission to infer from the account.

### Identity Center collector boundary

The collector is one dedicated permission set with one exact inline policy and
no managed policies, customer-managed references or permissions boundary. Its
actual account-local `AWSReservedSSO_*` suffix must be proven from AWS and
bound canonically. A profile name is outside the authorization boundary.

### Candidate A boundary

A is sensitive input collected in-process after STS validation and then self-
sealed; its persisted form is not an AWS-signed attestation. It may supply
non-inferable provider bindings, but cannot approve itself or define the
expected topology.

### Materialization and release-anchor boundary

The core materialization function and `materialize` subcommand have no AWS
client; only `candidate-aws-readonly` uses the hardened adapter. They produce
deterministic, create-only private files. The allowlist self-digest and release-
anchor digest are separate checks. The expected release digest must be a
distinct reviewed input; a current single-operator self-read proves only local
integrity, not an independent protected channel.

### Candidate B boundary

B is a later observation after the allowlist is frozen. Operational procedure
pre-authenticates a separate B profile before A and revalidates STS immediately
before B, while machine validation proves only the same canonical role, a
distinct nonce/snapshot and later chronology. A matching B remains report-only.

### Governance boundary

The current one-person roster can produce evidence but cannot independently
approve it. Technical role/session separation does not satisfy human duty
separation.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Committed synthetic fixture is used for live collection | `aws-readonly` rejects repository-local inputs and requires distinct owner-only private records plus a separate release digest | Block before AWS inventory |
| Candidate A defines its own expected graph | Hard-coded role/alias/action/condition/deny invariants constrain policies observed in A; exact source bytes are digest-bound | Materialization blocked |
| Drift present in A is silently allowlisted | A may confirm only source-bound live facts; extra/missing edges remain drift | Materialization blocked |
| Allowlist digest is copied from the same file | Separate record type, file/inode and independently supplied release-anchor digest | Collection blocked |
| Materializer output changes across runs | Canonical JSON, sorted relative paths, exact template bytes and immutable timestamps | Determinism test fails; no release anchor |
| Filesystem/YAML order changes the policy bundle | Ordered manifest of relative path plus canonical document digest | Digest mismatch blocks |
| Observed Lambda digest is presented as build-once provenance | GUG-219 labels it as observed only; independent archive provenance and byte equality remain a rollout blocker | No provenance claim |
| Current clock changes the allowlist digest | Timestamp comes from immutable source or sealed capture metadata | Nondeterministic input rejected |
| Generic ReadOnly role gains account authorization reads | Dedicated permission set; generic role is explicitly rejected | Stop before IAM/Lambda reads |
| Collector receives managed policy or permissions boundary | Effective-policy readback requires exact inline policy and empty attachments/boundary | Collector not eligible |
| Collector can invoke or mutate Lambda/IAM | Exact policy digest plus explicit-deny and negative-action validation | Collector not eligible |
| `AWS_PROFILE` is treated as authority | STS account/principal comparison is authoritative; profile is never serialized | Stop after STS |
| Identity Center suffix is guessed or reused from another account | A separately authorized readback supplies the exact private binding; GUG-219 cross-binds IAM and STS role forms | Principal mismatch blocks |
| STS session name changes the principal digest | Normalize to exact assumed-role base while retaining permission-set suffix | Stable role binding; foreign role blocks |
| IAM role ARN and STS assumed-role ARN are hashed inconsistently | One reviewed canonicalization contract derives the comparison principal | Contract test fails closed |
| A is relabeled as B | Distinct nonces, timestamps and snapshot digests; session refresh is recorded operationally | Bundle rejected |
| B reuses cached pages from A | Fresh collector-owned pagination and snapshot seal required | Incomplete/replayed evidence blocks |
| AWS changes after A but before B | B is fresh and compared with frozen bindings | Drift detected; no safe report |
| Materialized files are overwritten | Exclusive create, `O_NOFOLLOW`, owner-only mode, outside repository | Write rejected |
| Live allowlist or raw snapshot enters Git/CI/Linear | Operational-path rejection, documentation boundary and security tests | Publication blocked; incident handling |
| Unknown provider configuration field is omitted from digest | Pinned Lambda provider-field projection rejects unreviewed configuration fields; GUG-219 record containers use exact keys | Materialization or B blocked |
| Incomplete/denied read is treated as absence | GUG-218 strict pagination and no denied-read fallback | `INVENTORY_INCOMPLETE` |
| Same operator uses two profiles as independent review | Evidence binds human review status separately from cloud sessions | Approval remains false |
| Clean B is presented as deployment authorization | All output effect/deployment/production flags remain false | Overclaim rejected |

## Attack-path result

The intended path is:

```text
reviewed source
  -> dedicated read-only A
  -> deterministic private allowlist + separate release anchor
  -> later dedicated read-only B
  -> exact GUG-218 comparison
  -> sanitized report-only evidence
  -> different human review (currently blocked)
  -> separately authorized future controls
```

The following paths remain denied:

```text
synthetic allowlist -> aws-readonly
A -> self-approval
profile name -> authority
generic ReadOnly -> collector
same human/session variants -> independent approval
clean report -> Lambda/Change Set/deployment/production effect
```

## Residual risks

- An administrator can alter Identity Center, IAM or Lambda after capture B.
- AWS reads may be eventually consistent; ambiguous observations remain
  blocking.
- Candidate A/B and effective-policy data are sensitive even without
  credentials.
- A new Identity Center provisioning can change the opaque role suffix and
  invalidate the frozen binding.
- Build-once artifact publication, byte-equality proof and a protected release-
  anchor channel require their own governance.
- A clean inventory is detective evidence, not a preventive control.
- One current human cannot independently approve the result.

## Evidence classification

| Class | Status |
|---|---|
| Repository implementation | Implemented only on exact reviewed GUG-219 commit |
| Local validation | Named gates only |
| CI validation | Exact required checks only after completion |
| Candidate A | Materialization input only |
| Candidate B | Report-only observation only |
| Identity Center mutation | **Not authorized / not performed** |
| Independent approval | **Blocked** with one human |
| Deployment / production | **Blocked / NO-GO** |

## References

- [ADR-045](../../ADR/ADR-045-reviewed-lambda-authority-allowlist-and-collector.md)
- [Deployment contract](../deployment/platform-authority-lambda-invocation-materialization.md)
- [Operations runbook](../operations/platform-authority-lambda-invocation-materialization.md)
- [GUG-218 threat-model delta](gug-218-lambda-invocation-authority-threat-model-delta.md)
