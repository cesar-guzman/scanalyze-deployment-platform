# Platform-Authority Lambda Invocation Allowlist Materialization

## Purpose

GUG-219 provides the deterministic bridge between the reviewed GUG-217
retirement PEP and the GUG-218 account-wide read-only authority inventory. It
materializes a live-target allowlist and a separate release anchor without
granting or exercising any mutation, invocation or deployment authority.

Production remains **NO-GO**.

## Architecture

```text
reviewed repository source-byte digests
              +
dedicated collector contract and target binding
              +
in-process STS-validated candidate capture A
              |
              v
offline `materialize` subcommand (no AWS client)
      |                         |
      v                         v
private allowlist       private release anchor
      |                 independently supplied digest
      +-------------------------+
                                |
                                v
                 later read-only capture B
                                |
                                v
                    GUG-218 report-only receipt
```

The materializer constrains candidate A with hard-coded reviewed role, alias,
action, condition and deny invariants. It builds the fourteen expected edges
from the exact policies observed in A, then binds exact template and policy-
file digests. It does not derive the graph by parsing the GUG-217 template and
does not prove build-once archive provenance or byte equality. Candidate A
cannot introduce an allowed edge or repair drift.

## Canonical source set

Materialization requires all of the following:

| Input | Authority |
|---|---|
| GUG-217 CloudFormation template | Exact reviewed repository bytes and digest |
| GUG-217 invocation/trust policies | Ordered repository-relative paths and canonical JSON digests |
| Observed broker code | Lambda `CodeSha256` from candidate A; independent archive provenance is a later rollout gate |
| Observed published configuration | Canonical provider-projected configuration digest from candidate A |
| Target binding | Exact partition, authority account, Region and canonical broker function |
| Collector contract | Desired permission-set contract plus exact resulting IAM/STS role and inline-policy digests |
| Candidate A | Complete, fresh read-only facts collected in-process after STS validation; persisted form is self-sealed, not AWS-signed |

Missing or conflicting input blocks. Request parameters, environment defaults,
profile names, legacy aliases and previously observed values are not fallback
authority.

## Dedicated collector contract

The permission-set name is exactly:

```text
ScanalyzeAuthorityLambdaAudit
```

Its sole policy source is:

```text
policies/iam/platform-authority-lambda-invocation-inventory-role.json
```

The desired permission set must contain the exact canonical inline-policy
digest and no other authority:

```text
session duration:                     PT1H
AWS-managed policies:                 none
customer-managed policy references:  none
permissions boundary:                none
relay/secondary assume role:         none
Lambda invocation:                   explicitly denied
IAM/Lambda mutation:                 explicitly denied
deployment/production authority:     none
```

The collector contract is portable. Account-specific assignment IDs, role ARNs
and the generated Identity Center suffix are private operational data, not
repository configuration.

`AWS_PROFILE` selects a local credential chain only. STS establishes the actual
account and principal. The principal must be the canonical assumed-role base
corresponding to the provisioned
`AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_<opaque-suffix>` role. The
materializer strips the session name, validates the exact permission-set role
shape and binds both `collector_role_iam_arn_digest` and the normalized
`collector_role_sts_arn_digest`. It never predicts the suffix or copies one
from another account.

GUG-219 does not create, update, provision or assign the permission set. A
separately authorized Identity Center readback must prove assignment,
provisioning, `PT1H`, relay state and attachments. GUG-219 consumes that
private binding and validates the resulting IAM role, trust, inline policy,
managed-policy absence and permissions-boundary absence.

## Two-capture contract

### Candidate A — materialization input

Candidate A is a complete GUG-218 read-only capture under the
dedicated collector. It must have a unique nonce and bounded capture window.
The exact Identity Center suffix must already come from a separately
authorized readback and private collector-binding input. A supplies the
published version and projected provider metadata needed for materialization.

It is collected through the GUG-219 materialization entry point while reusing
the hardened GUG-218 read adapter. It is not submitted to the GUG-218
`aws-readonly` evaluation path, which still requires the not-yet-materialized
allowlist and release anchor.

Candidate A is always classified as materialization input. It cannot produce a
rollout decision because it participates in constructing the allowlist against
which a later observation will be judged.

### Deterministic materialization

The materializer:

1. validates every source and candidate-A digest;
2. constructs the exact fourteen-edge graph from observed policies constrained by reviewed invariants;
3. proves candidate A does not add, remove or alter the reviewed topology;
4. binds observed code/configuration, target and collector principal;
5. emits the GUG-218 allowlist with its canonical self-digest;
6. emits a separate release anchor binding the allowlist and source-set
   digests; and
7. writes both records create-only, owner-only, outside the repository.

Filesystem enumeration, JSON/YAML key order and the current clock cannot alter
the output. Paths participating in a policy bundle are repository-relative and
sorted before hashing. The raw template digest covers exact reviewed bytes.

The two outputs must be distinct files and distinct record types. The wrapper
rejects an existing destination, symlink, repository-local destination, same
path or same inode. The release-anchor digest is supplied separately to the
GUG-218 `aws-readonly` command. Copying the allowlist self-digest back into the
same invocation is rejected.

The release anchor is explicitly `MATERIALIZED_REVIEW_REQUIRED`. Its
`aws_readonly_inventory_eligible` field means only that the frozen bundle may
be consumed by a fresh B capture after full verification; it is not an
approval or effect flag.

### Capture B — evaluation input

Capture B starts only after the allowlist and release anchor are frozen.
Operational procedure pre-authenticates a separate B profile before A and
revalidates its STS principal immediately before B. Machine validation proves
the same canonical role, a new nonce, a distinct snapshot and later
chronology; because session names are normalized, it cannot prove credential-
session uniqueness. Candidate A bytes cannot be reused as B.

The full A-to-B sequence must satisfy:

```text
A_completed < release_created <= B_started <= B_decision
             < release_expires < A_expires
```

The release and both captures use at most five-minute windows. This sequence
has not yet been live-validated.

The GUG-218 bundle validator requires:

- the release anchor to name the exact allowlist;
- the recorded source commit to contain the exact current template, policies,
  materializer, adapter and wrappers;
- the current STS principal to match the frozen collector digest;
- complete pagination and all IAM/Lambda surfaces;
- exact equality with the fourteen expected edges;
- zero foreign invocation, trust or mutation edges;
- exact broker code and published configuration; and
- valid capture and decision chronology.

A matching B may yield `REVIEW_SAFE_REPORT_ONLY`. It still authorizes no effect.

## Operational storage boundary

These files are private operational material and must remain outside Git, CI,
Linear, NotebookLM, chat and public logs:

- candidate A and its raw snapshot;
- account-specific collector binding and exact role ARN;
- live allowlist and release anchor;
- any separately authorized future retention of candidate B; and
- any provider response or effective policy readback.

The current GUG-218 wrapper keeps raw B in memory and emits sanitized inventory
and receipt records. Only sanitized status, counts and digests may be
published. A committed synthetic fixture is repository-local and is rejected
by `aws-readonly`; persisted evidence still requires protected custody because
its self-digest is not a provider signature.

## One-person operating state

The current operator may, under explicit read-only authorization, perform A,
materialize the candidate records and perform B. The output must state that the
same human performed those duties and that independent approval is absent.

Different profiles, permission sets, sessions or timestamps do not turn one
person into an independent reviewer. No `APPROVED`, rollout-authorized or
production-ready state may be derived from the current roster.

## Evidence classification

| Evidence | Classification |
|---|---|
| Schemas, materializer, tests and documentation | Implemented on exact reviewed commit only |
| Named local gates | Locally validated only |
| Required PR checks | CI validated only for exact commit |
| Candidate A | In-process STS-validated and self-sealed materialization input; not provider-signed or clean-result evidence |
| Allowlist and release anchor | Private candidate trust material; no live effect |
| Candidate B | Fresh authenticated report-only evidence if complete bundle passes |
| Independent human review | **Blocked** with current one-person roster |
| Identity Center provisioning | Not performed by GUG-219 |
| Deployment or production | **Not authorized / NO-GO** |

## Validation boundary

The repository package is validated through the focused GUG-219 tests, GUG-218
regression suite, platform-authority gate, schema/policy validation, security
checks, full repository tests and clean-clone reproducibility. These are
repository facts only and do not replace an authenticated AWS capture.

## Related records

- [ADR-045](../../ADR/ADR-045-reviewed-lambda-authority-allowlist-and-collector.md)
- [Operations runbook](../operations/platform-authority-lambda-invocation-materialization.md)
- [Threat-model delta](../security/gug-219-lambda-authority-materialization-threat-model-delta.md)
- [GUG-218 inventory contract](platform-authority-lambda-invocation-authority.md)
