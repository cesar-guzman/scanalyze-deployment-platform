# Platform-Authority Lambda Invocation Authority Inventory

## Purpose

GUG-218 adds the repository and read-only, account-wide authorization gate
required before the GUG-217 retirement PEP can be considered for a
non-production rollout. It
proves whether one complete IAM and Lambda snapshot exactly matches the
reviewed authority graph. It never invokes Lambda and never authorizes a live
effect.

Production remains **NO-GO**.

## Architecture

```text
explicitly authorized read-only session
  -> private paginated IAM/Lambda capture
  -> typed inventory snapshot
  -> pure deterministic analyzer
  -> sanitized report-only receipt
  -> independent human review
  -> separate future rollout decision
```

Capture and analysis are deliberately separate. The GUG-217 broker keeps its
narrow runtime role and does not obtain account-wide IAM reads.

The collector seals authenticated provenance into the snapshot: source mode,
collector-origin capture times, canonical principal digest, opaque scan nonce
and raw snapshot digest. The reviewed allowlist binds the exact collector role;
root, IAM users and other assumed roles are rejected. The analyzer recomputes
these bindings and requires a decision within five minutes of capture. A JSON
file loaded through `snapshot-check` is explicitly `OFFLINE_UNVERIFIED` and
can never be evidence for rollout, regardless of its contents.

## Expected graph

The allowlist contains exactly fourteen edges:

| Edge class | Count | Contract |
|---|---:|---|
| Identity policy | 6 | Two actions for each of `classify`, `retire` and `reconcile` |
| Lambda resource policy | 6 | Exact principal, qualified alias and URL-only conditions |
| Role trust | 2 | Exact classifier and approver source-role trust |
| Mutation authority | 0 | No path may create or broaden invocation authority |

Both actions are required for each Function URL path:

- `lambda:InvokeFunctionUrl` with `lambda:FunctionUrlAuthType = AWS_IAM`; and
- `lambda:InvokeFunction` with `lambda:InvokedViaFunctionUrl = true`.

## Inventory boundary

The typed snapshot must contain complete pagination evidence and all of these
surfaces:

- IAM users, groups and roles;
- inline, attached customer-managed and attached AWS-managed policies;
- effective managed-policy versions, permissions boundaries and role trusts;
- target Lambda `$LATEST`, published versions and aliases;
- the reviewed broker `CodeSha256` and canonical published-configuration
  digest, one common alias version and absence of weighted alias routing;
- function/version/alias resource policies;
- all Function URL configurations;
- event-source mappings and asynchronous invocation configuration.

Every identifier in a live capture is derived from the expected binding or an
AWS list/get response. A request parameter never establishes authority.
Provider responses are projected to the minimum reviewed fields at the adapter
boundary; environment variables, raw Function URLs and unrelated AWS metadata
are never retained in raw form before the snapshot is sealed. Security-relevant
published configuration is reduced to a canonical digest covering handler,
runtime, architecture, execution role, environment, layers and the remaining
Lambda execution settings, including AWS `ConfigSha256`. The collector compares
its reviewed field manifest with the pinned botocore Lambda model and blocks
when AWS or the SDK introduces an unreviewed field.

IAM policy documents returned with RFC 3986 percent encoding are decoded once
under strict JSON/duplicate-key validation. Malformed or still-encoded policy
content blocks as unsupported evidence; it is never treated as an empty policy.

The AWS adapter rejects configurable endpoint and CA-bundle overrides and
accepts only verified HTTPS AWS service endpoints for the bound partition,
service and Region. Total capture duration and post-capture decision age are
each bounded to five minutes.

## Fail-closed statuses

| Status | Meaning | Rollout |
|---|---|---|
| `REVIEW_SAFE_REPORT_ONLY` | Complete snapshot exactly matches the reviewed graph | Still blocked pending separate approval and preventive controls |
| `FOREIGN_AUTHORITY_PRESENT` | Extra invocation, trust or mutation authority exists | Blocked |
| `INVENTORY_INCOMPLETE` | A page/read/surface is missing or ambiguous | Blocked |
| `POLICY_SEMANTICS_UNSUPPORTED` | Conservative evaluator cannot prove a statement safe | Blocked |
| `DRIFT_DETECTED` | Required edge or immutable binding differs | Blocked |
| `OFFLINE_UNVERIFIED` | Caller-authored diagnostic snapshot lacks authenticated collector provenance | Blocked; collect authenticated AWS inventory |

The corresponding guard receipt uses `BLOCKED_DRIFT` with
`AUTHORITY_DRIFT_DETECTED` and `RESOLVE_AUTHORITY_DRIFT` so structural drift is
not mislabeled as incomplete evidence.

A missing target is drift or incomplete evidence, never a safe empty result.

Every receipt is sanitized and fixes all effect/production flags to `false`.

The allowlist, inventory and receipt must be validated as one evidence bundle
at a trusted UTC instant. The bundle validator binds all canonical digests,
identity/target fields, edge tuples, terminal states, counts and timestamps.
Standalone schema or record validation is diagnostic only and cannot establish
`REVIEW_SAFE_REPORT_ONLY` or `PREFLIGHT_PASSED_REVIEW_REQUIRED`.

Before any snapshot load or AWS call, the wrapper requires
`--expected-allowlist-digest`. The expected digest must be injected from a
separately reviewed immutable manifest or protected configuration; copying it
from the same allowlist does not create an independent trust anchor. The
wrapper recomputes the canonical allowlist digest and validates the complete
account, Region, function, graph, artifact and collector binding before it
loads even an offline snapshot. For an AWS capture, STS is the only call
permitted before the canonical assumed-role digest is compared with the
reviewed collector digest; a different same-account role stops before EC2,
Lambda or IAM inventory begins.

## Read-only policy artifact

`policies/iam/platform-authority-lambda-invocation-inventory-role.json`
documents the maximum collector authority. It contains IAM, Lambda and STS
read operations plus explicit denies for invocation and mutation. It is a
repository contract only; GUG-218 does not create, attach or provision it.

## Offline use

The wrapper exposes its exact CLI with:

```bash
python scripts/deployment/platform-authority-lambda-invocation-authority.py --help
```

`snapshot-check` is a developer diagnostic. Its receipt is always
`BLOCKED_UNVERIFIED_SOURCE` with next control
`COLLECT_AUTHENTICATED_AWS_INVENTORY`. Only the separately authorized
`aws-readonly` mode may produce authenticated report-only evidence, and it
still cannot authorize a deployment or effect.

Run tests and contract validation with:

```bash
make platform-authority-bootstrap-check
python -m pytest -q \
  tests/test_deployment/test_gug218_lambda_invocation_contracts.py \
  tests/test_deployment/test_gug218_lambda_invocation_authority.py
```

Do not pass raw AWS output to stdout, CI artifacts, issue comments or PRs.

## Evidence boundaries

| Evidence | Classification |
|---|---|
| Schema, analyzer, policy fixture, tests and docs | Implemented only on reviewed commit |
| Named local gates | Locally validated only |
| Required PR checks | CI validated only after GitHub completion |
| AWS capture | Not performed unless separately authorized and recorded |
| Lambda invocation / token / STS session | Not performed |
| Production | **NO-GO** |

## Related records

- [ADR-044](../../ADR/ADR-044-account-wide-lambda-invocation-authority.md)
- [Operations runbook](../operations/platform-authority-lambda-invocation-authority.md)
- [Threat-model delta](../security/gug-218-lambda-invocation-authority-threat-model-delta.md)
- [GUG-217 deployment contract](platform-authority-identity-context-pep.md)
