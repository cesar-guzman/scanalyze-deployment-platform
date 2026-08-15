# ADR-054: GUG-377 Provider-Backed Upstream Materializer

- **Status:** Proposed repository implementation; not deployed
- **Date:** 2026-08-15
- **Implementation issue:** GUG-377
- **Upstream contract issue:** GUG-376
- **Consumer issue:** GUG-365
- **Extends:** ADR-053 for repository source contracts only
- **AWS/provider execution:** None
- **Production:** **NO-GO**

## Context

ADR-053 defines the closed GUG-376 prerequisite topology for GUG-365, but its
v1 public contracts intentionally remain STOP-only. They prove that current
source cannot safely authorize or certify a provider mutation; they do not
model a complete provider result, bounded asynchronous polling, generated-role
projection, one-attempt execution state or terminal repository handoff.

GUG-377 closes that source-model gap without executing GUG-376. It adds a
repository-only materializer that can compile and exercise the complete graph
against deterministic injected adapters. This implementation makes no AWS
call, opens no provider or package-registry connection, creates no private
evidence root and cannot construct a live provider adapter.

The distinction is deliberate:

- **closed repository source contracts** mean the operation graph, result
  variants, polling, attempt ledger, reconciliation and public packages can be
  validated deterministically with synthetic inputs; and
- **live provider authority and evidence** remain absent and require a separate
  GUG-376 authorization, private custody design and reviewed live orchestrator.

## Decision

### 1. Preserve v1 and add three closed v2 contracts

The five GUG-376 v1 schemas and fixtures remain unchanged and retain their
`STOP_UPSTREAM_SOURCE_CONTRACT_GAP` behavior. GUG-377 adds compatible,
explicitly versioned v2 schemas for only:

- `scanalyze.platform_authority.gug365_upstream_inventory.v2`;
- `scanalyze.platform_authority.gug365_upstream_plan.v2`; and
- `scanalyze.platform_authority.gug365_upstream_final_handoff.v2`.

Every v2 object is closed with `additionalProperties=false` wherever
applicable. Validators reject unsupported versions, v1/v2 substitution,
unknown operation or result variants, mutable references and arbitrary provider
payloads. A v2 digest cannot upgrade, reinterpret or reseal a v1 STOP record.

The inventory v2 contract contains the repository before-state projection and
target-state manifest for all planned resources. It records synthetic,
digest-only facts; it does not claim live provider inventory, runtime
provenance, private-root authority or provider certification.

The plan v2 contract causally binds:

- the exact source manifest;
- the inventory and target manifests;
- nine ordered phases and thirty ordered operations;
- one stable operation identifier and one closed operation kind per operation;
- exact request, target and dependency digests;
- the polling policy and terminal status set for every operation;
- one-attempt/no-retry and uncertainty behavior;
- completion, rollback/revocation and handoff package expectations; and
- `deployment_authorized=false`, `production=false`,
  `two_human_status=NOT_PROVEN` and
  `independent_approval_present=false`.

The final-handoff v2 contract proves only that the repository source contracts
completed under the scripted adapter. It records
`provider_certification_complete=false`, zero AWS/provider effects and
`STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED` as the live-promotion status.

### 2. Use one closed adapter protocol

The materializer exposes one typed `ProviderAdapter` protocol. It has no
generic `execute(action, payload)` method and accepts no arbitrary payload. Each
operation/result path is a closed, allowlisted variant with exhaustive
validation of the operation identifier, kind, request digest, target digest,
dependencies and result projection.

Two implementations are checked in:

- `InertProviderAdapter` is the default. Import, CLI startup and summary/dry-run
  construction do not create a provider client, inspect credentials, open a
  socket or invoke a subprocess.
- `ScriptedProviderAdapter` is deterministic test infrastructure. Its writes,
  polls and reconciliation reads are in-memory synthetic events. They are not
  AWS calls and cannot be promoted as provider evidence.

The future live boundary is explicit but unimplemented. Any attempt to build a
live adapter fails with:

```text
STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED
```

### 3. Compile exactly nine phases and thirty operations

The v2 plan preserves ADR-053's nine phases and expands them into one strict
global operation order:

| Order | Phase | Operation count | Repository contract |
|---|---|---:|---|
| 1 | `IDENTITY_CENTER_FOUNDATION` | 14 | Application, permission-set, assignment and provisioning requests plus closed outputs |
| 2 | `KMS_FOUNDATION` | 3 | Key creation, rotation and alias binding |
| 3 | `S3_ARTIFACT_FOUNDATION` | 7 | Bucket ownership, public-access, versioning, encryption, policy and tags |
| 4 | `SIGNER_PROFILE_FOUNDATION` | 1 | Immutable Lambda signing-profile version |
| 5 | `LAMBDA_CSC_FOUNDATION` | 1 | Enforcing single-publisher Code Signing Config |
| 6 | `BROKER_UNSIGNED_PUBLISH` | 1 | Exact GUG-215 unsigned object projection |
| 7 | `BROKER_SIGNING_JOB` | 1 | Exact broker signing-job/result projection |
| 8 | `LEDGER_FACTORY_UNSIGNED_PUBLISH` | 1 | Exact ledger-factory unsigned object projection |
| 9 | `LEDGER_FACTORY_SIGNING_JOB` | 1 | Exact ledger-factory signing-job/result projection |

Global sequences are exactly `1..30`. Every operation after the first depends
on the immediately preceding operation, so neither a phase nor an operation can
be skipped, duplicated, reordered or spliced. Each operation has
`attempt_limit=1`, `sdk_retry_count=0`, `retry_permitted=false` and
`ambiguous_outcome=UNCERTAIN_RECONCILE_ONLY`.

### 4. Make polling closed and bounded

Only operations whose typed contract declares asynchronous completion may
poll. Their policy contains a fixed poll kind, closed statuses, maximum attempt
count and maximum elapsed time. The repository runner receives its clock and
sleeper as injected functions; tests advance a fake clock and never wait on or
contact a provider.

The normalized status set is closed:

```text
IN_PROGRESS
SUCCEEDED
FAILED
UNKNOWN
```

`SUCCEEDED` may continue only after the exact terminal projection validates.
`FAILED` is terminal and stops the graph. An unrecognized status, exhausted
attempt bound, elapsed-time bound or contradictory result becomes
`UNCERTAIN_RECONCILE_ONLY`; it is never coerced to success or retried as a
write.

### 5. Consume one attempt before every scripted write

The repository `AttemptLedger` models the required compare-and-swap ordering.
It binds the plan and all thirty operation records, consumes the exact
operation's sole attempt before invoking the scripted adapter, persists its
outcome before advancing and rejects stale/replayed transitions.

This ledger is deterministic repository test state. It is not the separately
authorized, owner-only, durable private ledger required for GUG-376 live work.
No repository record may claim that it survived a provider crash, authenticates
an operator or proves an AWS effect.

A lost/ambiguous scripted result consumes the attempt and seals the operation
as `UNCERTAIN_RECONCILE_ONLY`. Re-running the materializer cannot invoke it
again. The only permitted continuation is the adapter's typed read-only
reconciliation method. Reconciliation can report a uniquely proven synthetic
effect, proven absence or continued ambiguity; it never grants a second write.

### 6. Separate completion, rollback and handoff

A successful scripted run returns separate digest-bound products:

1. a completion package for repository validation;
2. a rollback/revocation package; and
3. a final handoff v2.

The rollback/revocation package is not a compensating executor. It has
`automatic_rollback=false`, `deployment_authorized=false`, an empty provider
mutation list and a digest distinct from the completion package. Delete,
disable, revoke, overwrite, deassign and deprovision operations are absent from
the forward graph. Any future contraction of provider state is a separately
reviewed and authorized work package.

The handoff is fact-only and preserves:

```text
status = STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED
state = SOURCE_CONTRACTS_CLOSED_REPOSITORY_ONLY
evidence_scope = REPOSITORY_VALIDATED_SYNTHETIC_ONLY
synthetic_materialization_complete = true
provider_certification_complete = false
live_provider_evidence = false
aws_calls_performed = 0
aws_mutations = 0
provider_network_calls = 0
deployment_authorized = false
consumer_fresh_checkpoint_required = true
two_human_status = NOT_PROVEN
independent_approval_present = false
production = false
```

It also records zero GUG-365, GUG-357, GUG-215 and GUG-206 effects. Synthetic
completion is not a GUG-365 executable handoff, does not complete live GUG-376
and does not unblock GUG-365.

### 7. Keep public evidence digest-only

Public records use an explicit allowlist. They may contain stable contract
types, versions, operation identifiers, classifications, counts and canonical
digests. They contain no account ID, ARN, UserId, private path, provider payload,
signed URL, credential, token or raw response. Errors use stable codes and do
not interpolate rejected provider-controlled values.

Repository imports, plan construction, materialization tests and the default
CLI execute with AWS credential variables absent and EC2 metadata disabled.
Socket, SDK/HTTP imports and subprocess construction are denied in tests. The
resulting evidence classification is `REPOSITORY_VALIDATED_NO_LIVE_EXECUTION`.

## Rollback and recovery

Before any live authorization, rollback is a reviewed Git revert of GUG-377.
It has no AWS effect. A synthetic failed or uncertain operation preserves its
ledger state for diagnosis; restarting the repository test does not create a
new provider attempt.

No GUG-377 code deletes or repairs provider resources. Live recovery,
revocation, private-root cleanup and any billable-resource decision remain
outside this ADR and require separate authority.

## Consequences

- The GUG-376 v1 STOP contract remains a valid regression boundary.
- Repository source contracts are closed and executable only through inert or
  scripted adapters.
- Exact ordering, polling, one-attempt and reconciliation behavior can be
  reviewed without AWS or provider network access.
- GUG-376 live execution, private custody and provider evidence remain blocked.
- GUG-365, GUG-357, GUG-215 and GUG-206 receive no authority or effect.
- Single-operator truth remains explicit; production remains **NO-GO**.

## Evidence classification

- GUG-377 source and tests: `REPOSITORY_VALIDATED_NO_LIVE_EXECUTION` at most.
- Inventory and plan scope: `REPOSITORY_SCRIPTED_SYNTHETIC_ONLY`.
- Final-handoff scope: `REPOSITORY_VALIDATED_SYNTHETIC_ONLY`.
- Repository summary: `REPOSITORY_SOURCE_CONTRACTS_CLOSED`.
- Scripted terminal result: `SYNTHETIC_MATERIALIZATION_COMPLETE`.
- Provider certification/private root/runtime proof: `NOT_PROVEN`.
- Live provider construction: `STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED`.
- Ambiguous consumed operation: `UNCERTAIN_RECONCILE_ONLY`.
- GUG-365/GUG-357/GUG-215/GUG-206 effects: zero.
- Production: **NO-GO**.

## References

- [ADR-053](ADR-053-gug365-upstream-prerequisites-materialization.md)
- [Deployment contract](../docs/deployment/platform-authority-gug365-upstream-prerequisites.md)
- [Operations runbook](../docs/operations/platform-authority-gug365-upstream-prerequisites.md)
- [Threat model](../docs/security/gug376-upstream-prerequisites-threat-model.md)
