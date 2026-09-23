# GUG-432 upstream mutation executor

GUG-432 adds a separate execution library for the thirty GUG-377 upstream
operations. It does not change the inert GUG-377 materializer, the GUG-392
read-only capture lane, or GUG-431's staging-only input transport.

The AWS transport is limited by the execution plan to the authority accounts:
Identity Center in `839393571433`, all subsequent phases in `042360977644`,
and region `us-east-1`. This is the **authority-non-production** environment.
It cannot deploy the Scanalyze runtime to `905418363887`.
S3 mutations that accept an expected owner add the fixed authority-account
owner guard at the SDK boundary; this guard is included in the GUG-432
operation contract without expanding the legacy request catalog.

## Components

| Module | Responsibility |
| --- | --- |
| `platform_authority_gug376_upstream_live_plan.py` | Immutable complete catalog, source/tree, account, custody and trust bindings; fully resolved requests; existing semantic safety checks. |
| `platform_authority_gug376_upstream_live_provider.py` | Closed SDK routes, first-call STS, disabled SDK retries, immutable object bytes and typed readback projections; no authorization or self-certification. |
| `platform_authority_gug376_upstream_live_ledger.py` | Owner-only local custody, durable claim, ordered transitions, complete history validation and CAS. |
| `platform_authority_gug376_upstream_live_executor.py` | External verification gates, one operation per session/checkpoint, durable-before-write ordering, bounded read-only polling and reconciliation. |

Requests and provider projections remain private in memory. Public execution
results contain digests and statuses, never SDK exception messages, principal
identifiers, request documents or raw evidence. A transport result is not a
verified live receipt. `SYNTHETIC` and `AWS_TRANSPORT` are bound into the plan
and cannot be changed when finalizing its ledger.

## Required integration before connected execution

There is deliberately no CLI that accepts a JSON `approved` flag and starts
writing. The deployment owner must supply reviewed, independently pinned
implementations of the four mandatory verifier interfaces:

1. **Owner**: authenticates the exact one-operation authorization over an
   out-of-band channel, including source/tree, full write set, caller/session,
   authority policy and equal maximum-permissions cap, before state, causal
   predecessor slots, custody and ledger snapshot. A digest alone is invalid.
2. **Provider**: authenticates the preflight transcript and source freshness,
   direct fresh SSO session, first signed STS call, effective authority and
   absence of additive grants. It verifies fresh before state, causal slots,
   exact provider response/readback and any no-touch or reconciliation receipt.
3. **Ledger anchor**: maintains an external monotonic CAS anchor. It compares
   and durably advances the expected ledger digest before a write can run and
   after the terminal record. It must reject copied roots, stale checkpoints,
   rewound history and session reuse. Local unkeyed hashes do not protect
   against an owner who can rewrite the entire file and recompute hashes.
4. **Final evidence**: verifies the complete run's causal history and absence
   of unexpected resources, assignments, grants or publishers, and confirms
   closure/expiry of all phase sessions. Its receipt never authorizes production.

Each verifier exposes `identity()` and `verify(stage, expected, evidence, now)`.
`TrustPins` are supplied independently from receipts and plans. The executor
requires a `VerifiedReceipt` with the exact stage, binding, trust/code pins and
transport mode; a boolean or an exception fails closed. These interfaces are
trusted integration boundaries, not implementations of owner authentication.

The approved private root must already exist outside repository and synced
storage. Compute `ledger_root_digest(root)` and include it in `RunPlan` before
creating `DurableMutationLedger`. The root's actual directory identity is
rechecked against that binding. Keep one complete ledger for all nine phases;
never reset it for a later batch, or copy it to obtain a new attempt.

## Execution and recovery

Every `LiveOperation` contains fully resolved write values and separate before
and after readbacks. Its target digest is derived from the immutable after
readback contract; generated identifiers use closed response-field references
only in readbacks. The executor never interpolates them into a later write.
It records the concrete request digest when claiming that operation once.

Use a new checkpoint and phase-specific session for every operation. This is a
conservative batch size of one: any provider output required by the next
request must first be independently verified, then covered by a new owner
authorization. The window is at most fifteen minutes and cannot exceed session
expiry. Authorization is rechecked after verification and immediately before
the SDK mutation, after STS revalidation.

The sole attempt is persisted as `IN_FLIGHT` before dispatch. A timeout,
crash, missing receipt, failed readback or exhausted poll budget consumes the
attempt and leaves `IN_FLIGHT` or `AMBIGUOUS`; it never triggers a retry or
automatic rollback. `FAILED` also blocks all successors. Recovery performs
fresh read-only observations with an external reconciliation receipt.
`RECONCILED` does not release dependent operations. Resolve the incident and
obtain a separately reviewed recovery decision; do not edit the ledger.
If a process stops between local persistence and external anchoring,
`recover_anchor` supplies the complete history for an external CAS from the
last authenticated head. It makes no provider call or local transition and
cannot reset the anchor or authorize a retry.

`EXACT_PRESENT_NO_TOUCH` requires independently verified exact target state
and records a zero-attempt receipt. It is not a permission to adopt conflicting
resources or to skip a phase. SDK `close()` closes HTTP clients only; it does
not revoke an SSO session. The integration must expire/close the phase session
and prove this to the final verifier.

## Local validation and remaining gates

Run only the focused tests for this lane with the repository-pinned Python:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 uv run --no-project --python 3.11.14 --with pytest==9.1.1 --with jsonschema==4.26.0 --with boto3==1.42.57 --with botocore==1.42.97 python -m pytest -q -p no:cacheprovider tests/test_deployment/test_gug376_upstream_live_provider.py tests/test_deployment/test_gug376_upstream_live_ledger.py tests/test_deployment/test_gug376_upstream_live_executor.py
```

These tests use synthetic clients and verifier fixtures. They neither call AWS
nor prove owner authorization, connected custody, effective live permissions,
source freshness, provider certification or deployment. Source freshness must
come from an authorized evidence channel; this implementation does not query
the current `main` ref.

Connected activation still requires reviewed/published source and exact CI,
real verifier implementations and pins, private inputs, an approved root and
an exact authorized phase command. Terminal GUG-376 certification remains an
upstream prerequisite: GUG-365 installation, controlled GUG-215 retirement and
the later deployment/staging/production gates remain separate. Preserve the
retained Change Set; this library does not execute or delete it.

Production acceptance still requires a verified deployed version, public DNS,
HTTPS for `https://prod.scanalyze.cloud` and `/api`, identity configuration and
a successful authenticated processing journey. None follows from local tests.
