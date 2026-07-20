# GUG-218 Account-Wide Lambda Authority Inventory Runbook

## Safety boundary

This runbook prepares and reviews a read-only inventory. It does not authorize
IAM/Lambda mutation, provisioning, token exchange, STS context creation,
Lambda invocation, Change Set operations, Terraform Apply, customer deployment
or production.

The current roster has one human. A clean report cannot replace the different
classifier and approver required by GUG-215/GUG-217.

An offline snapshot is never trusted evidence. The wrapper controls the source
mode; request JSON cannot claim `AWS_READ_ONLY`. Only the authenticated
collector may seal AWS provenance into a candidate report.

## Phase 0 — Authorization and binding

Before any AWS call:

1. record issue, branch, commit, PR and evidence owner;
2. record the explicitly authorized account, Region, profile and time window;
3. verify the expected function name, aliases, role names and allowlist digest
   come from a reviewed immutable deployment/release contract, and pass that
   independently obtained digest as `--expected-allowlist-digest`;
4. require the CLI to recompute the canonical allowlist digest and validate the
   complete account, Region, function, graph and artifact binding before the
   snapshot loader or any AWS client can start;
5. verify the reviewed allowlist binds the exact read-only collector role and
   prove the current STS assumed-role session resolves to that role; STS is the
   only AWS call permitted before this comparison, and root, IAM users or any
   other same-account or foreign role stop before EC2, Lambda or IAM reads;
6. prove the session contains no invocation or mutation authority;
7. define private raw-evidence retention and deletion;
8. identify an independent reviewer for any future rollout decision.

Stop if account, Region, binding, profile or authorization is absent. Never use
the default AWS profile.

Unset and reject custom AWS endpoint or CA-bundle configuration, including
global/service endpoint overrides. The adapter must construct and read back
canonical HTTPS endpoints for the reviewed partition, service and Region; a
localhost, proxy endpoint or alternate provider is not AWS provenance.

## Phase 1 — Identity preflight

Run `sts:GetCallerIdentity` first and compare the returned account to the exact
authorized account. Record only a sanitized suffix/status in public evidence.
Do not print or retain credentials, session tokens or profile configuration.

The collector role may only use the reviewed read-only policy. Any effective
invoke or mutation permission stops the procedure.

## Phase 2 — Private capture

Capture all pages for:

1. IAM account authorization details;
2. managed policy versions needed by attached policies and boundaries;
3. target function metadata and policy;
4. all versions, each version policy, each `CodeSha256` and the complete
   published execution-configuration digest;
5. all aliases, their exact version/routing configuration, alias policies and
   Function URL configurations;
6. all event-source mappings and asynchronous invocation configurations.

The adapter must reject a denied call, malformed page, repeated token,
truncated response without a token or a token without truncation. Do not
convert a partial capture into an empty list.

Project every provider response to the minimum reviewed fields before it joins
the snapshot. Never retain Lambda environment variables, raw Function URLs,
role/VPC/KMS/logging values, event filter payloads or unrelated provider fields
in public evidence. The adapter must instead derive a canonical digest of all
published execution fields, including AWS `ConfigSha256`, handler, runtime, architecture,
execution role, environment, layers, VPC/KMS/logging and timeout/memory
settings. A missing/invalid `ConfigSha256` or a field absent from the reviewed
pinned-botocore manifest blocks the capture. No raw provider object is evidence
by default.

Decode RFC 3986 encoded IAM policy documents exactly once, then apply strict
JSON and duplicate-key validation. Malformed or double-encoded content is
ambiguous evidence and stops the capture; never coerce it to an empty policy.

The adapter must record collector-origin start/completion times, an opaque scan
nonce, the digest of the canonical STS principal and a digest over the complete
raw snapshot. The analyzer must verify the seal and freshness window. Missing,
future, stale, mismatched or caller-supplied provenance blocks the result.
The sanitized decision must occur no more than five minutes after collection
completes; a longer TTL in an input cannot relax that invariant.
The collection itself must also complete within five minutes.

Keep the raw snapshot only in the approved private location. Never upload it to
GitHub, Linear, CI, chat or a support bundle.

## Phase 3 — Analysis

Run the pure analyzer against the private typed snapshot and reviewed
allowlist. Require:

- the expected account, Region and target function binding;
- complete pagination and surface markers;
- exactly fourteen expected authority edges;
- zero extra or missing invocation/trust edges;
- zero authority-mutation edges;
- three exact aliases on one reviewed numeric version, no weighted routing and
  exact broker `CodeSha256` plus published-configuration digest on the
  published version, `$LATEST` and base function;
- no public, foreign, wildcard, unqualified, `$LATEST`, legacy-version,
  asynchronous or event-source path;
- no unsupported policy semantics.

Only the sanitized receipt may leave the private boundary. Before sharing or
using it as a review candidate, validate the reviewed allowlist, inventory and
receipt together with `validate_gug218_evidence_bundle` at a trusted,
timezone-aware UTC instant. Verify their canonical digests, exact cross-record
bindings and chronology. Per-file validation, a caller-supplied clock, a
future-dated record or a resealed receipt detached from the inventory is not
valid evidence.

For local development, `snapshot-check` may analyze a caller-authored fixture,
but it must return `OFFLINE_UNVERIFIED` / `BLOCKED_UNVERIFIED_SOURCE` and
`COLLECT_AUTHENTICATED_AWS_INVENTORY`. Never relabel that receipt or use it as
rollout evidence.

## Phase 4 — Review and freshness

`REVIEW_SAFE_REPORT_ONLY` is evidence for review, not authorization. Before a
future non-production rollout:

1. have a different person review the exact binding, digest and reason counts;
2. repeat the read-only capture in a separately authorized window;
3. require the second snapshot to produce the same closed graph;
4. install or verify the separately reviewed preventive authority guardrail;
5. rerun GUG-214 through GUG-217 gates;
6. obtain explicit live execution authorization.

The current one-person roster cannot complete step 1.

## Stop conditions

Stop immediately for:

- any AWS mutation or Lambda invocation in a collector path;
- wrong account, Region, profile or target;
- custom/non-HTTPS/noncanonical service endpoint or CA-bundle override;
- collection duration or decision age above five minutes;
- any denied/missing/incomplete page or unsupported policy statement;
- wildcard/foreign/public principal or resource;
- direct, asynchronous, unqualified, `$LATEST`, old-version or event-source
  invocation path;
- extra Function URL or alias;
- any principal able to change Lambda/IAM authority or pass a role into such a
  path;
- raw identifiers or policy content entering public evidence;
- offline, stale, future-dated, unsealed or principal-mismatched evidence being
  presented as an authenticated AWS observation;
- code-equivalent but configuration-different Lambda versions or aliases;
- missing provider `ConfigSha256` or an unreviewed Lambda configuration field;
- expected allowlist digest sourced from the same untrusted allowlist or CLI
  channel instead of an immutable reviewed contract;
- standalone receipt validation without the exact reviewed allowlist,
  inventory and trusted evaluation instant;
- one operator being presented as independent approval;
- any claim of live or production authorization.

## Failure and reconciliation

Do not retry a failed capture blindly. If an AWS response is ambiguous, run
read-only reconciliation under a new authorization window. Mark the prior
receipt `INVENTORY_INCOMPLETE` or `DRIFT_DETECTED`; never edit it to appear
clean.

Use `BLOCKED_DRIFT` only for verified structural or immutable-binding drift and
resolve the cause under a new reviewed package. Do not relabel it incomplete or
repair it from the inventory session.

This package creates no durable AWS state. Rollback deletes no cloud resource.

## Public closeout template

```text
Implemented: <commit/PR only>
Locally validated: <named gates>
CI validated: <exact checks or not established>
AWS read-only inventory: <not performed or sanitized timestamp/status>
Live validated: no
Independent approver: blocked while one human exists
Production: NO-GO
```
