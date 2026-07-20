# ADR-044: Account-Wide Lambda Invocation Authority Inventory

- **Status:** Accepted for repository implementation; live use blocked
- **Date:** 2026-07-20
- **Work package:** GUG-218
- **Amends:** ADR-041 and ADR-043
- **Production:** **NO-GO**

## Context

GUG-217 defines three exact IAM-authenticated Lambda Function URLs and a
broker that obtains immutable human proof before a retained Change Set can be
retired. Its runtime preflight validates the expected roles, aliases and
policies. That local topology check cannot prove that another identity policy,
resource policy, alias, version, Function URL, event source or deployment
principal does not provide a second path to the same function.

For same-account Lambda access, an identity-based allow can authorize an
invocation independently of a resource policy. Function URL authorization also
has two permissions to evaluate: `lambda:InvokeFunctionUrl` and, for new
Function URLs, `lambda:InvokeFunction`. Resource policies may be attached to a
function, version or alias. A safe rollout therefore needs a complete,
account-wide graph instead of an allowlist-only spot check.

The organization currently has one human operator. Repository work and
read-only inventory do not satisfy GUG-215's independent classifier and
approver requirement.

## Decision

### 1. Capture and analysis are separate trust boundaries

GUG-218 introduces a pure analyzer that consumes a typed snapshot. A separate
read-only adapter may collect that snapshot from AWS after explicit
authorization. The GUG-217 broker does not receive broad IAM inventory
permissions and does not perform account-wide discovery during an effect path.

Raw AWS responses remain private and process-local. The public result is a
sanitized receipt containing only bounded status values, counts, reason codes
and canonical digests. The receipt contains no account ID, ARN, user, email,
policy document, Function URL, profile name or provider response.

The collector, rather than an input file, owns the evidence provenance. An
authenticated read-only capture binds collector-origin start/completion times,
the canonical assumed-role digest, an opaque scan nonce and the digest of the
sealed raw snapshot. The reviewed allowlist binds the exact collector role; IAM
users, account root and a different assumed role are rejected. The analyzer
recomputes and verifies those bindings within a five-minute decision window.
Before any snapshot loader runs, the CLI also recomputes the complete allowlist
digest and validates its account, Region, function, graph, artifact and
collector bindings against an independently supplied reviewed digest. During
AWS collection, STS identity is the sole call permitted before the collector
principal comparison; a different same-account role cannot reach EC2, Lambda
or IAM inventory APIs.
An offline caller-authored snapshot is always classified
`OFFLINE_UNVERIFIED` and its receipt is always
`BLOCKED_UNVERIFIED_SOURCE`, even when its graph matches the allowlist. Input
JSON cannot promote itself to authenticated AWS evidence.

### 2. The expected graph is exact and closed

The reviewed GUG-217 topology permits exactly fourteen authority edges:

- six identity-policy edges: classifier to `classify`, approver to `retire`
  and `reconcile`, each requiring the Function URL and function invoke actions;
- six qualified Lambda resource-policy edges for those same duties; and
- two exact role-trust edges for the classifier and approver source roles.

There are zero allowed authority-mutation edges. An additional or missing edge
is drift. Wildcard actions/resources, `NotAction`, `NotResource`, unsupported
conditions, public or cross-account principals, unexpected AWS services,
unqualified functions, `$LATEST`, old numeric versions, foreign aliases,
additional Function URLs, asynchronous invoke routes and event-source mappings
all block rollout.

### 3. Inventory completeness is a security property

The collector must exhaust every pagination token for IAM and Lambda. It must
cover users, groups, roles, inline and attached policies, effective managed
policy versions, permissions boundaries and role trust policies. Lambda
inventory covers the target function, `$LATEST`, every published version,
every alias, resource policy, Function URL configuration, event-source mapping
and asynchronous invocation configuration.

A denied read, malformed response, missing or repeated continuation token,
unknown policy version, unsupported policy semantics or incomplete surface is
not absence. It produces a blocking status.

RFC 3986 encoded IAM policy documents are decoded exactly once and parsed with
duplicate-key rejection. Provider responses are projected to the minimum
fields required by the graph before the private snapshot is sealed.

The live adapter rejects ambient endpoint and CA-bundle overrides, constructs
HTTPS clients for the canonical AWS service endpoints of the reviewed
partition/Region and verifies the resulting client endpoints. A complete
capture may take no more than five minutes; a longer observation is stale
evidence rather than a clean inventory.

### 4. Invocation and mutation authority are evaluated independently

The analyzer reports both:

- principals capable of invoking the base function, version, alias or URL; and
- principals capable of creating or changing functions, aliases, versions,
  URLs, resource policies, event sources, IAM policies, trusts, role
  attachments or pass-role paths that could manufacture new invocation
  authority.

The first graph must equal the exact allowlist. The second must be empty for a
rollout candidate. Existing account administrators remain a residual control
plane risk and are not relabeled safe by this report.

The allowlist binds both the reviewed Lambda `CodeSha256` and a canonical
digest of the complete published execution configuration. That digest covers
the handler, runtime, architecture, execution role, environment, layers,
network/KMS/logging settings and the remaining published configuration fields
without retaining their raw values in the sanitized snapshot. It includes AWS
`ConfigSha256`; a missing or malformed value blocks, and the collector rejects
any field not present in the reviewed manifest for the pinned botocore model.
All three
aliases must point to the same numeric published version, weighted routing
must be empty, and that version, `$LATEST` and the base function must carry
both exact reviewed digests. Alias-name or code-digest equality alone is not
sufficient.

The allowlist, inventory and guard receipt form one evidence bundle. A safe
status is valid only when the bundle validator proves their complete binding,
canonical digests, terminal-state mapping and chronology against a trusted,
timezone-aware evaluation instant. Validating any record in isolation cannot
establish a rollout-candidate result. Future-dated evidence, expired evidence
and a receipt detached from its inventory or reviewed allowlist fail closed.

Before any snapshot load or AWS call, the CLI requires the expected allowlist
digest. That value must come from an independently reviewed, immutable release
or deployment contract. Supplying a digest from the same file or invocation is
only self-consistency and does not establish provenance.

### 5. Every output is report-only

The only non-blocking analysis status is `REVIEW_SAFE_REPORT_ONLY`. It means the
authenticated, collector-sealed snapshot matched the reviewed graph at one
observation time. It does not authorize provisioning, token exchange, STS
context creation, Lambda invocation, Change Set retirement or production.

Offline analysis is diagnostic only. Its required next control is
`COLLECT_AUTHENTICATED_AWS_INVENTORY`; it can never satisfy rollout evidence.

Every receipt fixes these values:

```text
production = false
aws_mutation_performed = false
lambda_invocation_performed = false
deployment_authorized = false
live_retirement_authorized = false
```

The companion inventory also fixes `live_effect_authorized = false`.

A missing target is `DRIFT_DETECTED` or `INVENTORY_INCOMPLETE` and blocks
rollout. Drift produces an explicit `BLOCKED_DRIFT` receipt rather than being
collapsed into incomplete evidence. A future live gate must require a fresh
inventory, an independent repeat observation and a separately approved
preventive authority package. Time-of-check/time-of-use is not solved by an
inventory receipt.

### 6. Live and production controls remain separate packages

GUG-218 does not deploy an SCP, permissions boundary, Lambda resource policy or
runtime PEP. Preventive organization/account guardrails require their own
issue, review, deployment authority and rollback. SCPs and permissions
boundaries are not universal substitutes for evaluating resource policies and
external principals.

## Consequences

- The account-wide check is deterministic and testable without AWS.
- GUG-217 keeps its narrow runtime permissions.
- Pagination and policy-semantics uncertainty fail closed.
- Caller-authored or stale snapshots cannot be promoted to trusted evidence.
- Published code and runtime configuration are bound independently.
- A detached or resealed record cannot replace validation of the complete
  allowlist/inventory/receipt chain.
- Sanitized evidence can be shared without exposing live identifiers.
- Administrators, external principals and post-capture drift remain explicit
  residual risks.
- One current human still cannot perform the live two-person workflow.

## Alternatives rejected

- **Trust only the expected roles and policies:** cannot detect additive IAM or
  Lambda authority.
- **Filter known principals after collection:** turns an allowlist into a blind
  spot for foreign authority.
- **Give the broker IAM account-inventory permissions:** expands the effect
  runtime trusted computing base and couples high-latency discovery to a
  protected operation.
- **Treat a clean snapshot as a permanent guardrail:** ignores TOCTOU and
  privileged policy mutation after capture.
- **Assume an SCP or permissions boundary covers every path:** these controls
  have principal and policy-type limitations and require separate rollout.
- **Treat one operator with multiple profiles as independent approval:** roles
  and sessions are not different people.

## Rollback

Before live use, rollback removes the analyzer, schemas, fixtures and
documentation from a reviewed repository change. No cloud cleanup is required
because this package performs no mutation or invocation.

If a future collector has been used, discard private raw snapshots under the
approved evidence-retention procedure. Receipts do not grant authority and
must never be used to bypass a fresh inventory.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Repository artifacts only on the exact reviewed GUG-218 commit |
| Locally validated | Named local gates only for that exact commit |
| CI validated | Not established until required PR checks pass |
| AWS read-only inventory | Not performed by repository implementation |
| Preventive guardrail | **Not implemented** |
| Live Lambda / token / STS use | **Not performed** |
| Independent approver | **Blocked**; one current human |
| Production | **NO-GO** |

## Authoritative references

- [IAM GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)
- [Lambda Function URL authorization](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
- [Lambda resource-based policies](https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html)
- [IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [AWS Organizations service control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [IAM permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
