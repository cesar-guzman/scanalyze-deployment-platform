# Identity Control Plane Deployment Reference

> **Decision:** ADR-024 / GUG-93\
> **Phase gate:** GUG-117\
> **Execution status:** repository implementation; live execution blocked\
> **Production:** **NO-GO**

## Purpose

This reference explains the portable identity control plane that translates
ADR-023 into deployment infrastructure and fail-closed runtime behavior. It is
safe to reuse for any customer and dedicated account because the source
contains no embedded customer, deployment, account, region, pool, client,
domain, email, or provider resource instance.

Deployment-specific values come only from the authoritative deployment record
and verified upstream contracts. Examples in this document use symbolic values;
they are not operational inputs and must not be replaced with live values in
Git.

This document does not authorize Terraform apply, AWS access, Cognito changes,
user creation, client credential creation, migration, bootstrap, retirement, or
production.

## Ownership boundary

| Component | Owner | Authoritative data | Explicit non-owner |
|---|---|---|---|
| `roots/identity-control-plane` | Identity Plan/Apply boundary | Exact deployment tuple and upstream contract digests | Local operator arguments, another root's state, console discovery |
| `modules/identity-control-plane` | Terraform identity resource owner | Provider configuration, membership/audit/bootstrap resource definitions | Application membership decisions and live users |
| Pre-token runtime | Application Security / identity runtime | Exact deployment config plus authoritative membership record | Provider groups, client metadata, email, headers, payloads |
| Bootstrap runtime | GUG-94 lifecycle boundary using GUG-93 transport/runtime primitive | Approved, versioned bootstrap record | SQS body alone, self-signup, shared administrator |
| M2M runtime provisioner | Workload identity administration boundary | Exact reviewed workload binding and idempotency record | Terraform, a human role, request-only scope claims |
| `identity-control-plane/v1` contract | Identity control-plane Apply producer | Non-sensitive public identifiers, versions, restrictions, and digest | Credentials, users, memberships, tokens, state |
| Services consumer | Services Terraform root and application startup validation | Verified identity contract | Copied console values, environment fallback, legacy map |
| Edge identity consumer | Edge identity Terraform root | Verified identity plus services contracts | Self-created Cognito resources or wildcard audience |

Terraform is the resource owner, not the authorization policy decision point.
The authoritative membership store and runtime policy checks remain mandatory
after Terraform creates the resources.

## Canonical deployment graph

```text
account-ready-gate
  -> global
  -> network
  -> platform
  -> data-foundation
  -> cicd
  -> artifact-publication
  -> identity-control-plane
  -> services
  -> edge-identity
  -> edge
  -> addons
  -> synthetic-validation
```

The machine authority is `deployment/layers.yaml`. The identity stage consumes
the verified global contract, immutable release manifest, and externally
reviewed `identity-contract/v2` workload registry. The release manifest
identifies both the pre-token and control-processor runtime artifacts by exact
bucket, key, immutable object version, and source-code digest. Services cannot
plan until the published identity-control-plane contract is present and exact.
Edge identity cannot plan until both services and identity are exact.

## Required input bindings

The root accepts an exact tuple and rejects missing or mismatched upstream
values:

| Input | Authority | Validation requirement |
|---|---|---|
| `customer_id` | Deployment registry | Canonical immutable customer identifier |
| `deployment_id` | Deployment registry | Canonical immutable deployment identifier, distinct from customer |
| `account_id` | Account-ready authority | Exact dedicated account |
| `region` | Deployment registry | Exact supported regional scope |
| release version and digest | Release promotion authority | Exact immutable release manifest |
| global contract and expected digest | Global root plus registry expectation | Contract identity, tuple, and digest equality |
| release-manifest contract and expected digest | Promotion authority plus registry expectation | Tuple, region, release, digest, and two immutable runtime artifact locators |
| `identity-contract/v2` and expected digest | Reviewed workload-identity registry | Exact tuple, digest, action-set coverage, and client/binding equality; an empty initial registry is valid |
| policy version and digest | Reviewed ADR-023 policy publication | Supported semantic version and exact RFC 8785/SHA-256 digest |
| SPA callback/logout URLs | Reviewed deployment configuration | Unique exact HTTPS URLs; no wildcard or local development fallback |

A hash establishes content identity, not writer authority. The consumer must
validate both the digest and the producer/IAM boundary.

## Terraform resource posture

The identity module defines the deployment-local target resources:

- a deletion-protected Cognito user pool;
- immutable customer/deployment custom attributes;
- admin-only user creation, exact SPA OAuth configuration, token revocation,
  and enumeration-safe client errors;
- the closed `scanalyze.api.v1` resource server;
- human role groups marked non-authoritative;
- a versioned V2 pre-token function alias and exact pool invocation permission;
- a deletion-protected, encrypted, point-in-time-recoverable membership table;
- a deletion-protected, encrypted authorization-audit table;
- a FIFO bootstrap queue and exact paired DLQ;
- a bounded encryption key and encrypted retained operational logs; and
- alarms for token errors, throttles, and bootstrap poison messages.

Terraform does not define:

- provider users, passwords, temporary enrollment values, MFA material, or
  group memberships;
- application membership rows or role changes;
- M2M credential values;
- lifecycle/support/break-glass API behavior;
- migration mappings; or
- destructive decommission operations.

`prevent_destroy` and provider deletion protection are deliberate. They are not
removed to make a plan convenient.

## Human token flow

```mermaid
sequenceDiagram
    participant User as Enterprise user
    participant IdP as Deployment identity provider
    participant Hook as V2 pre-token processor
    participant Membership as Membership store
    participant Audit as Authorization audit
    participant API as API Gateway and backend
    User->>IdP: Complete approved authentication flow
    IdP->>Hook: Supported token event and immutable attributes
    Hook->>Hook: Verify pool, client, event, customer, and deployment
    Hook->>Membership: Get exact subject/customer/deployment membership
    Membership-->>Hook: Active versioned membership or no authority
    Hook->>Audit: Sanitized allow or denial
    Hook-->>IdP: Canonical access claims; provider groups suppressed
    IdP-->>User: Short-lived access token
    User->>API: Access token and requested operation
    API->>API: Validate issuer, audience, token use, and route scope
    API->>API: GUG-153 policy, freshness, ownership, and action enforcement
```

The processor permits only supported V2 human token events from the exact pool
and client. It reads one exact membership. A missing record, suspended/revoked
state, unknown role, stale membership version, stale policy/catalog version,
foreign binding, timeout, or audit failure denies token issuance.

GUG-93 deliberately deploys this path inactive: the hook receives
`HUMAN_RUNTIME_ENABLED=false`, `USER_POOL_ID=UNBOUND`, and an empty allowed-client
list. The runtime checks that gate before reading provider input or membership
state. Binding the generated pool and SPA client and enabling human token
issuance is a separate reviewed GUG-153/GUG-94 promotion; it is not inferred
from Terraform-created identifiers.

Provider groups and client metadata may be present in the provider event but
never establish role or tenant authority. The response suppresses provider
groups and emits the role and versions from the membership store only.

## Access-token-only edge handoff

Edge identity receives:

- the issuer;
- exact SPA and approved M2M audiences;
- `scanalyze.api.v1/read`, `scanalyze.api.v1/write`, and
  `scanalyze.api.v1/admin`;
- route-to-scope mapping;
- the upstream identity contract identity and digest; and
- explicit restrictions that reject ID tokens, request identity headers,
  legacy `X-Tenant-ID`, and a default-route fallback.

Every protected route declares exactly one reviewed scope because HTTP API JWT
authorizers treat multiple configured scopes as alternatives. Backend
authorization still checks principal grant and object ownership. The edge may
narrow authority but cannot create a role, membership, object owner, or
customer/deployment binding.

## Bootstrap processing

The bootstrap queue is transport, not authority. A message refers to an
authoritative bootstrap record; the processor reloads and validates that record
before any effect.

In the GUG-93 repository state this is a composed and locally tested future
primitive, not an enabled lifecycle operation. `HUMAN_RUNTIME_ENABLED=false`
causes the processor to deny before loading a bootstrap record or invoking a
provider or membership adapter. GUG-94 must supply the reviewed authority,
provider operation, and enablement evidence before this sequence can execute.

Required conditions include:

- supported request/command versions;
- exact subject, customer, and deployment;
- approved state and expected conditional version;
- exactly two distinct, non-self approvers bound to the same request and tuple;
- reviewed phishing-resistant assurance and authentication age;
- supported role, catalog versions, policy version, and policy digest;
- lifetime no longer than 900 seconds;
- an authoritative idempotency key; and
- conditional claim and consume.

Provider user creation and membership creation receive the same trusted
idempotency key. Provider temporary values and recovery material are discarded
from the processor response. The response contains only sanitized completion
and non-sensitive references.

The SQS handler returns only failed message identifiers in
`batchItemFailures`. A malformed record without a usable identifier rejects the
whole batch because it cannot be retried safely. Message bodies and dependency
exceptions are not logged.

General-purpose human runtime provisioning remains disabled. The bounded
first-administrator transition becomes eligible for non-production execution
only through GUG-94's separately reviewed workflow.

## M2M runtime provisioning

The M2M provisioner is intentionally outside Terraform. Its pure runtime
contract supports injected provider, credential-store, binding-store, audit,
and clock adapters. The flow is:

1. validate a machine-only command and exact workload/environment/customer/
   deployment/actions binding;
2. load an existing idempotency record;
3. return existing non-sensitive references only when every binding matches;
4. otherwise acquire a conditional binding claim;
5. call an idempotent provider adapter with the exact closed scope set;
6. escrow the generated credential immediately in the approved credential
   store;
7. conditionally complete the workload binding; and
8. emit sanitized audit and return only client and credential references.

A raw credential is never a Terraform input/output, contract field, application
result, log field, audit field, test fixture value intended for deployment, or
general CI artifact. The provider and credential-store adapters are responsible
for secure in-memory transfer and must not serialize their input.

Provisioning claims use a 300-second lease, longer than the Lambda timeout. A
retry may recover only an expired lease through an exact conditional
compare-and-swap that replaces the prior claim token. Fresh leases and CAS
conflicts deny before provider access. Existing custody is accepted only after
readback proves the exact secret name and ARN, deployment KMS key, immutable
binding tags, current idempotent version, and no pending deletion.

Human principals, empty/default actions, duplicate actions, unknown scopes,
foreign bindings, idempotency conflicts, dependency failures, and incomplete
provider responses deny and release the conditional claim where safe.

A newly created client is not application authority. Its sanitized exact
binding must first be reconciled into `identity-contract/v2`, independently
reviewed, and republished under a new digest. Only a subsequent identity,
services, and edge plan may add that client to backend bindings and JWT
audiences. The bootstrap contract intentionally starts with empty client and
binding lists.

## Contract publication and consumption

The contract is an atomic, versioned envelope. It publishes public integration
identifiers and restrictions, not operational or credential values. Consumers
must verify:

1. contract ID and schema version;
2. exact customer/deployment/account/region;
3. expected contract digest;
4. issuer and public client identifiers;
5. access-token-only semantics;
6. exact claim mapping, action scopes, and action scope sets;
7. exact equality between M2M client identifiers and M2M bindings, with every
   binding constrained to the current customer/deployment and reviewed scopes;
8. current authorization, role, scope, and policy versions; and
9. explicit false values for cross-account/deployment access, ID-token API use,
   provider-group authority, and credential exposure.

Publication to live SSM is blocked. Local fixtures demonstrate shape only and
are never substituted into a live consumer.

## Portable replication procedure

For a future authorized deployment, the process is identical for every
customer/account:

1. resolve one authoritative deployment tuple and upstream contract digests;
2. select one reviewed release and policy digest;
3. create a plan for the identity state key with no live discovery fallback;
4. reject any replacement or deletion unless a separately approved migration
   explicitly owns it;
5. apply only the exact reviewed saved plan;
6. publish and read back the atomic identity contract;
7. plan services and edge consumers using that exact contract;
8. exercise synthetic positive and negative token/bootstrap/M2M behavior;
9. exercise a second isolated deployment and prove cross-binding denial; and
10. retain sanitized evidence outside Git and make a separate GO/NO-GO
    decision.

Steps 3-10 are not authorized by this document and remain blocked.

## Legacy inventory and state adoption

Do not import provider resources simply because a name resembles the expected
deployment. A separately approved report-only inventory must establish:

- provider resource and Terraform-state ownership;
- exact customer/deployment/account/region;
- immutable attribute compatibility;
- client audiences, flows, callbacks, and token policy;
- group mapping versus authoritative membership;
- policy/catalog versions and digest;
- downstream consumers and active sessions; and
- retention, rollback, and evidence custody.

Classify each resource using ADR-024's fully bound, partial, ambiguous/shared,
provider-only, state-only/orphaned, immutable-incompatible, and inconsistent
classes. Only a fully bound, compatible, non-conflicting resource is a state-
adoption candidate.

An adoption procedure requires protected state backup/version evidence, exact
resource identification, reviewed import configuration, a plan showing no
replacement or unrelated change, independent Identity/Security review, and
approved non-production validation. State adoption does not authorize existing
users or prove that their memberships are correct.

Immutable incompatibility uses blue/green migration. The old provider is
retained and disabled from new authority until the successor and every consumer
are validated. No automatic alias, email-domain, group, or customer-only claim
translation is permitted.

## Decommission and rollback

Follow the [bootstrap and retirement runbook](../operations/identity-bootstrap-retirement.md).
The safe default is retain-first:

- stop new issuance/provisioning;
- revoke or expire grants and sessions;
- preserve audit and retention obligations;
- move consumers only through a new reviewed contract;
- verify no consumer or rollback path depends on the old resource; and
- request a separate destructive approval if deletion is ever justified.

The normal Identity Apply role explicitly denies destructive identity,
storage, queue, key, Lambda, log, alarm, and secret operations. Its only delete
permission is scoped to the exact Terraform `.tflock` object. Decommission must
use a separate reviewed change identity and cannot be performed by this layer's
regular apply session.

Rollback is a new reviewed forward plan and routing decision. It never uses
manual state edits, automatic import, pool deletion, credential disclosure,
legacy claim fallback, or reduced protection.

## Deferred pre-live controls

These gates must be implemented and independently reviewed before the related
capability is enabled:

- **Human bootstrap:** GUG-94 must add recoverable claim leases, reconciliation,
  and an outcome-audit protocol that remains correct across crashes between
  provider effects, record consumption, and audit persistence.
- **M2M command authority:** no producer may receive `sqs:SendMessage` until its
  IAM identity is exact and reviewed, and the consumer reloads an authoritative
  approved provisioning record for the requested action set. The queue body is
  transport, never authority.
- **Existing-customer identity apply:** the identity root must reject execution
  without a reviewed `greenfield`, `adopted`, or `migration_required`
  disposition backed by a sanitized inventory digest. Adoption also requires a
  replacement-free plan.

The current human runtime remains disabled, no M2M command producer is granted
queue write authority, and no existing-customer apply is authorized. All three
controls are **Blocked/deferred**, not live-validated behavior.

## Validation

The following are offline, non-AWS checks:

```bash
.venv/bin/python -m pytest -q \
  backend/lambdas/scanalyze-identity-control-plane/tests
terraform -chdir=modules/identity-control-plane test -no-color
terraform -chdir=modules/edge-identity test -no-color
make schema-check
make gitops-orchestrator-check
make provider-check
make docs-check
```

Each result must be recorded as `PASSED`, `FAILED`, `SKIPPED`, or `BLOCKED` for
the exact revision. A skipped provider/live check is not a pass.

## Evidence status

| Evidence class | Current GUG-93 status | Boundary |
|---|---|---|
| **Implemented** | Candidate repository implementation exists in the GUG-93 branch | Requires review and merge before it is mainline evidence |
| **Locally validated** | Focused runtime tests passed in a Python 3.11 environment; remaining named gates must be reported with the final exact revision | No AWS/provider behavior |
| **CI validated** | Pending | Requires required checks on the exact PR commit |
| **Live validated** | **Blocked** | No AWS, Cognito, bootstrap, M2M credential, migration, adoption, decommission, or two-deployment execution authorized |
| **Production** | **NO-GO** | GUG-117 and later production gates remain open |

## Related sources

- [ADR-024](../../ADR/ADR-024-identity-control-plane-and-provider-boundary.md)
- [ADR-023](../../ADR/ADR-023-enterprise-authorization-and-user-lifecycle.md)
- [Enterprise authorization reference](enterprise-authorization.md)
- [M2M identity v2 migration](m2m-identity-v2-migration.md)
- [SSM contract reference](ssm-contracts.md)
- [Bootstrap and retirement runbook](../operations/identity-bootstrap-retirement.md)
- [Threat model](../production-readiness/threat-model.md)
