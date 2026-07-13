# GUG-93 — Portable Identity Control Plane and Provider Boundary

> **Sanitized source for NotebookLM**\
> **Canonical decision:** ADR-024\
> **Repository scope:** Terraform, contracts, runtime primitives, tests, and
> documentation\
> **CI:** Pending for the exact PR commit\
> **Live validation:** Blocked\
> **Production:** NO-GO

## Why this package exists

GUG-92 defined portable enterprise authorization, but a policy document cannot
issue a safe token or provide a provider contract to services. GUG-93 introduces
a dedicated identity control-plane stage between artifact publication and
services. It owns provider infrastructure, authoritative membership/audit
storage, a bounded bootstrap transport, access-token claim production, and the
non-sensitive contract consumed by services and edge identity.

The same source works for every customer and dedicated account. Customer,
deployment, account, region, release, and policy values come from authoritative
external bindings at deployment time. There are no customer-specific source
forks or embedded provider identifiers.

## Canonical deployment sequence

```text
artifact-publication
  -> identity-control-plane
  -> services
  -> edge-identity
  -> edge
```

The identity stage consumes the exact global contract, immutable release
manifest, and reviewed external `identity-contract/v2` workload registry. The
release manifest binds separate pre-token and control-processor artifacts by
bucket, key, immutable object version, and source-code digest. Services then
consume `identity-control-plane/v1`. Edge identity consumes both the services
and identity contracts before configuring protected API audiences and route
scopes.

No layer reads another layer's Terraform state, discovers resources by name, or
uses copied console values. A missing, stale, foreign, or mismatched contract
blocks the consumer.

## Exact portable binding

Every control-plane and consumer decision binds:

- one customer;
- one deployment;
- one dedicated account;
- one region;
- one immutable release;
- one supported authorization/role/scope catalog set; and
- one reviewed policy version and canonical digest.

Customer and deployment remain different concepts. An account or user pool does
not replace either value. A request field, provider group, email domain, legacy
tenant alias, resource name, or current account cannot infer a missing binding.

## Provider groups are non-authoritative

The provider may contain the closed role group names for mapping and operator
visibility. They do not establish authorization. A token can contain multiple
provider groups, and group precedence is not the Scanalyze enterprise policy.

The authoritative membership store supplies the exact:

- subject and principal type;
- customer and deployment;
- active membership state;
- single role;
- membership version;
- authorization, role, and scope catalog versions; and
- policy version and digest.

The pre-token processor suppresses provider group/IAM-role claims and adds the
canonical access claims from that membership only. A provider group, client
metadata field, or user-supplied claim cannot elevate the membership.

## Access-token-only API authorization

Protected APIs accept access tokens only. ID tokens identify a user to a client
application and are not Scanalyze API credentials.

The action scopes are exactly:

| Action | Scope |
|---|---|
| `read` | `scanalyze.api.v1/read` |
| `write` | `scanalyze.api.v1/write` |
| `admin` | `scanalyze.api.v1/admin` |

API Gateway validates the exact issuer, audience, token type, and required route
scope. That is not a complete authorization decision. The backend still checks
the current grant, deny precedence, customer/deployment, object ownership, and
sensitive-operation policy. GUG-153 owns that backend enforcement.

There is no default route, ID-token fallback, legacy tenant header, or request-
supplied audience fallback.

## Pre-token fail-closed behavior

The V2 human pre-token processor accepts only a reviewed pool, client, event
version, and supported event type. It validates immutable provider attributes
against the configured deployment, then loads one exact membership.

It denies:

- missing or malformed subject/customer/deployment;
- a foreign or conflicting binding;
- a missing, inactive, suspended, expired, or revoked membership;
- an unknown role or principal type;
- a stale membership, catalog, policy version, or digest;
- an unsupported provider event/client/pool;
- a membership dependency timeout; or
- an unavailable required audit dependency.

GUG-93 deploys the human path inactive with
`HUMAN_RUNTIME_ENABLED=false`, `USER_POOL_ID=UNBOUND`, and an empty client
allowlist. The gate denies before provider-event parsing or membership access.
Binding the generated pool and SPA client and enabling issuance requires a
separate reviewed GUG-153/GUG-94 promotion.

Logs and audit contain stable reason categories and opaque references only. Raw
claims, attributes, tokens, identities, and dependency exceptions are not
included.

## Human provisioning boundary

Terraform never manages users, passwords, MFA values, invitations, memberships,
or group assignments. General human runtime provisioning and self-signup are
disabled.

The first-administrator state machine is a composed, locally tested future
primitive. GUG-93 denies it before request lookup or provider/membership effects;
it becomes eligible for non-production use only through GUG-94's reviewed
lifecycle workflow. It does not create a shared platform administrator or a
general create-user API.

## One-use bootstrap

A valid bootstrap request:

- binds an exact target subject, customer, and deployment;
- has exactly two independent approvers;
- forbids target self-approval;
- uses current phishing-resistant assurance;
- expires within 900 seconds;
- carries current policy/catalog versions and digest;
- uses a trusted idempotency key;
- is conditionally claimed at its expected version; and
- is conditionally consumed only after idempotent provider and membership
  effects succeed.

Replay, expiry, stale state, concurrent claim, partial/conflicting binding,
unsupported role, timeout, or consume conflict denies. SQS partial batch failure
reporting retries only failed identifiers. Message bodies are never logged and
DLQ redrive is not authorized by GUG-93.

Provider enrollment values are not returned or audited. Enrollment and later
human lifecycle administration remain GUG-94 responsibilities.

## M2M runtime provisioning and credential custody

Generated M2M credentials are prohibited from Terraform. Marking a Terraform
output sensitive would still leave the value in state, so the identity module
does not create or export the credential.

The runtime provisioner:

1. validates a machine-only workload/environment/customer/deployment/action
   binding;
2. acquires a conditional idempotency claim;
3. calls an idempotent provider adapter with the exact scope set;
4. immediately stores the generated credential in the approved credential
   store;
5. conditionally completes the workload binding;
6. emits sanitized audit; and
7. returns only a public client identifier and credential reference.

The credential is never returned, logged, audited, contracted, placed in
Terraform/state, or published as CI evidence. An exact idempotent replay returns
existing non-sensitive references. A conflicting replay or dependency failure
denies.

An in-progress claim has a 300-second lease, longer than the processor timeout.
Only an expired lease can be atomically reacquired with an exact prior-token,
timestamp, workload, environment, customer, deployment, and action-set CAS.
Custody readback must prove the exact secret name/ARN, deployment KMS key,
binding tags, current idempotent version, and no scheduled deletion.

Live provider/credential-store adapters, rotation, delivery, and revocation are
not proven by repository tests and remain blocked.

A runtime-created client is not application authority. Its sanitized exact
binding must be reconciled into `identity-contract/v2`, independently reviewed,
and republished under a new digest. Only a subsequent identity, services, and
edge plan may add that client to backend bindings and JWT audiences. The initial
registry is intentionally empty.

## Contract boundary

`identity-control-plane/v1` carries only non-sensitive integration information:

- exact deployment tuple and contract identity;
- issuer and public provider/client identifiers;
- access-token-only restriction;
- canonical claims, action scopes, action scope sets, versions, and policy
  digest;
- exact M2M client-list/binding equality for the current customer/deployment;
  and
- provider-groups-are-not-authority restriction.

It never carries a client credential, password, invitation value, token,
membership/user list, raw claim, MFA material, provider response, state, or plan.
SSM publication is live behavior and remains blocked.

## Legacy quarantine and migration

GUG-93 performs no live inventory or migration. A future report-only inventory
classifies resources as:

- fully bound and compatible;
- partially bound;
- ambiguous/shared;
- provider-only/unmanaged;
- state-only/orphaned;
- immutable-schema incompatible; or
- inconsistent.

Only a fully bound compatible resource may be considered for reviewed state
adoption. Adoption requires exact ownership proof, protected state backup,
versioned import configuration, a replacement-free plan, independent review,
and non-production validation. Import does not authorize existing users.

An incompatible immutable provider schema requires blue/green migration. The
old provider is retained until successor token issuance, memberships,
consumers, revocation, and two-deployment isolation are validated. There is no
automatic group, domain, account, pool-name, or legacy-claim inference.

## Retain-first retirement

Identity deletion is never rollback. Retirement proceeds by:

1. freezing new provisioning and authority expansion;
2. revoking/expiring sessions, grants, bootstrap requests, and old clients;
3. moving every consumer through reviewed contracts;
4. waiting through approved token, retry, queue, audit, and customer retention;
5. proving that no active or rollback path depends on the old resources;
6. retaining protected audit/state evidence; and
7. requesting a separate destructive approval if deletion is justified.

`prevent_destroy`, deletion protection, and retention are not disabled simply
to obtain a green plan.

The normal Identity Apply role also explicitly denies destructive operations
across Cognito, DynamoDB, SQS, Lambda, IAM, KMS, Secrets Manager, logs, and
alarms. Only deletion of the exact Terraform `.tflock` object is allowed for
state-lock release. A destructive decommission requires a separate reviewed
change identity.

## Deferred pre-live controls

Three controls remain explicit enablement blockers:

1. GUG-94 must add a recoverable bootstrap claim lease, reconciliation, and
   outcome-audit protocol before human runtime is enabled.
2. No identity may receive `sqs:SendMessage` to the M2M provisioning queue until
   it is an exact reviewed producer and the consumer reloads an authoritative
   approved provisioning record. A command body never establishes authority.
3. Before identity apply for an existing customer, the identity root must
   require a reviewed `greenfield`, `adopted`, or `migration_required`
   disposition backed by a sanitized inventory digest; adoption also requires
   replacement-free plan evidence.

These are **Blocked/deferred**. They are not locally or live validated behavior,
and none authorizes AWS execution.

## Evidence taxonomy for GUG-93

| State | Meaning |
|---|---|
| **Implemented** | The reviewed revision contains the identity layer, runtime, contracts, tests, ADR, deployment reference, and retirement runbook. It is repository evidence only. |
| **Locally validated** | Named offline tests pass without AWS credentials for the exact revision. It does not prove provider behavior. |
| **CI validated** | Required PR checks pass for the exact commit. Current status remains pending until that evidence exists. |
| **Live validated** | Explicitly authorized non-production evidence proves provider creation/upgrade, token claims, bootstrap, M2M credential custody, consumers, rollback, and two-deployment isolation. No such evidence exists here. |
| **Blocked** | AWS/Cognito execution, migration, state adoption, bootstrap, M2M credential operations, decommission, and production remain blocked. |

Production remains **NO-GO**.

## Fail-closed questions and answers

### Does a Cognito group authorize a Scanalyze role?

No. Provider groups are non-authoritative. The current exact membership record
establishes the role and versions.

### Can an ID token call the API?

No. Protected APIs require an access token, exact audience, and route scope,
followed by backend authorization.

### Can Terraform create or output an M2M client credential?

No. Generated credential values must never enter a plan, state, output, or
contract. Runtime creation escrows the value and returns only references.

### Can any authenticated administrator bootstrap the first administrator?

No. The request must be exact, one-use, dual-approved, non-self-approved,
strongly authenticated, current, conditionally claimed/consumed, and audited.

### Can a bootstrap queue message establish authority by itself?

No. The processor reloads and validates the authoritative record. Missing or
conflicting state denies.

### Can an old provider be imported because its name looks correct?

No. State adoption requires exact ownership/binding proof and a replacement-
free reviewed plan. Ambiguous or incompatible resources remain quarantined.

### Is deleting the old provider a rollback?

No. Identity rollback is a reviewed forward contract/plan transition. Old
resources are retained until migration, revocation, retention, and successor
evidence are complete.

### Do local tests or CI prove Cognito behavior?

No. Local tests establish only repository behavior. CI establishes only the
identified commit/workflow. Live behavior requires separately authorized
non-production evidence.

### Is GUG-93 production-ready after repository implementation?

No. Live provider execution, migration, lifecycle APIs, backend enforcement,
two-deployment isolation, and later phase gates remain blocked. Production is
**NO-GO**.

## Sanitization boundary

NotebookLM may ingest this file only. Do not ingest provider exports, user or
group lists, addresses, live identifiers, credentials, tokens, enrollment/MFA
material, Terraform state/plans, logs, screenshots, raw audit records, approval
artifacts, or customer data. Unknown values remain `Unknown` or `Blocked`; they
are never inferred.

## Canonical sources

- [ADR-024](../ADR/ADR-024-identity-control-plane-and-provider-boundary.md)
- [Identity control-plane reference](../docs/deployment/identity-control-plane.md)
- [Bootstrap and retirement runbook](../docs/operations/identity-bootstrap-retirement.md)
- [ADR-023](../ADR/ADR-023-enterprise-authorization-and-user-lifecycle.md)
- [Threat model](../docs/production-readiness/threat-model.md)

This source explains those documents. It does not override them or store live
evidence.
