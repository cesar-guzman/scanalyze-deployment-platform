# ADR-024: Portable Identity Control Plane and Provider Boundary

- **Status:** Original decision accepted by merged GUG-93 PR; provider-
  compatibility amendment is a candidate pending review and merge
- **Date:** 2026-07-13
- **Scope:** GUG-93 Cognito, API Gateway identity handoff, Terraform ownership,
  bootstrap infrastructure, and runtime provider boundary
- **Phase gate:** GUG-117
- **Upstream decisions:** ADR-020, ADR-021, ADR-023
- **Downstream consumers:** services, edge identity, GUG-153 backend policy
  enforcement, GUG-94 lifecycle APIs, and GUG-95 UI/E2E
- **Live enablement:** Blocked pending CI, reviewed merge, approved
  non-production execution, migration review, and isolation evidence

Production: NO-GO

## GUG-94 bootstrap amendment

ADR-026 replaces the original effect-then-consume bootstrap ordering with
conditional `claimed -> effects_applied -> audit_committed -> consumed`
checkpoints. Stable provider and canonical membership references are persisted
before audit, and audit is persisted before one-use consumption. Exact retries
recover audit or consume outages without repeating provider/membership effects;
consumed requests deny replay. This is locally validated code and does not
enable human runtime or authorize a live provider operation.

## Post-merge provider compatibility amendment

Independent review after the original merge identified two repository-to-
provider contract mismatches. The release-manifest schema accepted a narrower
S3 object-version alphabet than the Terraform consumer, even though S3
VersionIds are opaque Unicode values and may contain URL-ready `+`, `/`, and
`=` characters. The candidate schema preserves Unicode, explicitly rejects the
unversioned `null` sentinel, and the Terraform module/root enforce the provider
limit of 1,024 UTF-8 bytes.

The Identity Apply policy originally permitted `PutMetricAlarm` but not the
tag reconciliation calls required by the tagged Terraform alarm resources.
The candidate statement now includes `ListTagsForResource`, `TagResource`, and
`UntagResource`, scoped to the existing exact
`${deployment_id}-identity-*` alarm ARN family. `DeleteAlarms` remains under
the explicit destructive-action deny. This amendment adds no wildcard action,
cross-deployment resource, live execution, or production authorization. This
amendment becomes accepted only after its own reviewed merge and main
verification.

## Context

ADR-023 defines a provider-neutral enterprise authorization policy. It does not
create an identity provider, membership store, token claim producer, bootstrap
channel, or Terraform handoff. The former deployment graph also placed services
before the provider contract they must consume, making a secure handoff
impossible without copied values or a circular dependency.

GUG-93 must realize the provider boundary without making Cognito groups,
Terraform state, request metadata, or a deployment-specific source fork an
authority. The same reviewed source must be usable for every customer,
deployment, account, and supported partition. Deployment-specific values enter
only through the authoritative deployment record and verified upstream
contracts.

The implementation must also account for properties that are difficult or
irreversible after provider creation:

- Cognito custom attributes cannot be made required and cannot be removed or
  changed after they are added;
- a client credential is sensitive at creation time and must never enter a
  Terraform plan, state, output, contract, log, or general evidence surface;
- a first-administrator bootstrap can create standing privilege if replay,
  expiry, approval, and audit are not enforced atomically; and
- deleting or replacing a user pool can strand users and break every downstream
  audience, issuer, session, and client binding.

## Security objectives

1. Bind one identity control plane to exactly one `customer_id`,
   `deployment_id`, account, region, policy version, policy digest, and release.
2. Issue authorization claims only from a current authoritative membership,
   never from provider group names or request-controlled metadata.
3. Permit only access tokens at protected APIs; ID tokens are not API
   credentials.
4. Keep human user creation out of Terraform and disable general-purpose human
   runtime provisioning.
5. Permit M2M client creation only through an idempotent runtime boundary that
   escrows the generated credential before returning non-sensitive references.
6. Make first-administrator bootstrap one-use, dual-approved, strongly
   authenticated, time-bound, conditionally consumed, and audited.
7. Fail closed for missing, malformed, stale, foreign, conflicting, legacy, or
   unavailable identity dependencies.
8. Preserve existing provider resources until adoption, migration, rollback,
   retention, and decommission evidence is independently approved.

## Decision

### 1. Add a dedicated identity control-plane layer

The canonical deployment sequence becomes:

```text
artifact-publication
  -> identity-control-plane
  -> services
  -> edge-identity
  -> edge
```

The layer owns provider resources, the authoritative membership and
authorization-audit stores, bootstrap transport, its encryption boundary, and a
versioned `identity-control-plane/v1` contract. It has an isolated Terraform
state key and dedicated Plan/Apply identities. Services consume the contract
before receiving identity environment configuration. Edge identity consumes
the same contract plus the services contract before configuring API audiences
and route scopes.

No consumer searches by resource name, reads another root's Terraform state, or
copies console values. Missing or mismatched producer contract, digest,
customer, deployment, account, region, release, or policy stops the consumer.

### 2. Use one portable deployment binding

Every module, root, contract, runtime configuration, and consumer binds the
same tuple:

```text
customer_id
deployment_id
account_id
region
```

The customer and deployment identifiers are distinct immutable values from the
deployment registry. Account and region bind the provider instance, but do not
replace customer or deployment authorization. The policy source contains no
customer, account, region, pool, client, domain, email, or resource instance.

The identity layer also binds:

- the reviewed release and release-manifest digest;
- the reviewed external `identity-contract/v2` M2M registry digest;
- `enterprise-authorization.v1`;
- `enterprise-roles.v1`;
- `scanalyze.api.v1`;
- the reviewed policy version; and
- the RFC 8785 canonical policy digest.

An unknown or future version does not become current automatically. Digest
comparison is exact; request-provided digests are non-authoritative.

### 3. Cognito is an authentication adapter, not the policy authority

Each deployment receives a dedicated user pool. Self-signup is disabled,
deletion protection is enabled, token revocation is enabled, callback/logout
URLs are exact HTTPS values, and the pool uses immutable custom attributes for
the canonical customer and deployment identifiers.

The source creates the closed human role group names only as provider mapping
and operator visibility. `cognito:groups`, group precedence, display names,
email domains, client metadata, and user-supplied attributes are never
authorization authority. The authoritative membership store remains the source
of subject, role, state, customer, deployment, membership version, catalog
versions, policy version, and policy digest.

A V2 pre-token generation processor:

1. accepts only a reviewed pool, client, event version, and supported human
   token-generation event;
2. validates immutable provider bindings against deployment configuration;
3. loads exactly one membership by subject, customer, and deployment;
4. requires an active membership and current supported versions;
5. suppresses provider group and IAM-role claims;
6. adds only canonical access-token authorization claims; and
7. records a sanitized allow or denial without raw identity values or claims.

Dependency timeout or an unavailable audit dependency fails closed. M2M client
credentials do not use provider group or human membership paths.

GUG-93 deliberately deploys the human hook with `HUMAN_RUNTIME_ENABLED=false`,
an empty client allowlist, and the explicit `USER_POOL_ID=UNBOUND` sentinel.
This is required because a new pool depends on its trigger alias while a Lambda
environment that referenced that same generated pool/client would create a
Terraform dependency cycle. The disabled gate runs before provider input or a
membership read. GUG-153/GUG-94 must perform a separate reviewed promotion that
binds the generated pool and SPA client before human issuance or bootstrap can
be enabled.

### 4. Protected APIs are access-token-only

The canonical action scopes remain:

| Action | Scope |
|---|---|
| `read` | `scanalyze.api.v1/read` |
| `write` | `scanalyze.api.v1/write` |
| `admin` | `scanalyze.api.v1/admin` |

API Gateway audiences include only the exact reviewed SPA and runtime-created
M2M client identifiers supplied by the identity contract. Each protected route
declares its required scope. The default route is disabled. `X-Tenant-ID`,
payload customer/deployment fields, legacy tenant aliases, and request-supplied
client identifiers cannot create authority.

API Gateway token validation is necessary but not sufficient. GUG-153 remains
responsible for fresh membership/grant evaluation, exact object authorization,
deny precedence, and sensitive-operation enforcement. An ID token, a valid
scope without a current grant, or an API-authorizer success alone never
authorizes an application operation.

### 5. Human provisioning is outside Terraform

Terraform never declares provider users, passwords, invitation values, MFA
material, memberships, or live group assignments. General human runtime
provisioning is disabled, and the GUG-93 runtime denies bootstrap commands
before loading their authoritative record. GUG-94 will own reviewed invitation,
activation, role change, suspension, revocation, and session-revocation APIs.

The bounded bootstrap workflow described below is a composed, locally tested
future primitive, not an enabled GUG-93 exception. Enabling it requires the
separate reviewed lifecycle promotion and does not create a standing platform
administrator.

### 6. Future first-administrator bootstrap is a one-use state machine

A bootstrap record is authoritative only when all of the following are true:

- it uses the supported version and exact subject/customer/deployment binding;
- it targets the reviewed initial role and current policy/catalog versions;
- two distinct approvers approved the same request;
- neither approver is the target subject;
- approvals are bound to the same customer, deployment, request, and current
  authentication assurance;
- the request lifetime is no more than 900 seconds and it is not expired;
- an idempotency key is present; and
- the record is still in the expected approved version/state.

Processing uses a conditional claim, idempotent provider effect, idempotent
membership creation, and conditional consume. A concurrent claim, replay,
expiry, stale version, dependency timeout, or consume conflict denies. A retry
uses the same trusted idempotency key; it cannot create a second principal or
membership.

The SQS consumer reports partial batch failures by the original message
identifier and never logs message bodies. Poison messages remain on the exact
source/DLQ path. Redrive is a separately authorized recovery operation; GUG-93
does not perform it.

Temporary enrollment values returned by a provider adapter are never returned
by the processor, written to audit, or logged. Delivery/enrollment remains an
approved provider workflow owned by GUG-94.

The composed bootstrap code currently consumes the record before emitting its
final required allow audit. Because the path is disabled and lacks human
provider permissions, this creates no reachable GUG-93 execution. GUG-94 must
add an independently reviewed, recoverable outcome-audit protocol before any
bootstrap enablement; an operator may not treat the current primitive as live.

### 7. M2M credentials use runtime creation and immediate escrow

Terraform may define non-sensitive M2M policy and contract structure, but it
must not create or export a generated client credential. A generated value in a
Terraform resource remains sensitive even when an output is marked sensitive;
therefore it is prohibited from plans and state entirely.

The M2M runtime provisioner accepts only an internal, reviewed command bound to
one workload, environment, customer, deployment, closed action set, and
idempotency key. Its dependency boundary is:

```text
conditional binding claim
  -> idempotent provider client creation
  -> immediate credential escrow in the approved secret store
  -> conditional workload binding completion
  -> sanitized audit
  -> return client ID and secret reference only
```

The raw credential exists only inside the provider-to-secret-store adapter
call. It is never returned, logged, audited, added to a contract, placed in
Terraform, or published as CI evidence. An idempotent replay returns existing
non-sensitive references only after exact binding comparison. A conflicting
replay, unsupported action, human principal, foreign binding, provider timeout,
secret-store timeout, or conditional-write conflict denies.

An in-progress binding has a 300-second lease, which is longer than the
control-processor runtime timeout. A retry may recover only an expired lease by
atomically replacing the prior claim token while the exact timestamp, workload,
environment, customer, deployment, and action set remain unchanged. A fresh
lease or failed compare-and-swap denies before a provider call. Credential
readback also requires the exact secret name/ARN, deployment KMS key, tags,
current version, and absence of pending deletion.

Live provider and secret-store adapters, client rotation, delivery, and
revocation require separate approved non-production evidence. Repository code
does not prove those behaviors.

The initial published M2M registry is allowed to be empty. A runtime-created
client does not become authority automatically: its sanitized binding must be
reconciled into `identity-contract/v2`, independently reviewed, and republished
as a new digest. Only a subsequent services/edge plan may add that exact client
to backend bindings and JWT audiences. Until that promotion, the client remains
inactive at application boundaries.

### 8. Contract publication contains identifiers, never credentials

`identity-control-plane/v1` may publish only values required by downstream
validation, including:

- exact customer/deployment/account/region and contract identity;
- provider issuer, user-pool identifier, and public client identifiers;
- resource-server identifier and action scopes;
- access-token-only and provider-group-non-authoritative restrictions;
- claim names and supported policy/catalog versions;
- contract and source digests.

It must never publish client credentials, passwords, invitation values, tokens,
cookies, MFA values, raw claims, user inventories, group memberships, recovery
material, or customer data. The contract envelope's digest protects content;
IAM and the deployment registry establish writer authority.

### 9. IAM and observability remain purpose-specific

Identity Plan and Apply use dedicated terminal roles. The pre-token runtime may
read one exact membership, append one sanitized audit event, use only its
approved encryption boundary, and write only its dedicated operational log
stream. Bootstrap and M2M adapters receive separate permissions matched to
their specific stores and provider operations; they do not inherit broad
identity administration.

Operational logs contain stable reason codes and aggregate outcomes only. Audit
records contain opaque references and policy/version evidence, never raw
claims, user attributes, tokens, enrollment values, message bodies, or provider
responses. Alarm existence is repository configuration until live notification
delivery and response are exercised.

### 10. Legacy resources are denied, inventoried, and adopted explicitly

GUG-93 performs no live discovery, import, upgrade, user migration, or deletion.
A separately authorized report-only inventory classifies each existing pool,
client, membership source, and state relationship:

| Class | Meaning | Default treatment |
|---|---|---|
| Fully bound and compatible | Exact tuple, current schema/policy, known owner, and no state conflict | Candidate for reviewed state adoption |
| Partially bound | One or more canonical binding/version fields are absent | Deny and quarantine |
| Ambiguous/shared | More than one customer/deployment or conflicting candidate exists | Deny and quarantine; no inferred winner |
| Provider-only | Resource exists but no authoritative membership/contract/state ownership is proven | Deny and investigate |
| State-only/orphaned | State refers to missing or unverifiable provider resources | Stop and reconcile under recovery controls |
| Immutable-schema incompatible | Existing pool cannot represent required immutable attributes safely | Retain; use reviewed blue/green migration |
| Inconsistent | Provider, membership, contract, registry, or state disagree | Deny and quarantine |

State adoption is allowed only for an exactly identified compatible resource,
under a reviewed import block or equivalent versioned procedure, after backup,
read-only inventory, ownership proof, a replacement-free plan, independent
review, and non-production validation. An import is not migration proof and does
not authorize user access.

If immutable provider schema or binding is incompatible, create a new isolated
pool and execute a separately approved blue/green user migration. Never copy
authority from an email domain, group name, current account, pool name, or
legacy customer-only claim.

### 11. Decommission is retain-first

Identity resources default to retention and deletion protection. Retirement
first disables new issuance and traffic, revokes or expires sessions and
grants, waits through the approved retention window, verifies that every
consumer uses the successor contract, preserves required audit evidence, and
proves rollback no longer depends on the old resource.

Only a separate destructive change with data-owner, Security, Operations, and
required production approval may remove retained resources. Removing a
Terraform state address, disabling deletion protection, deleting a pool,
destroying an audit table, deleting a credential, or shortening retention is
never an automatic rollback action.

The ordinary Identity Apply role therefore has an explicit deny for identity
resource deletion, queue purge, key disable/scheduled deletion, Lambda
permission removal, and monitoring/retention deletion. Its sole delete
exception is the exact Terraform `.tflock` object required to release a state
lock. A future decommission must use a separate reviewed role/change identity;
it cannot widen or reuse the regular apply session.

## Alternatives rejected

### Keep identity inside `edge-identity`

Rejected because services require the provider contract before edge identity,
and API ownership should not own membership/bootstrap data or provider users.

### Authorize from Cognito groups

Rejected because tokens can contain multiple groups and group precedence is an
IAM-role selection feature, not the Scanalyze role/membership policy. Group
display names also cannot carry freshness, customer/deployment, policy digest,
or lifecycle state safely.

### Create humans or M2M credentials in Terraform

Rejected because user lifecycle is operational state and generated credentials
would enter plans/state. Marking an output sensitive prevents display but does
not remove the value from state.

### Accept ID tokens when scopes appear valid

Rejected because ID tokens identify a user to a client application; they are
not access authorization for Scanalyze APIs.

### Infer legacy ownership and import automatically

Rejected because naming, account proximity, email domains, pool membership, and
group names are ambiguous and can silently cross a customer/deployment
boundary.

## Consequences

### Positive

- one source implementation is portable across customers and accounts;
- downstream consumers receive a versioned fail-closed contract before use;
- human membership remains current and independently auditable;
- provider groups cannot silently elevate authorization;
- M2M credentials remain outside Terraform and general evidence; and
- bootstrap, migration, retirement, and rollback have explicit stop rules.

### Costs and limitations

- the deployment graph gains a stateful security-critical layer;
- provider schema changes require careful blue/green migration;
- runtime adapters and authoritative stores must be highly available or token
  issuance fails closed;
- bootstrap and M2M provisioning require conditional stores and recovery logic;
- phishing-resistant privileged flows require downstream GUG-94/GUG-153 work;
  and
- live create/upgrade/adoption/decommission evidence remains unavailable until
  explicitly authorized.

### Deferred pre-live controls

The following controls are deliberate enablement blockers, not accepted live
risk:

1. GUG-94 must add a recoverable lease/CAS and outcome-audit protocol to the
   first-administrator bootstrap before human runtime can be enabled. A crash
   after claim or consume must be reconcilable without replaying authority or
   losing the final audit outcome.
2. Before any principal receives `sqs:SendMessage` to the M2M provisioning
   queue, the command must be produced by one exact reviewed IAM identity and
   the consumer must bind requested actions to an authoritative approved
   provisioning record, not trust the message body as authority.
3. Before `roots/identity-control-plane` can be applied to an account with any
   pre-existing identity resource, it must require a reviewed disposition of
   `greenfield`, `adopted`, or `migration_required`, backed by a sanitized
   inventory digest. `adopted` additionally requires a replacement-free plan.

Until these controls and their tests/evidence exist, bootstrap enablement, M2M
command production, and identity apply for an existing customer remain
**Blocked**.

## Rollback boundary

Before any apply, rollback is withdrawal of the candidate change. After a
non-production apply, identity rollback is a new reviewed forward plan; it does
not restore state, delete the new pool, or re-enable legacy claims.

For a blue/green migration, keep the prior pool and contract disabled-but-
recoverable until successor issuance, consumers, revocation, and isolation are
validated. On failure, stop new issuance, restore routing only to the last
reviewed compatible contract, revoke affected sessions, and reconcile state
with a new plan. If an outcome is unknown, preserve both resources and stop.

## Evidence classification

| Classification | GUG-93 meaning |
|---|---|
| **Implemented** | The exact reviewed revision contains the layer, runtime, contracts, tests, ADR, references, and runbook. This is repository evidence only. |
| **Locally validated** | Named offline Python, schema, Terraform mock, security, DAG, and repository gates pass for the exact revision without AWS credentials. |
| **CI validated** | Required PR checks pass for the exact commit. It is not provider or account evidence. |
| **Live validated** | An explicitly authorized non-production change proves create/upgrade/bootstrap/M2M/consumer/rollback behavior for one exact tuple and separately proves isolation from a second tuple. |
| **Blocked** | AWS/Cognito execution, legacy inventory, state adoption, migration, bootstrap, M2M credential creation/rotation, decommission, and production remain blocked without separate authority and evidence. |

No live validation was performed by GUG-93 repository work. Production remains
**NO-GO**.

## Related sources

- [Enterprise authorization decision](ADR-023-enterprise-authorization-and-user-lifecycle.md)
- [Identity control-plane reference](../docs/deployment/identity-control-plane.md)
- [Bootstrap and retirement runbook](../docs/operations/identity-bootstrap-retirement.md)
- [SSM contracts](../docs/deployment/ssm-contracts.md)
- [Production-readiness threat model](../docs/production-readiness/threat-model.md)
- [AWS Cognito pre-token generation](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html)
- [AWS API Gateway JWT authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html)
- [AWS S3 versioning workflows](https://docs.aws.amazon.com/AmazonS3/latest/userguide/versioning-workflows.html)
- [AWS CloudWatch PutMetricAlarm](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html)
