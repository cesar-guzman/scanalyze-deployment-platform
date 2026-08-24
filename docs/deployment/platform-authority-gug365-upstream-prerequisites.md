# GUG-376 upstream prerequisites for GUG-365

## Status and scope

This document defines the closed-world contract for the non-production inputs
that GUG-365 consumes. GUG-376 v1 remains the fail-closed source-gap checkpoint.
GUG-377 adds repository-only inventory, plan and final-handoff v2 contracts and
a deterministic materializer that can exercise them only through inert or
scripted adapters. It is not a deployed materializer.

GUG-384 separately implements the authority-account policy/render, typed
capture, exact-target-bound double-snapshot certification and digest-only public receipt. Its
checked-in CLI supplies no live provider factory, does not collect the Identity
Center surfaces and does not alter the existing nine-surface envelope.

This PR performs no AWS call or provider/package-registry network operation,
creates no private root or live artifact and grants no mutation authority.
Production remains **NO-GO**.

GUG-376 owns the upstream foundation and signing handoff only. It excludes the
GUG-365 bundle, GUG-357 `CreateStack`, GUG-215 broker invocation or Change Set
effect, GUG-206 execution, Terraform state operations and customer resources.

## Authoritative repository inputs

The v2 repository compiler derives every fixed field from an exact clean
reviewed source commit and these existing contracts:

- [GUG-363 intent schema](../../schemas/platform-authority-retirement-entrypoint-intent.v1.schema.json);
- [GUG-363 plan schema](../../schemas/platform-authority-retirement-entrypoint-plan.v1.schema.json);
- [GUG-215 package manifest schema](../../schemas/platform-authority-change-set-retirement-package-manifest.v1.schema.json);
- [GUG-365 ledger-factory package schema](../../schemas/platform-authority-retirement-ledger-factory-package.v1.schema.json);
- [GUG-365 service-role plan schema](../../schemas/platform-authority-retirement-entrypoint-service-role-plan.v1.schema.json);
- [classifier source policy](../../policies/iam/platform-authority-change-set-retirement-classifier-role.json);
- [approver source policy](../../policies/iam/platform-authority-change-set-retirement-role.json); and
- [application actor policy](../../policies/iam/platform-authority-identity-enhanced-application-actor-policy.json).

No private intent, profile label or environment variable may override fixed
account, Region, permission-set names, policy templates, object-key patterns,
runtime, architecture, authorization mode or evidence flags.

## Private upstream plan

The canonical upstream plan is owner-only and has `additionalProperties=false`
semantics. At minimum it binds:

| Projection | Required contents |
|---|---|
| Source | Exact head, merge, tree, clean-checkout evidence and every referenced source digest |
| Ownership | GUG-376 producer, GUG-365 consumer, one upstream run and original GUG-365 run/gap digests |
| Target | Non-production authority binding and `us-east-1`, represented publicly only by reviewed digests |
| Owner decisions | Approved decision-record digest and the exact selected values inside private custody |
| Runtime | Pre-existing Lambda-version evidence digest and exact Python 3.12 runtime-version ARN |
| Identity Center | Instance/store/user private bindings, application and permission-set contracts, assignment/provisioning contracts and same-user invariant |
| Supply chain | KMS, bucket, Signer, CSC, both package manifests and complete signing contracts |
| Phase graph | Exactly nine ordered phases, each complete ordered operation list and causal predecessor |
| Authority | One executor-policy digest per operation and one still-unapproved authorization template per exact executable request batch |
| Recovery | Private ledger root digest, one-attempt contract and rollback/revocation boundary per operation |
| Handoff | Expected GUG-363 intent/plan and ledger-factory signing-contract outputs; never GUG-365 plan output |

The plan always states `deployment_authorized=false` and `production=false`.
Its digest proves integrity, not permission.

Read-only discovery is closed by the reviewed authority-account and management
boundary templates in
`policies/iam/platform-authority-gug376-authority-inventory-read-only.json`
and
`policies/iam/platform-authority-gug376-identity-center-inventory-read-only.json`.
Their rendered digests are private plan inputs; neither policy can authorize a
phase mutation.

## Owner decisions

Values that are not fixed by current source are unavailable until a separate
private `OWNER_DECISIONS_REQUIRED` record is approved by digest. Candidate
fields include:

- globally unique S3 bucket name;
- KMS alias permitted by the future schema;
- AWS Signer profile name;
- Identity Center application label;
- exact loopback redirect URI permitted by the GUG-363 intent schema; and
- an approved pre-existing Lambda function/version as the runtime evidence
  source.

For each field the record includes the source constraint, proposed value,
stable collision/no-touch snapshots, impact, revocation boundary and digest.
Approval never authorizes AWS activity.

## Provider-generated slot contract

The upstream plan cannot know identifiers that AWS returns only after a create
request. It represents them as typed slots rather than placeholders or
free-form strings.

| Slot family | Producer | Validation and consumers |
|---|---|---|
| `identity.application_arn` | Exact application create operation | Must match the source-constrained application ARN form; consumed by application configuration, both policies and GUG-363 |
| `identity.classifier_permission_set_arn` / `identity.approver_permission_set_arn` | Their distinct create operations | Names are fixed; ARNs feed assignments, provisioning and policy/readback bindings |
| `identity.*_assignment_request_id` / `identity.*_provision_request_id` | Exact asynchronous assignment/provision operations | Terminal success must be polled read-only; consumed only by causal receipts |
| `identity.*_role_arn` | Identity Center provisioning | Must match the exact `AWSReservedSSO_<fixed-name>_<16-hex>` form and complete IAM readback |
| `kms.key_arn` | Exact key create operation | Exact authority account/Region key ARN; consumed by alias, bucket encryption/policy and all object writes |
| `signer.profile_version_id` / `signer.profile_version_arn` | Exact signing-profile create operation | One immutable active version on `AWSLambda-SHA384-ECDSA`; consumed by CSC and both jobs |
| `lambda.code_signing_config_arn` | Exact CSC create operation | `Enforce` and one allowed publisher; consumed by both signing contracts |
| `broker.unsigned_version_id` / `factory.unsigned_version_id` | Their distinct `PutObject` calls | Exact key, KMS, checksum, size and manifest bytes; consumed by one matching job each |
| `broker.job_id` / `factory.job_id` | Their distinct Signer start calls | UUID, terminal `Succeeded`, correct owner/invoker/platform/profile and source |
| `broker.signed_key` / `broker.signed_version_id` | Broker Signer output | Exact same bucket/KMS, schema-constrained signed key, distinct from every source/factory object |
| `factory.signed_key` / `factory.signed_version_id` | Factory Signer output | Exact same bucket/KMS, schema-constrained signed key, distinct from every other object |

Every public slot record contains the slot name, exact producer action and
phase/sequence, canonical request/response/readback digests, the two approved
JSON Pointer field paths, the two projection digests, resolved-value digest,
external transcript-verification digest and prior certification digest where
the consumer is cross-phase. The raw value is transient and is never persisted
in a public record. It is written once with CAS semantics.

A slot cannot be resolved from a plan parameter, fixture, log line, eventual
list result or unmatched pre-existing resource. When a response is lost,
read-only reconciliation must prove one unique causal target. Otherwise the
slot remains unresolved and all consumers fail closed.

`runtime.runtime_version_arn` remains a future read-only provider fact; no
GUG-377 operation may produce it. Inventory v2 contains a closed synthetic
before-state and target-state projection, with provider/runtime/private-root
proof explicitly `NOT_PROVEN`. It permits the repository to validate exact
account/Region, Python 3.12, published-version and manual-management constraints
without accepting a copied ARN or claiming a provider observation.

The original exported GUG-376 runner and every v1 public mutation builder remain
unchanged STOP shims. They continue to return
`STOP_UPSTREAM_SOURCE_CONTRACT_GAP`, preserving the five v1 contracts and their
fixtures as regression evidence.

GUG-377's separate repository materializer closes the missing source model with:

- inventory, plan and final-handoff v2 records;
- one typed `ProviderAdapter` protocol with no generic
  `execute(action, payload)` escape hatch;
- an inert default adapter and deterministic scripted test adapter;
- typed response/readback projections for generated identifiers;
- closed asynchronous statuses and bounded polling with injected clock/sleeper;
- one-attempt CAS ordering and `UNCERTAIN_RECONCILE_ONLY`; and
- separate completion, rollback/revocation and handoff packages.

The scripted adapter performs only in-memory synthetic events. The default
adapter performs nothing. No live provider adapter can be constructed; every
attempted live promotion stops with
`STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED` before credentials, client creation,
private ledger access or a provider call.

## Runtime evidence contract

The selected source is an owner-approved, pre-existing, published Lambda
version in the authority account and `us-east-1`. A future read-only collector
uses the equivalent of `GetFunctionConfiguration` and
`GetRuntimeManagementConfig` twice, with complete pagination where applicable,
and requires stable equality for:

- exact function and published qualifier;
- `Runtime=python3.12`;
- architecture `x86_64`;
- `UpdateRuntimeOn=Manual`; and
- the same non-empty `RuntimeVersionArn`.

The collector binds normalized provider facts and the source-provenance record
to one evidence digest. It must never create or update a function to obtain the
value. `$LATEST`, auto-updated runtime state, a copied ARN or a synthetic fixture
causes `STOP_RUNTIME_PIN_SOURCE_NOT_PROVEN`.

## Identity Center target contract

### Application

The application record fixes its provider, label, exact loopback redirect,
authorization-code/PKCE authentication method, grant, access scope
`sts:identity_context`, assignment configuration and application actor policy.
Only the one approved immutable UserId is assigned. Any group, second user,
extra grant, scope, redirect, actor or unmanaged setting is drift.

### Permission sets and assignments

The permission sets are exactly:

```text
ScanalyzeAuthorityRetireClass
ScanalyzeAuthorityRetireApprove
```

Each has its exact repository-rendered inline policy, fixed session duration
and exact tags. Managed-policy attachments, customer-managed policy
references, permissions boundaries, relay state and additive identity policies
are empty. The same immutable UserId is directly assigned to both permission
sets and each is provisioned to the one authority account.

The generated roles must be distinct and match their fixed permission-set
names. Complete IAM readback must prove exact Identity Center trust, only the
expected inline policy, no additional attached/inline policies and exact tags.
The same user across the two assignments is mandatory; the two role ARNs do
not establish independent people.

Every record preserves:

```text
authorization_mode=SINGLE_OPERATOR_NONPROD_EXCEPTION
two_human_status=NOT_PROVEN
independent_approval_present=false
production=false
```

`ScanalyzeGug357IdentityAudit` is outside this contract.

## Nine-phase graph

Each phase is `ABSENT_READY`, `EXACT_PRESENT_NO_TOUCH`, `AUTHORIZED`, `IN_FLIGHT`,
`READBACK_VERIFIED`, `UNCERTAIN_RECONCILE_ONLY` or
`DRIFT_BLOCKED_NO_REPAIR`. Only a verified phase or approved causal no-touch
receipt can precede the next phase.

### 1. `IDENTITY_CENTER_FOUNDATION`

The closed write set consists only of the exact application create/configure
operations, application user assignment, two fixed permission-set creates,
two inline-policy writes, two same-user account assignments and two
permission-set provisioning operations. Tags/configuration are included in a
create request whenever the provider supports them. Asynchronous assignment
and provisioning request IDs are slots; polling is read-only. Terminal
readback includes the application, grants/scopes/configuration, permission
sets, policies, assignments, provisioning status and two generated IAM roles.

### 2. `KMS_FOUNDATION`

The closed write set creates one key with exact policy, description and tags,
enables exact rotation and creates one exact alias. The key ARN is a slot.
Terminal readback covers key state/spec/usage/origin/multi-Region state,
policy, tags, rotation and alias. Existing, pending-deletion, external or
multi-Region keys are not eligible.

### 3. `S3_ARTIFACT_FOUNDATION`

The closed write set creates one bucket and establishes exact bucket-owner
enforced ownership, full public-access block, enabled versioning, KMS default
encryption with bucket key state, bucket policy and tags. The policy permits
only the planned phase principals and exact encrypted/versioned object paths;
public/ACL/cross-account access and unencrypted writes are denied. Terminal
readback also proves no website, replication, foreign access point or
unexpected lifecycle mutation surface in the closed inventory.

### 4. `SIGNER_PROFILE_FOUNDATION`

One exact `PutSigningProfile`-equivalent request creates a single immutable
profile version for `AWSLambda-SHA384-ECDSA`, exact signature validity and
tags. The returned version ID/ARN are slots. Creating a second version,
overwriting the selected name or adopting another profile is forbidden.

### 5. `LAMBDA_CSC_FOUNDATION`

One exact create request sets
`UntrustedArtifactOnDeployment=Enforce` and an allowed-publisher list
containing only the resolved profile-version ARN. The returned CSC ARN is a
slot. Tags and description are exact; `Warn`, an extra publisher or another
profile version fails closed.

### 6. `BROKER_UNSIGNED_PUBLISH`

One exact versioned `PutObject` writes bytes identical to the deterministic
GUG-215 ZIP at its schema-constrained unsigned key with the resolved KMS key,
explicit checksum, content length and exact metadata/tags. The returned S3
version ID is a slot. A null version, overwrite, multipart ambiguity or digest
mismatch stops the run.

### 7. `BROKER_SIGNING_JOB`

One exact job consumes the broker unsigned version and resolved profile
version. Its job ID and output key/version are slots. Polling never starts a
new job. Completion requires `Succeeded`, exact owner/invoker/platform/profile,
unexpired signature, same bucket/KMS and semantic ZIP equivalence.

### 8. `LEDGER_FACTORY_UNSIGNED_PUBLISH`

One exact versioned `PutObject` writes bytes identical to the deterministic
GUG-365 ledger-factory ZIP at its fixed unsigned key under the same KMS key.
It has a different key, version, manifest and archive digest from the broker.

### 9. `LEDGER_FACTORY_SIGNING_JOB`

One exact job consumes the factory unsigned version using the same profile
version. Its job and signed destination must be different from the broker's.
Terminal readback applies the same signature and ZIP-equivalence checks and
also proves the CSC still has one enforcing publisher.

## Operation and authorization records

Every write operation includes:

```text
phase
sequence
aws_api_action
canonical_request_digest
exact_target_digest
complete_configuration_digest
expected_readback_digest
executor_policy_digest
phase_operation_digest
phase_mutation_digest
causal_predecessor_digest
rollback_or_revocation_boundary
attempts=1
sdk_retries=0
```

The owner authorizes one exact contiguous request batch in one phase at a time
for at most fifteen minutes. The authorization binds the current source, run,
before-state, complete template write-set digest, exact resolved request
digests, private ledger root, session/caller evidence and
`automatic_rollback=false`. A provider output needed by a later request ends
the batch; readback and CAS resolution precede a new authorization for the
same phase. Authorization is revalidated immediately before every write. A
phase cannot reuse another phase's session or policy.

The exact three-line response is a request/response contract, not a signature.
Execution additionally requires a trusted owner-controlled external-channel
verifier receipt bound to that response and authorization. The runner also
requires the complete executor-authority evidence object and an append-only
ledger history; neither can be replaced with a caller-supplied digest alone.
Those are reserved live GUG-376 requirements. GUG-377 does not consume an owner
response or pretend to authenticate a provider. Its repository `AttemptLedger`
models the required CAS order only: it consumes one synthetic attempt before
the scripted call, persists the typed result before advancing and rejects
stale, repeated or out-of-order transitions. No live verifier, credential
adapter, AWS client, durable private ledger or live orchestrator is implemented.

## Repository completion and reserved private products

The v2 materializer exercises result/readback validation only against the
scripted adapter. Its successful terminal state is
`SYNTHETIC_MATERIALIZATION_COMPLETE`; this means the repository graph and
contracts completed, not that any provider resource exists.

For both packages, the closed result variants bind exact source version,
successful job, profile version, signed destination, KMS encryption, checksum,
size, outer archive digests, semantic member equivalence and signature expiry.
They reject an extra closed-scope version, delete marker, publisher, mutable
reference or substituted destination. Repository output persists only approved
digests and classifications, never raw provider fields.

A future separately authorized private GUG-376 run must still build, but never
implicitly apply:

1. the closed GUG-363 intent;
2. the GUG-363 plan through the existing repository `plan` command;
3. the ledger-factory signing contract; and
4. independently delivered expected digests.

The GUG-363 plan must retain `deployment_authorized=false`, `production=false`,
`authorization_mode=SINGLE_OPERATOR_NONPROD_EXCEPTION`,
`two_human_status=NOT_PROVEN` and
`independent_approval_present=false`.

GUG-377 does not create these private products or their root. Its completion
package is repository evidence only. Its separate rollback/revocation package
has `automatic_rollback=false`, `deployment_authorized=false`, no provider
mutations and a digest distinct from the completion package.

## Handoff checkpoint

The v1 final handoff remains the original fail-closed checkpoint with
`STOP_UPSTREAM_SOURCE_CONTRACT_GAP`. Final-handoff v2 records a successful
repository simulation while keeping live promotion stopped:

```text
status=STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED
state=SOURCE_CONTRACTS_CLOSED_REPOSITORY_ONLY
synthetic_materialization_complete=true
evidence_scope=REPOSITORY_VALIDATED_SYNTHETIC_ONLY
provider_certification_complete=false
live_provider_evidence=false
aws_calls_performed=0
aws_mutations=0
provider_network_calls=0
deployment_authorized=false
consumer_fresh_checkpoint_required=true
two_human_status=NOT_PROVEN
independent_approval_present=false
production=false
```

It binds the source, inventory, target, thirty-operation result chain,
completion and rollback package digests. It contains no provider identifier,
private-root claim or live topology certification. `LIVE` remains reserved for
a future separately reviewed private orchestrator and cannot be obtained by
resealing either v1 or v2.

The consumer must refresh all provider facts read-only before compiling a
fresh GUG-365 plan. Handoff equality does not authorize compilation, AWS
mutation or deployment.

## Acceptance gates

GUG-377 repository completion requires all of the following:

- valid inventory, plan and final-handoff v2 schemas plus unchanged v1
  regression fixtures;
- exact source and target manifests with cross-version substitution rejected;
- exactly nine phases and thirty uniquely identified, globally ordered
  operations;
- the inert default and deterministic scripted adapters only;
- exact causal result binding, closed bounded polling and injected time;
- one attempt consumed before every scripted write, no blind retry and
  read-only-only uncertain reconciliation;
- separate completion and non-executable rollback/revocation packages;
- public-evidence leakage sentinels and zero SDK/socket/subprocess activity; and
- zero AWS/provider/GUG-365/GUG-357/GUG-215/GUG-206 effects.

Future GUG-376 live completion separately requires all of the following:

- exact reviewed source and clean-checkout gates;
- one authorized private root and one causal run;
- approved owner-decision digest;
- stable provider-backed runtime evidence from a pre-existing Lambda version;
- exact same-user Identity Center topology with no independence claim;
- all nine phases verified or causally proven exact/no-touch;
- distinct successful signing jobs and four distinct immutable object
  versions across the two source/destination pairs;
- one enforcing, single-publisher CSC shared by both contracts;
- deterministic offline rebuild and all negative tests;
- valid GUG-363 intent/plan and ledger-factory signing contract with expected
  digests delivered independently;
- sanitized Linear manifest and private digest-bound handoff; and
- `GUG365_AWS_WRITES=0`, `GUG357_CREATE_STACK=0`, `GUG215_EFFECTS=0`,
  `GUG206_EFFECTS=0` and production `NO-GO`.

GUG-377 closes provider-output, polling, generated-role, KMS/S3/Signer
destination and result contracts only at the repository/scripted level. It does
not implement the private orchestrator, live provider adapter, durable private
ledger, runtime evidence collector or owner authorization verifier. Therefore
no GUG-376 phase is authorized or executed. Repository review, merge,
exact-head revalidation, private-root authorization, provider-backed runtime
evidence and phase-specific owner authorization remain separate mandatory
gates.

## References

- [ADR-053](../../ADR/ADR-053-gug365-upstream-prerequisites-materialization.md)
- [ADR-054](../../ADR/ADR-054-gug377-provider-backed-upstream-materializer.md)
- [Operations runbook](../operations/platform-authority-gug365-upstream-prerequisites.md)
- [Threat model](../security/gug376-upstream-prerequisites-threat-model.md)
