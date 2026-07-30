# GUG-215 threat-model delta: brokered retained Change Set retirement

## Scope

This delta covers the version-pinned Lambda PEP, identity-enhanced human
invocation, service-owned durable ledger, one-shot exact Change Set deletion,
uncertainty reconciliation and revocation.

It does not authorize deployment of the PEP, `ExecuteChangeSet`, `DeleteStack`,
`CreateChangeSet`, Terraform Apply, seed, customer deployment, production,
migration, destruction or redrive. No live GUG-215 stack or alias was deployed
or invoked during repository implementation.

## GUG-217 threat-model amendment

ADR-043 replaces the direct identity-enhanced invocation boundary with an
ordinary exact `AWS_IAM` Function URL plus an in-broker deny-all STS proof.
Human proof is persisted by digest before the protected retirement effect; the
broker execution role remains the CloudFormation and ledger principal, and
native downstream `onBehalfOf` is not claimed.

The GUG-215 target, ledger, one-attempt and no-retry controls remain in force.
See the [GUG-217 threat-model delta](gug-217-identity-context-pep-threat-model-delta.md)
for the request-secret, Function URL, proof-role and attribution threats. The
path is not live validated and still requires two independent humans.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| A human bypasses the PEP with direct CloudFormation authority | Human permission-set policies allow only assume/set-context into exact invoker roles; invokers allow `lambda:InvokeFunction` on qualified aliases only and explicitly deny direct `DeleteChangeSet`, `DeleteStack` and `ExecuteChangeSet`; the reviewed CLI forces `RequestResponse` | AWS denies direct mutation; CLI mutation adapters are hard disabled |
| A human or alternate service writes the retirement ledger | Table resource policy denies supported DynamoDB writes unless `aws:PrincipalArn` is the exact broker execution role; human roles also explicitly deny writes | Resource-policy deny applies even if another identity policy grants an allow |
| One operator is bound to both duties | CloudFormation and broker configuration require two different immutable Identity Store UserIds | Equal IDs fail deployment/configuration; live use remains blocked until assignments and operators are reviewed |
| Identity context is absent or fabricated | Exact `sts:SetContext`, Identity Center context provider, UserId, IdentityStoreArn, InstanceArn and ApplicationArn conditions; no `IfExists` fallback | Assume/invoke denied before Lambda |
| A normal SSO profile is mistaken for identity-enhanced credentials | Live use requires a separately reviewed `CreateTokenWithIAM` plus STS `ProvidedContexts` adapter and immutable UserId readback | Live invocation remains blocked while the adapter is absent |
| Classifier invokes approval or retirement | Classifier invoker can invoke only alias `classify`; approver invoker can invoke only `retire` and `reconcile` | Alias IAM deny and broker alias allowlist |
| A foreign same-account principal invokes a broker alias | Broker rejects function-, alias- and version-scoped Lambda resource policies; preflight must inventory all identity policies and prove no foreign invoke authority | Any foreign invoke path blocks live use; account control-plane administrators remain a reviewed trusted boundary |
| Caller chooses target, identity or action in payload | Broker requires event exactly `{}`; aliases and immutable environment bindings select operation and target | `REQUEST_AUTHORITY_FORBIDDEN` before target or ledger write |
| Mutable or foreign code becomes the PEP | Versioned S3 object, expected CodeSha256, code-signing config, published version and aliases; `$LATEST` rejected | Broker denies before effect |
| Alias is retargeted to different code or configuration | Broker compares alias/version, code digest, role, signing configuration, policy and concurrency against immutable deployment bindings | Drift denies before effect; a stable retarget with equivalent reviewed bytes/config is equivalent authority |
| Broker execution role is broadened | Lambda-service-only trust, exactly one named inline policy, no attached policies/boundary, canonical live policy digest readback | Deny before effect |
| Caller supplies an authorization artifact | Broker uses the live role policy digest and deployment-bound assignment/invoker-policy digests; human CLI accepts no policy input | Caller artifacts have no authorization effect |
| Ledger loses deletion protection, PITR, encryption or resource policy | Broker reads table status/schema/billing/SSE/PITR/tags/stream/replicas and exact resource policy before every operation | Deny before classification, transition or delete |
| Missing DynamoDB key context vacuously satisfies `ForAllValues` | Item IAM requires exact `dynamodb:LeadingKeys` and `Null=false`; runtime uses only the deployment-bound key | AWS denies before ledger access |
| Live metadata is used to reconstruct the missing bootstrap Plan | GUG-215 never consumes or emits a bootstrap Plan; immutable broker configuration records reviewed template/inventory evidence separately | Historical cancel remains denied |
| Customer/request data redirects authority | No payload fields allowed; exact account, Region, stack, Change Set and digests come from immutable function configuration and AWS metadata | Reject before target inspection |
| Pagination hides a foreign Change Set | Broker consumes every `ListChangeSets` page and rejects invalid/repeated tokens or non-exact inventory | Deny as ambiguous |
| Same-name Change Set is substituted | Broker binds stack/name in IAM, compares the post-claim retirement key plus every ARN/UUID/content digest to the `ATTEMPTED` ledger and uses the final full Change Set ID for describe, template read and delete | Replacement cannot redirect the one delete by reusing only the name |
| Stack gained resources, was recreated or inherited authority | Fresh checks require the classified full Stack ID digest, zero resources, `REVIEW_IN_PROGRESS`, no RoleARN, notifications, parent or root metadata | Deny |
| Retire is replayed after attempt | `CLASSIFIED -> APPROVED -> ATTEMPTED` CAS occurs before delete; attempt count is fixed at one | Later retire returns reconciliation required without delete |
| SDK or orchestrator repeats delete | Broker SDK has zero retries, reserved concurrency is one, source contains one delete call and durable attempt is consumed first | No second request; reconcile only |
| Direct invocation requests asynchronous delivery | IAM cannot distinguish `Event` from `RequestResponse` for `lambda:InvokeFunction`; the reviewed CLI uses `RequestResponse`, account-wide invoke inventory is mandatory, and the durable attempt claim remains authoritative if a foreign principal bypasses that interface | Foreign/async invoke authority blocks live use; redelivery cannot consume a second delete attempt |
| Lost response is interpreted as success or failure | Any exception around delete returns reconciliation required while ledger remains `ATTEMPTED` | No retry and no terminal claim |
| Reconciliation deletes again | `reconcile` alias routes to a non-delete handler; target presence performs no ledger write | Observe again or deny; never delete |
| Replacement/foreign object or recreated stack is hidden during reconciliation | Full Stack ID continuity and the complete paginated inventory are checked against the ledger and repeated immediately before terminal CAS | Leave `ATTEMPTED`; no cleanup shortcut |
| Retirement is called recovery READY | Terminal control is revocation required or PAB plus revocation required; no READY value | GUG-214 remains blocked |
| Sensitive identifiers leak through CLI/Lambda | Empty payload, sanitized status/reason codes and no application logging | Refuse/deny and keep raw provider evidence private |
| Temporary invocation access becomes standing authority | Short-lived exact assignments, post-operation removal, session revocation and readback are mandatory | Recovery remains blocked until absence is proved |

## Trust boundaries

### Identity Center boundary

The authoritative human binding is the identity-enhanced context attached to
the exact account-local invoker role. Profile names, terminal separation, chat
identity and caller-provided UserIds are not authority. Two different
immutable Identity Store UserIds and their reviewed assignments are mandatory.
The Lambda event itself does not carry caller identity. IAM trust and invoke
authorization enforce that boundary before execution; the broker verifies the
effective invoker-role definitions and absence of a Lambda resource policy.

### Invocation boundary

Human sessions can invoke only qualified aliases. The alias is the operation;
the request is empty. `lambda:InvokeAsync`, unqualified function invocation and
`$LATEST` are denied or rejected. The CLI never exposes direct delete or ledger
mutation as a reachable command.

### Broker boundary

The version-pinned, code-signed Lambda execution role is the sole principal
that can read the protected target, mutate the durable ledger and call the one
exact delete. It revalidates its own live trust/policy/code/alias/signing and
the ledger controls before each operation.

### Durable ledger boundary

The item key is
`gug215#sha256:<64-hex-sha256-of-full-change-set-id>`. Create-only
`CLASSIFIED`, CAS `APPROVED`, CAS `ATTEMPTED` and CAS
`RETIRED_RECONCILED` are service-owned. The table resource policy prevents a
human or alternate role from manufacturing state even if local evidence is
copied.

### Target boundary

Stack-plus-name IAM is supplemented by full UUID/content PEP immediately
before delete. Target reads are fresh and complete. No customer destination,
request locator or naming inference participates.

### Evidence boundary

The CLI returns sanitized status, ledger digest and next-required control.
Raw Identity Store bindings, AWS responses, CloudTrail, ledger documents,
template contents and resource identifiers remain private. Repository merge,
CI and ticket state do not prove live deployment or invocation.

## Residual risks

CloudFormation does not atomically combine final content revalidation and
`DeleteChangeSet`. A separately authorized foreign writer could race between
the last read and the one delete request. Exact-name IAM, full-UUID/content
checks, one reserved concurrency slot, durable attempt consumption and
post-effect reconciliation reduce but cannot eliminate that governance race.

Identity-enhanced policies bind immutable Identity Store UserIds but do not by
themselves prove organizational independence. Operator assignment review and
human governance remain required.

The broker configuration binds assignment and invoker-policy digests; actual
Identity Center provisioning/readback is an external deployment prerequisite.
No live evidence currently proves those bindings.

Those assignment digests are reviewed evidence references, not live
authorization facts. The repository also lacks the identity-enhanced
credential adapter, and no account-wide permission inventory has yet proved
that only the two invoker roles can reach the aliases. Both conditions block
live use.

Control-plane administrators capable of rewriting IAM, Lambda configuration or
deployment bindings are a residual trusted boundary. GUG-215 does not claim
to defend against a compromised authority-account administrator.

CloudFormation inventory can be eventually consistent. Repeated
`broker-reconcile` invocations may perform read-only target observation while
the object remains visible, but cannot retry delete or reset the ledger.

The dedicated ledger and Lambda are retained control-plane infrastructure.
Repository rollback does not decommission them. Their future deletion or
replacement requires a separate destructive review.

Account-level S3 Public Access Block remains an independent GUG-214 gate.
Retiring unexecuted metadata neither creates resources nor repairs PAB.

## Evidence handling

- Never publish Identity Store UserIds, assignments, role/function/table ARNs,
  artifact locators, code-signing configuration, Change Set identifiers,
  templates, ledger documents or raw AWS responses.
- Publish only sanitized state classes, counts, digests, gate outcomes and
  whether deployment/invocation occurred.
- Do not treat caller artifacts, terminal output or screenshots as durable
  authorization.
- Record assignment/session revocation independently after any live attempt.

## Evidence classes

- Implemented: exact reviewed commit containing broker, aliases,
  identity-enhanced roles, resource-policy ledger, CLI, tests and docs.
- Locally validated: named gates for that exact commit only.
- CI validated: pending required checks for the exact PR commit.
- Live inventory: sanitized read-only observation only.
- Live PEP deployment: **Not performed**.
- Live alias invocation: **Not performed**.
- Live retirement: **Blocked** pending two independently reviewed users,
  deployment, assignment/provisioning, identity-enhanced credential adapter,
  account-wide invoke inventory and exact readback.
- Production: **NO-GO**.
