# GUG-221 threat-model delta: server-side repair PEP

## Scope

This delta covers the repository design for a non-production, server-side PEP
that may repair the exact partial `ScanalyzeAuthorityLambdaAudit` provisioning
state. It covers the human invocation boundary, three private Lambda aliases,
three authority execution roles, the exact invocation-authority inspector, two
management service roles, the provider-backed DynamoDB Plan/CAS ledger, three
Identity Center effects and final SSO/IAM readback.

It excludes AWS deployment, live invocation, Lambda inventory execution,
Change Sets outside the reviewed PEP stacks, Terraform Apply, customer
deployment, migration, destruction, redrive and production. Production remains
**NO-GO**.

## Security objective

Ensure that a human can request only one reviewed, empty-payload operation and
cannot directly exercise or redirect the repair mutations. Plan must first
prove the exact immutable binding and account-wide invocation graph and create
one provider-backed `PLAN_VERIFIED` record. Repair must consume that exact
record through CAS before any effect. Any ambiguity must permanently remove
mutation from the permitted next actions.

## Assets

- exact reviewed source commit and signed Lambda package digest;
- published numeric Lambda versions and alias mapping;
- immutable server configuration and 15-minute-or-shorter validity window;
- GUG-220 consumed-ledger digest and unchanged prior evidence;
- exact Identity Center instance/store, collector permission set and principal;
- canonical collector and service-policy digests;
- private SAML and optional KMS bindings;
- provider-backed DynamoDB Plan/repair record and monotonic counters;
- exact provider-derived account-wide invocation graph and stable digest;
- exact management mutation/readback service roles;
- complete Identity Center and authority-account IAM snapshots;
- exact read-only inventory and quarantine status for any retained KMS,
  DynamoDB or Logs resources left by a failed Phase B operation; and
- sanitized receipts and evidence classification.

## Trust boundaries

### Human-to-Lambda boundary

The human `ScanalyzeLambdaAuditRepair` permission set may call only exact
qualified private aliases and must send exactly `{}`. It has no direct
Identity Center, Identity Store, IAM, STS role-assumption or DynamoDB write
authority. Request data never establishes the target or action.

### Version and configuration boundary

Each alias targets a reviewed published version. Code hash, code signing,
function mode, account, Region, repair ID, source, principal, permission set,
policy digests, ledger binding, time window, SAML/KMS binding and service roles
come from immutable deployment configuration. `$LATEST`, unqualified ARNs and
caller environment are non-authoritative.

The runtime completely enumerates all regional functions with all versions and
then all three reviewed functions' version and alias sets. It blocks an
additional published version or alias, a changed alias target, a protected
execution role used by another function, duplicate entries and incomplete or
replayed pagination. This closes the same-function alternate-PEP path that an
unqualified `lambda:SourceFunctionArn` condition cannot distinguish by itself.

### Source and signed-artifact boundary

The deployment handoff does not trust a local manifest, downloaded ZIP or
operator-created provider readback. It rebuilds the closed package from a clean
commit that must equal local and current protected GitHub `main`, proves the
merged PR/tree and six required GitHub Actions checks against live branch
protection, then reads the exact Signer job and S3 versions directly. Mandatory
SHA-256, a job-ID-derived destination key, exactly one signed version and an
exact twenty-five-entry ZIP bind the only eligible CloudFormation parameter
tuple. The entry set includes twelve standalone IAM contracts used by runtime
readback, so live role authority cannot be compared with caller assertions.

### Change Set derivation and readback boundary

The dependency is intentionally split. Phase A fresh-enumerates the GUG-220
partial state with fixed read-only profiles, complete pagination, unique
digest matches, global account-assignment checks, DescribeInstance encryption
readback, KMS DescribeKey for a CMK, IAM GetSAMLProvider and absent collector
role proof. Pending operations are sampled before and after each provider
snapshot and two complete snapshots must have the same provider-state digest.
Offline/self-digested evidence is compared to this fresh state and can never
authorize by itself.

Only exact Phase A live readback may reveal the provider-created repair-invoker
permission-set ARN. Phase B cannot be prepared from a contract-supplied ARN and
refreshes Phase A before it verifies the PEP Change Set. Both Change Set
verifiers bind exact CloudFormation metadata/template/parameters/tags/resources
and the unique CloudTrail CreateChangeSet event, including absence of RoleARN,
notifications, nested/import/deployment-mode features and exact rollback
configuration. Any missing page, malformed extra entry, masked value or drift
fails closed.

Phase B retention is also a trust boundary. If creation or rollback fails after
the KMS key/alias, DynamoDB ledger or log groups exist, the state is
`FAILED_RETAINED_RESOURCES`. Complete read-only provider inventory and exact
stack-event physical identifiers are required before any disposition.
Canonical names, expected tags and configuration matches cannot prove
ownership or authorize adoption. Candidates remain quarantined because a
later deployment can collide with their names and the retained resources can
continue to incur cost. Cleanup requires a separate reviewed child issue and
destructive authorization.

### Plan/repair/reconcile separation boundary

Plan, repair and reconcile have different functions, versions, aliases and
execution roles. Plan can only create the exact durable record and assume the
readback role. Repair can only update that record and assume the management
mutation service role. Reconcile cannot write the ledger or invoke Identity
Center mutations and assumes only the readback role. All three may assume only
the exact path-scoped invocation inspector for read-only graph collection.

### Account-wide invocation-authority boundary

Lambda runtime identity cannot prove the original human invoker. Every provider
snapshot therefore uses the inspector role and the GUG-218 collector semantics
to enumerate all enabled Regions and complete IAM/Lambda authority. Exactly one
reviewed materialized SSO role and exactly three qualified invoke edges may
exist. Foreign or unknown edges, mutating authority, missing coverage, stale
evidence or graph drift between snapshots blocks before ledger access or an
effect. The inspector explicitly denies invoke, IAM/Lambda mutation and role
chaining.

### Cross-account service-role boundary

Management mutation/readback roles use the authority-account root only as the
stable trust principal required for management-first creation, then require
the corresponding exact Lambda execution-role ARN through
`ArnEquals aws:PrincipalArn` and the exact authority account. The paired caller
and trust policies include `sts:SetSourceIdentity` for durable attribution.
Human SSO roles and unconstrained wildcard principals are not trusted. The
mutation role exposes exactly three reviewed writes; the readback role exposes
none.

### Durable one-shot boundary

The Plan function must conditionally create the DynamoDB `PLAN_VERIFIED` record.
The repair function cannot create an item and must atomically consume that exact
record before its first effect. The table is retained, deletion protected, KMS
encrypted and allows only Plan `PutItem` plus repair `UpdateItem`; all other
writes are denied. Stage changes use compare-and-swap over the immutable
binding, Plan/repair versions, planned state and counters. A host-local marker
is not mutation authority.

### Provider-state boundary

The PEP trusts no write response as final state. Complete Identity Center
pagination and authority-account IAM discovery establish predecessor and final
states. Missing access, token replay or eventual-consistency ambiguity blocks.

### Governance boundary

The current one-person roster is an explicit residual risk. One person using
multiple roles or sessions does not satisfy independent approval or production
separation of duties.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Human calls Identity Center writes directly | Invoker role allows only exact `lambda:InvokeFunction` aliases and explicitly denies adjacent authority | IAM deny; no repair |
| Caller changes target or authority through payload | Phase A plan/repair/reconcile events remain exactly `{}`. Phase B accepts only the exact proof fields plus fresh KMS-authenticated topology evidence; stack, Change Set, ledger, identities and policy bindings still come exclusively from pinned version configuration and the matching signed receipt | `NON_EMPTY_EVENT`, `REQUEST_AUTHORITY_FORBIDDEN` or evidence-binding deny |
| Caller uses unqualified ARN or another version | Exact qualified invocation ARN, numeric version, alias-mode and code-hash binding | Invocation or PEP rejection |
| Operator signs an unreviewed clean commit | Current protected GitHub main, merged PR/tree and required-check/App provenance are read directly | Signed handoff blocked |
| Third-party App reports a homonymous green check | Live branch-protection set plus exact GitHub Actions App ID/slug binding | Source-review receipt rejected |
| Signer input is self-asserted or substituted | Deterministic rebuild from reviewed commit equals exact source S3 version byte-for-byte | Signed handoff blocked |
| Signed ZIP adds `sitecustomize.py`, `.pyc` or another executable | ZIP name set must equal the twenty-five manifest entries; duplicates/encryption/symlinks rejected | Signed handoff blocked |
| Signer destination is overwritten or read through `latest` | Job-ID-derived key, one version, no delete marker, exact VersionId Head/Get and mandatory SHA-256 | Signed handoff blocked |
| Public or asynchronous path bypasses review | No URL/public permission/event source; synchronous-only `ClientContext`; every protected alias, including the separate pre-Phase-B broker, materializes async retries `0`, age `60`, no destination. Direct provider readback rejects missing, inherited, unqualified or version-specific drift. The marker proves transport only and carries no authorization input | Runtime rejection before provider/ledger access or deployment gate failure |
| Human assumes mutation/readback service role | Account-root principal is constrained by exact `aws:PrincipalArn`; caller and target bind `SourceIdentity` | STS deny |
| Plan or reconcile inherits repair authority | Three separate functions/roles; Plan only `PutItem`, repair only `UpdateItem`, reconcile no writes | Policy/test gate fails |
| Direct repair invocation bypasses Plan | Repair cannot `PutItem`; exact unconsumed `PLAN_VERIFIED` record and matching planned-state digest are mandatory | `PLAN_REQUIRED`, `PLAN_STATE_CHANGED` or CAS block |
| Foreign same-account principal invokes a protected alias | Exact inspector plus account-wide provider-derived graph requires only three reviewed edges and stable digest on every snapshot | Blocked before ledger/effect |
| Two concurrent invocations both mutate | DynamoDB `attribute_not_exists` claim plus reserved concurrency one | Only one claim; other invocation blocked |
| Another host deletes/replaces local evidence | Provider-backed retained DynamoDB record is authoritative; local files cannot authorize | Existing claim blocks |
| Ledger writer is broadened | Table policy separates exact Plan `PutItem`, repair `UpdateItem` and denies every unsupported/foreign write | DynamoDB deny |
| Plan record is absent or repair tries to create it | Only Plan can conditionally create; repair can only CAS `PLAN_VERIFIED -> CLAIMED` before obtaining mutation role/effect | No mutation |
| Stale stage resumes midway | CAS requires exact intent, source, stage and counters | Condition failure; reconcile only |
| GUG-220 is retried | New repair ID/binding; original digest read-only and unchanged; GUG-220 ledger never reused | Blocked |
| Foreign permission set with same name is adopted | Exact ARN, metadata, tags, attachment and boundary comparisons | Blocked drift |
| Existing inline policy is overwritten | Eligible predecessor requires policy absence | No effect |
| Foreign/group assignment is hidden | Complete pagination; exact one `USER`; all groups/foreign principals rejected | Blocked drift/incomplete |
| Provisioning reaches foreign account | Immutable target plus complete provisioned-account enumeration | Blocked drift |
| Optional Identity Center CMK is over-broad | Exact key ARN, `kms:ViaService` and encryption-context conditions | KMS deny / blocked |
| SDK/Lambda retries an uncertain write | SDK retries disabled; async retries `0`; synchronous marker and consumed CAS claim | `UNCERTAIN_RECONCILE_ONLY` |
| Runtime exhausts its budget after consuming Plan or dispatching an effect | 660-second immutable-window gate, 480-second pre-claim Lambda gate, five bounded authority epochs, 75-second dispatch reserve and 60-second provider/polling reserve | Blocked before claim/effect, or durable uncertainty before timeout |
| Network response loss is treated as failure | Any possibly started effect is ambiguous; no resume or retry | Reconcile only |
| Successful waiter is treated as final proof | Independent SSO and target IAM readback required | No verified receipt |
| An in-progress assignment/provisioning operation hides eventual drift | Unfiltered accounts, per-account assignments, List `IN_PROGRESS` plus Describe each request ID | Blocked only when bound to either exact permission set |
| Account-local role suffix is guessed | Complete IAM discovery and exact role/trust/policy checks | Blocked |
| Collector role contains hidden policy/boundary | Enumerate inline/managed policies and boundary; require exact single policy | Blocked drift |
| Invoker SSO role drifts after permission-set provisioning | Enumerate the distinct invoker role and require exact SAML actions, policy digest, zero extras and no boundary | Blocked drift |
| Attacker tampers with alias after review | Published version, code hash, signing config and alias readback | Deployment/live gate fails |
| Failed Phase B is treated as a clean rollback | `FAILED_RETAINED_RESOURCES` plus complete read-only KMS/DynamoDB/Logs and stack-event inventory | Quarantine; no redeploy, retry or success claim |
| Canonical name/tag is used to adopt or delete a retained resource | Exact physical-ID and execution-lineage proof is mandatory; names, tags and configuration are discovery-only | No inference or adoption; separate cleanup child |
| Cost or name collision pressures an inline cleanup | Record cost exposure; require a separately authorized KMS/DynamoDB/Logs child and readback | Resource and canonical name remain quarantined |
| Receipt overclaims mutation attribution | Durable ledger digest, effect counters and final state digest required | Receipt rejected |
| Sensitive identifiers leak to public evidence | Private evidence custody; sanitized digests/status/counts only | Publication blocked |
| Single operator is labeled independent review | Explicit no-independent-approval evidence | Governance/production gate blocked |
| Repository green is labeled live | Separate Implemented, Local, CI and Live classifications | Production remains NO-GO |

## Intended attack path

```text
reviewed source and immutable deployment binding
  -> human invokes exact plan-v1 alias with {}
  -> complete SSO/IAM and account-wide invocation-authority preflight
  -> create-only durable PLAN_VERIFIED record
  -> exact non-production authorization
  -> human invokes exact repair-v1 alias with {}
  -> re-prove provider state and invocation graph
  -> DynamoDB CAS PLAN_VERIFIED -> CLAIMED / BEFORE_FIRST_EFFECT
  -> management mutation service role
  -> exact ordered policy / USER assignment / provisioning effects
  -> monotonic CAS attribution
  -> exact reconcile-v1 read-only SSO/IAM verification
  -> sanitized non-production evidence
```

## Denied attack paths

```text
human SSO session -> sso mutation APIs
human payload -> account/principal/policy/action selection
unqualified Lambda or function URL -> PEP
reconcile role -> DynamoDB or Identity Center write
repair role -> create/replace durable Plan
foreign invocation edge -> ledger or provider effect
management service role -> human assumption
host-local file deletion -> new repair authorization
timeout or unknown provider status -> retry/resume
waiter success -> verified state
one human with two sessions -> independent approval
reviewed Phase B state -> execution by an unbound actor or token
18-resource receipt -> evidence for the 23-resource PEP template
failed Phase B + matching retained name/tag -> adoption, deletion or redeploy
GUG-221 success -> production authorization
```

## Required negative tests

The package must reject at least:

- non-empty events, null, arrays and scalar payloads;
- unqualified/wrong aliases, `$LATEST`, wrong versions and wrong execution role;
- expired, future, malformed or greater-than-15-minute windows;
- foreign account, Region, instance/store, permission set, principal or SAML;
- wrong collector/service policy digest or source commit;
- invoker permission with SSO/IAM/STS/DynamoDB authority;
- service-role trust without exact account/`aws:PrincipalArn`, including an
  SSO role, user or unconstrained wildcard;
- reconcile access to DynamoDB writes or any of the three mutations;
- Plan access to `UpdateItem`, repair access to `PutItem`, or either role using
  unsupported ledger writes;
- a missing, stale, already-consumed, malformed or conflicting durable Plan;
- a foreign/unknown invocation edge, incomplete account-wide coverage,
  mutating invoker authority or graph drift between snapshots;
- CAS with stale stage, counters, source or intent;
- effect before claim and any automatic mutation retry;
- managed/customer-managed attachments, boundaries or group/foreign assignment;
- foreign provisioned target, role, trust, policy or relay;
- partial pagination and replayed pagination token;
- verified receipt without exact SSO, IAM and durable attribution;
- stale/unmerged GitHub source, branch-protection drift, missing checks, wrong
  Check App, differing PR/main tree, self-asserted Signer source, missing S3
  checksum, overwritten signed key or any additional ZIP entry; and
- forged/stale local signed receipt not reproduced from direct provider
  readback; copied, incomplete, extra, masked or `UsePreviousValue` Change Set
  parameters; foreign ARN/name/type/capability/role/tag/template/resource;
  repeated pagination token; replacing change; or a partial resource inventory;
  and
- independent-review, live-validation or production overclaims.

## Residual risks

Phase A execution provenance is fail-closed: a final stack snapshot alone
cannot establish that the reviewed Change Set ran. The read-only verifier binds
the immutable review receipt to one deterministic `ClientRequestToken`, one
exact CloudTrail `ExecuteChangeSet` event and the complete terminal
`StackEvents` set. Foreign actors/tokens, duplicate events, partial pagination
and state-equivalent stacks without that lineage are denied. The trace is
evidence only; it grants no execution authority and production remains NO-GO.
Its stable binding excludes only the verifier observation field
`evaluated_at`; Phase B normalizes that outer/nested timestamp while retaining
every provider event, actor, token, resource, digest and verifier binding.

Phase B has the same independent provenance requirement. Its broker, token and
request digest are contract-bound before execution, and its read-only trace
receipt must prove the exact ordered 23-resource template plus the root stack.
An older 18-resource fixture could never represent the current verifier output
and is rejected. A state-equivalent PEP stack without the exact CloudTrail and
StackEvents lineage remains unusable, even if every expected resource happens
to exist. The trace is still insufficient: a separate read-only direct-provider
receipt must verify the effective IAM, Lambda, DynamoDB, KMS and Logs state in
two stable complete snapshots.
Stability cannot certify a consistently foreign state. The effective-state
verifier derives 23 expected semantic contracts from the exact reviewed
template bytes plus PEP parameter handoff and compares per-resource
expected/observed digests. It rejects extra Lambda inventory, global/restore or
throughput DynamoDB state, IAM boundary drift, KMS algorithms/aliases and Logs
data-protection inheritance. AWS-assigned IAM role IDs are classified as
non-template properties, shape-checked and bound by two-snapshot stability.
The expected Signer profile version comes from the PEP handoff. A signing-job
ARN is required and account/Region/format/stability checked, but remains
provider-assigned evidence rather than proof of one exact signing job.

Any failure to parse Lambda invocation metadata, read the response file or
validate the returned public receipt occurs after the function may have run.
The client therefore collapses all such failures to
`UNCERTAIN_RECONCILE_ONLY` and permits only the read-only reconcile alias next.

- One human currently holds all operational logins; independent approval is not
  available.
- Runtime `AssumeRole` calls set a deterministic `SourceIdentity` and both
  policies permit only the exact role edges, but the target trusts do not yet
  make presence of `SourceIdentity` a condition. This is a forensic-attribution
  hardening gap, not additional invocation or mutation authority.
- DynamoDB `UpdateItem` cannot be constrained by IAM to require the reviewed
  conditional expression. Plan/Repair separation therefore also depends on the
  signed handler, empty payload, exact alias, CAS validation and
  `lambda:SourceFunctionArn`. A future contract should split immutable Plan
  evidence from mutable repair progress or add a Plan-only signature.
- If an account-wide recheck or budget guard fails after an `ATTEMPTING_n` CAS
  but before provider dispatch, the repair stays consumed and fail-closed. It
  must be reconciled and, when no effect is proven, replaced by a new reviewed
  repair; the original ledger is never replayed.
- `ClientContext` proves synchronous transport, not the named human caller.
  Human attribution remains outside the handler in the exclusive Identity
  Center assignment and IAM invoke edge. A foreign same-account invoke grant
  would therefore be security-relevant drift and must be detected by the
  account-wide Lambda authority inventory.
- The package binds but does not vendor `boto3`/`botocore`. An AWS-managed
  runtime SDK update blocks fail-closed; require a fresh `PLAN_VERIFIED`
  immediately before repair and preserve the observed versions.
- An organization administrator can alter Identity Center or IAM state after
  readback; every operation therefore needs fresh evidence and an explicit
  administrative change freeze from the final plan snapshot through
  `RECONCILE_VERIFIED`.
- Eventual consistency can prolong `UNCERTAIN_RECONCILE_ONLY`; it never permits
  a retry.
- The DynamoDB control is only live after independently reviewed deployment and
  readback of its resource policy, KMS, retention and deletion protection.
- A failed Phase B operation may leave retained KMS, DynamoDB and Logs
  resources that accrue cost and block canonical names. Until exact provenance
  and a separately authorized recovery or cleanup child are complete, they
  remain `FAILED_RETAINED_RESOURCES`; availability or cost pressure does not
  permit inferred ownership, adoption or deletion.
- A regional AWS control-plane outage can prevent reconciliation; no fail-open
  path exists.
- GUG-218/GUG-219 remain report-only and do not authorize Lambda invocation or
  production.

## Post-merge review delta

The post-merge and independent reviews found no fail-open path, but confirmed
seven defects across five failure categories that could deny valid operation
or weaken offline evidence integrity:

- invalid AWS CLI continuation flags could make second-page SSO/IAM state
  unverifiable;
- an unsupported page-size flag could make permission-set tag readback
  unverifiable even on the first page;
- one shared Lambda description expectation could reject the reviewed
  operational functions before ledger access;
- the semantic validator could reject the valid durable Plan ledger and Plan
  receipt required by the runtime.
- the semantic validator did not independently verify that a ledger carried
  the digest of its immutable initial Plan binding.

The remediation keeps the secure failure mode while restoring compatibility:
bounded capability-aware CLI-native pagination, exact function-versus-version
description bindings, a reconstructed immutable Plan-binding digest, and one consistent
durable Plan matrix across producer, runtime, invoker, JSON Schema and semantic
validation. Unsupported page-size options, token ambiguity, raw IAM truncation
without a CLI token, description drift, ledger tampering, state-digest mismatch
and legacy unproven Plan evidence all remain denied. No permission, trust,
action, resource scope or live execution authority was added.

## Phase B broker composition delta

A direct SSO executor is not a valid identity-enhanced execution path. The
ordinary human SSO role is invoke-only and may call exactly one qualified,
private Lambda broker alias with no Function URL, unqualified ARN, async route
or alternate trigger. The broker performs `CreateTokenWithIAM` Authorization
Code + PKCE and passes the opaque identity context through exactly one STS
`ProvidedContext` to a deny-all proof role. The proof role establishes the
human and exact operation binding but cannot mutate CloudFormation or any
downstream provider.

The broker consumes a provider-backed one-shot CAS before effect. A separate
broker service role then calls `ExecuteChangeSet` for the exact stack, UUID-
bearing Change Set and derived token. Since `RoleARN` remains absent,
CloudFormation uses the broker role's caller credentials; its downstream grants
are limited to the reviewed resource set under
`aws:CalledVia = cloudformation.amazonaws.com`. The SSO and proof roles cannot
obtain those grants. Receipts record `native_on_behalf_of = false`, so the human
proof actor is never misreported as the CloudTrail effect actor.

The application, actor policy, exact alias/version, invoke assignment, proof
role, broker role, one-shot ledger and revocation topology must preexist and be
provider-readback verified through a separate reviewed infrastructure change.
The exact handler, PEP, policy snapshot and policy contracts are already bound
into the deterministic signed ZIP. Bootstrapping those controls inside the
protected Phase B Change Set would be circular. This PR does not deploy them or
authorize a live invocation.

Embedding provider evidence in the Lambda environment would add another
circularity: a published version is an immutable environment snapshot, while
the collector can attest its alias/version only after it exists. Publishing a
second version with that receipt would immediately stale the observation. The
version therefore holds only the static topology binding and exact KMS
key/algorithm; fresh signed evidence arrives only in the synchronous event.

The static environment is not trusted merely because it was published.
`PhaseBIdentityBinding` defines one closed projection of exactly 37
string-valued variables. Direct provider readback requires the `Environment`
object to equal `{"Variables": <exact projection>}` with no sibling,
omission, expansion, type coercion or value change. The collector emits only
`environment_variables_sha256` in the Lambda state, then binds it through
`topology_state_digest` into the receipt digest and KMS signature. Raw
environment values do not enter the receipt. Thus an environment substitution
cannot remain invisible behind otherwise matching alias, version, code or
policy state.

The event is an untrusted carrier. Exact keys and the 4 KiB limit are checked
before any AWS client exists. The broker then verifies schema, freshness,
`broker_topology_sha256`, policy digests, key/algorithm, canonical digest and
KMS signature before OIDC, STS, ledger or CloudFormation access.
`ClientContext` proves only `RequestResponse`. The fresh receipt digest is
recorded downstream but cannot influence the static binding digest.

The ledger resource policy also denies every principal from removing or
replacing that policy, deleting or structurally updating the table, creating
backups/exports, restoring from PITR, changing PITR/TTL/auto scaling/streaming
destinations/tags, using broad data APIs, or enclosing the broker's direct
item permissions in a transaction. The collector requires TTL exactly
`DISABLED` with no `AttributeName`; a missing response, transitional state or
retained attribute is topology drift and blocks before data-plane access.
These denies preserve provider Get/List/Describe evidence collection and the
broker's direct exact-key one-shot CAS.

Residual boundary: DynamoDB table resource policies do not support legacy
global-table APIs, imports or restore-from-backup. The broker role omits those
permissions, but a different same-account principal needs a separately
reviewed account/organization guardrail to be denied. No account-wide
immutability or production claim is valid until that control is implemented
and live-read back.

The immediate runtime receipt proves only that the execution gate was consumed
and closure is pending. It cannot claim provider revocation. Revocation
requires read-only provider evidence of assignment and invoke-authority
removal, zero pending operations, expiry of every possible session and a still-
consumed ledger. Authorization codes, PKCE verifiers, tokens, identity-context
blobs, STS credentials, physical resource IDs and request payloads are secret or
sensitive transient values and never enter receipts or logs.

Residual TOCTOU is bounded by the short operation window, one-shot CAS, exact
alias/version and fresh provider snapshots, but is not claimed away. The
CloudFormation trace proves the broker effect lineage; a separate direct-
provider receipt proves effective state. Neither receipt is production
approval.

The nine-resource authority-account template is not an Identity Center
bootstrap. It does not create or provision the application, permission set,
assignment or materialized invoker role. Treating its
`IdentityCenterApplicationArn` or `InvokerPrincipalArn` parameters as
authority would recreate a confused-deputy boundary. A separate typed
management/Identity Center materialization and direct-provider receipt is
required before any live Change Set is eligible. That layer is absent in this
repository-only change and is an explicit live blocker.

The target receipt schema is not a trust root. A shape-valid receipt with a
self-consistent digest remains attacker-fabricable and runtime rejects it.
Only direct provider revalidation or an exact KMS-verifiable envelope may
authenticate the future receipt. All application/invoker/signing inputs then
flow through PEP and PRE_B receipts; the deployment contract has no broker
role/topology authority and downstream readback requires both PRE_B digests.

| Threat | Control | Failure behavior |
|---|---|---|
| Operator supplies a plausible but unproven Identity Center application, invoker role, signing key or Code Signing Config | Separate provider-authenticated materialization receipt; schema/self-digest alone is explicitly insufficient; the nine-resource stack never establishes this authority | `BLOCKED_IDENTITY_PRECONDITION_NOT_MATERIALIZED`; no PEP/PRE_B handoff, Change Set verification or broker invocation |
| Operator omits or changes PRE_B after PEP review | Execution, effect validation and readback require exact identity, PEP handoff/receipt and both PRE_B artifact digests before clients | Fail before STS, CloudFormation, DynamoDB or effect clients |
| Worktree, placeholder or self-consistent policy digest replaces reviewed intent | Rebuild package, template and policies from the exact Git object; compare the signed manifest; render only a closed placeholder set; bind exact 37-parameter and 9-resource read-only receipts | Handoff or Change Set verification fails; no execution authority is emitted |
| Receipt embedded before the attested alias/version exists | Static version binding; fresh signed receipt only in the one-shot payload | Missing fresh evidence denies invocation |
| Environment omits, adds or alters a binding | Exact 37-key provider projection and strict `Environment == {"Variables": exact}` equality | Collector rejects state; no receipt is eligible for signature or invocation |
| Dynamic evidence is smuggled into the immutable version | Fresh topology receipt/provider digest are excluded from the canonical environment and permitted only in the exact synchronous payload | Extra environment key is topology mismatch; deny before invocation |
| Environment drift is omitted from signed evidence | Canonical `environment_variables_sha256` is nested in provider state, then covered by `topology_state_digest`, receipt digest and KMS signature | Any projected-value change changes the signed state lineage |
| Extra field or async path smuggles authority | Exact event keys and synchronous `ClientContext`, checked before clients/CAS | Deny before KMS or effect clients |
| Forged, replayed, stale or foreign receipt | Canonical digest, freshness, static/policy/key binding and KMS `Verify` | Deny with no OIDC, STS, ledger or CloudFormation call |

AWS documents these mechanics in
[identity-enhanced IAM role sessions](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-identity-enhanced-iam-role-sessions.html),
[`CreateTokenWithIAM`](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateTokenWithIAM.html),
[application actor policies](https://docs.aws.amazon.com/singlesignon/latest/userguide/iam-auth-access-using-resource-based-policies.html),
[`AssumeRole` `ProvidedContexts`](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
and [CloudTrail `userIdentity`](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html).

## Evidence classification

| Class | Current claim |
|---|---|
| Architecture, IaC, policies, broker contracts, tests and docs | **Implemented** on one exact repository commit only |
| Named local checks | **Locally validated** only when recorded passing for that commit |
| Required GitHub checks | **CI validated** only when green for that commit |
| Deployed stacks and aliases | **Not live validated** |
| Provider-backed claim and repair | **Not executed** |
| Candidate A/B validation | **Blocked** pending `RECONCILE_VERIFIED` plus a dedicated collector SSO session |
| Independent human approval | **Blocked** |
| Production | **NO-GO** |

## References

- [ADR-047](../../ADR/ADR-047-lambda-audit-provisioning-repair.md)
- [Deployment contract](../deployment/platform-authority-lambda-audit-provisioning-repair.md)
- [Operations runbook](../operations/platform-authority-lambda-audit-provisioning-repair.md)
- [GUG-220 threat-model delta](gug-220-lambda-audit-permission-set-threat-model-delta.md)
