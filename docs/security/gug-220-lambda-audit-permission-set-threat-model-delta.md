# GUG-220 threat-model delta: Lambda audit permission-set provisioning

## Scope

This delta covers the exact Identity Center creation or reconciliation,
single-user bootstrap assignment, one-account provisioning, effective IAM
readback and private handoff for `ScanalyzeAuthorityLambdaAudit`.

It excludes group creation, foreign accounts, Lambda invocation, IAM/Lambda
mutation, broker deployment, token exchange, STS provided contexts, Change Set
operations, Terraform Apply, customer deployment, migration, destruction,
redrive and production. Production remains **NO-GO**.

The authorized GUG-220 live ledger is now consumed. The terminal result was
`UNCERTAIN_RECONCILE_ONLY`; sanitized read-only reconciliation proved the
collector permission set exists while policy, assignment, target provisioning
and collector-role verification remain absent. Replaying GUG-220 is an explicit
threat, not a recovery action. GUG-221 / ADR-047 owns a separate exact-state
repair and must leave the original ledger untouched.

## Assets

- reviewed GUG-219 policy-template bytes and canonical digest;
- exact repository source commit with byte equality for the GUG-219 template,
  policy and runtime plus the GUG-220 core and CLI;
- exact rendered target-policy digest;
- private target account and canonical live Identity Center `InstanceArn` and
  `IdentityStoreId` digest bindings;
- maximum 15-minute intent validity window;
- canonical owner-local execution-ledger directory and one stable one-shot
  work-package/target marker that records `intent_digest`;
- private immutable Identity Store principal binding;
- exact permission-set, assignment and provisioning state;
- account-local Identity Center IAM role, trust and effective policy;
- private GUG-219 collector binding; and
- sanitized status, counts and digest evidence.

## Trust boundaries

### Repository-to-provider boundary

The repository defines a portable closed contract. Live account, principal,
ARN, suffix and provider identifiers enter only through a separately approved
private intent. Provider state cannot broaden the reviewed policy.

### Management-account mutation boundary

The authorized management session may mutate only the exact permission set,
one direct `USER` assignment and one approved account target. The workflow
validates STS before effects and does not use a default profile.

### Asynchronous-result boundary

Assignment and provisioning are asynchronous. A request token and API success
are not final evidence. Unknown outcome disables all retries and permits only
read-only reconciliation.

The execution ledger is created with `O_EXCL` and the final receipt is reserved
before the first AWS write. Once the window is consumed, timeout, `OSError` or
post-write readback failure cannot return the intent to a retryable state.

### Target-account IAM boundary

Identity Center materializes an account-local IAM role with an opaque suffix.
Exact IAM trust, inline policy, attachments and boundary must be read back from
the target account. Name shape alone does not prove authority.

### Evidence-custody boundary

Raw intents, identifiers, policies, responses and bindings remain outside the
repository in owner-only create-only storage. Public evidence is sanitized and
cannot reconstruct the live principal.

Private inputs are opened with `O_NOFOLLOW` and validated from the open file
descriptor as regular files owned by the current effective user with exact
mode `0600`. This closes the symlink and path-check-to-open gap.

### Governance boundary

The current single operator may perform the bounded bootstrap, but cannot
independently approve the result. Technical session separation is not human
separation.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Generic ReadOnly or administrator role substitutes for the collector | Exact permission-set name, STS identity and account-local IAM role readback | Stop before collection |
| Policy is broadened from provider or request data | Canonical renderer and exact template/rendered digests | Mutation blocked |
| Dirty, uncommitted or rebound runtime creates authority outside review | Intent binds an existing ancestor source commit; critical bytes match that commit; one sealed policy object is used without worktree re-read | `SOURCE_COMMIT_BINDING_INVALID` or `SEALED_COLLECTOR_POLICY_MISMATCH` before effects/evidence |
| A stale or copied intent is replayed against another Identity Center control plane | Maximum 15-minute TTL plus exact live `InstanceArn`, `IdentityStoreId` and SAML provider ARN digest revalidation before every mutation | Intent rejected; new plan required |
| A pre-hardening intent v1 omits source commit, live binding or expiry | Such intents are explicitly obsolete and non-migratable | No mutation or readback authorization |
| Intent is replayed through another ledger directory | Intent contains the canonical directory digest; plan/apply require the same owner-only `0700` directory | Binding rejected |
| Concurrent or repeated apply uses the same or a different intent | One fixed work-package/target ledger filename in the canonical owner-local directory, created with `O_EXCL` before AWS writes | `EXECUTION_LEDGER_ALREADY_CONSUMED` |
| Same operator selects another private directory to bypass the lock | Only `~/.scanalyze-private-evidence/gug-220-live-v2` is accepted | Alternate directory rejected |
| Local ledger is removed or another host executes | Explicitly documented residual: owner-local marker is not immutable or cross-host | Live/production remains NO-GO; multi-operator operation requires external immutable ledger |
| Intent expires or principal/source changes between operations | Full inventory, TTL, principal, live bindings and source are revalidated immediately before each mutation | No subsequent mutation; reserved receipt records blocked/incomplete status |
| Receipt cannot be persisted after an AWS write | Receipt path is reserved with `O_EXCL`; fallback emits sanitized uncertain status with null digest and the consumed ledger remains authoritative | No retry; reconcile read-only |
| Managed policy or boundary adds hidden authority | Complete Identity Center and IAM attachment/boundary readback | `BLOCKED_DRIFT` |
| Collector gains invoke or mutation authority, including through a resource policy | Exact GUG-219 inline policy plus `DenyUnreviewedActions` with an exact `NotAction` exception set | Collector ineligible |
| A function resource policy expands a listed collector read outside the reviewed broker/account | Exact policy denies `lambda:GetPolicy` outside the broker and qualifiers, denies function-scoped list reads outside authority-account function ARNs, and leaves `Resource: "*"` only on non-resource-level discovery actions | Collector ineligible |
| Same-account resource-policy trust creates an unreviewed relay despite implicit identity deny | Exact policy explicitly denies `sts:AssumeRole`; target policy digest and trust are read back | Collector ineligible |
| Role trust points at another same-account SAML provider | The intent binds the unique planned provider digest and role readback requires exact ARN equality | Collector ineligible |
| Permission set is provisioned to a foreign account | Frozen one-target intent and complete provisioned-account readback | `BLOCKED_DRIFT` |
| Wrong user receives assignment | Exact immutable Identity Store `UserId`; one direct `USER` assignment only | Mutation/readback blocked |
| Email or profile alias is treated as authority | Identity Store and STS identities are authoritative; aliases stay outside decisions | Stop before effects |
| A group or duplicate assignment expands access | Closed assignment type/count contract | `BLOCKED_DRIFT` |
| Name collision is silently adopted | Exact description, duration, policy, attachments, boundary, assignment and target comparison | Adoption blocked |
| Timeout causes duplicate mutation | Terminal `UNCERTAIN_RECONCILE_ONLY`; no write retry | Read-only reconciliation only |
| `OSError` or post-write readback failure appears retryable | Consumed ledger plus pre-reserved `UNCERTAIN_RECONCILE_ONLY` receipt | No retry; reconcile read-only |
| Read-only evidence failure is mislabeled as deterministic drift | Dedicated `READBACK_INCOMPLETE` status with `aws_mutation_attempted = false` and ambiguity true | No drift claim; repeat read-only only |
| Partial pagination is treated as absence | Strict pagination and duplicate detection on every list surface | Evidence incomplete |
| A non-active or second Identity Center instance is silently selected | Require exactly one discovered instance and status `ACTIVE` | Plan/apply blocked |
| Local endpoint or CA overrides fabricate AWS readback | Reject global and STS/IAM/SSO/IdentityStore endpoint overrides and CA-bundle environment overrides; force configured endpoint URLs to be ignored by the AWS CLI child | Plan/apply/readback blocked |
| A later IAM page hides additive authority | Exhaust every IAM page and reject pagination-token replay | Verification blocked |
| Provisioning success is trusted without IAM verification | Target IAM role, trust, policy, attachments and boundary readback | No `READBACK_VERIFIED` |
| Inline policy changes but the existing target is not reprovisioned | Any material inline-policy change forces explicit `ProvisionPermissionSet` and target IAM readback | No verified state |
| Receipt claims verified state without both concrete objects | `READBACK_VERIFIED` requires non-null permission-set/role ARN digests and all three assignment/provisioning/role gates | Receipt rejected |
| Opaque Identity Center suffix is predicted | Discover from exact target IAM inventory and cross-check with STS | Principal binding blocked |
| Raw identity evidence leaks into Git or issue tracking | Private owner-only paths, sanitized receipts and redaction tests | Publication blocked; containment required |
| Symlink or path swap redirects a private input | Descriptor-based `O_NOFOLLOW`, `fstat`, regular-file/current-owner checks and exact `0600` mode | Input rejected |
| One operator is represented as two approvers | Explicit governance field and separate human-roster gate | Independent approval remains false |
| Candidate A/B clean result authorizes retirement | Report-only classifications and GUG-215 two-human gate | No protected effect |
| Missing GUG-217 runtime triggers deployment | Candidate sequence stops as blocked; deployment excluded | No AWS effect |
| Partial GUG-220 state is treated as permission to retry | Consumed GUG-220 ledger plus separate GUG-221 intent, private PEP and durable ledger | GUG-220 mutation remains blocked |
| GUG-221 reuses or deletes the GUG-220 ledger | Separate artifact types and provider-backed CAS record; runbook prohibition | Repair rejected and evidence incident raised |
| Broad founder/admin authority repairs the partial state | Human `ScanalyzeLambdaAuditRepair` can invoke only exact private aliases; service roles own raw APIs | Session ineligible |

## Attack-path result

The intended path is:

```text
reviewed GUG-219 policy
  -> exact private intent
  -> one bounded Identity Center mutation sequence
  -> complete Identity Center and target-IAM readback
  -> dedicated STS-validated read-only session
  -> private GUG-219 Candidate A/B sequence
  -> sanitized report-only result
```

The following paths remain denied:

```text
generic ReadOnly -> collector
administrator -> evidence collector
profile/email -> principal authority
timeout -> retry
stale or rebound intent -> mutation
same or different intent_digest -> second mutation window
different ledger directory -> apply
timeout or OSError -> retry
partial IAM page -> absence
multiple/non-ACTIVE Identity Center instances -> authority selection
inline-policy update without reprovision -> verified state
null permission-set or role ARN -> READBACK_VERIFIED
symlinked private input -> evidence ingestion
permission-set name -> assumed effective policy
one human/two sessions -> independent approval
clean Candidate B -> Change Set retirement or production
```

## Residual risks

- An organization administrator can alter the permission set or assignment
  after readback.
- Identity Center and IAM eventual consistency can produce an extended
  uncertain state.
- A direct user assignment concentrates bootstrap authority in the current
  sole operator.
- Provider policy representations may normalize JSON; canonical semantic
  comparison remains part of the trusted implementation.
- Private evidence custody is an operational control, not a provider-signed
  attestation.
- GUG-218 is detective evidence; a separate preventive guardrail is still
  required.
- GUG-215 cannot proceed safely until a second human is available.
- The GUG-220 state is partial and cannot be repaired without the separately
  reviewed GUG-221 invoke-only boundary and no-retry server-side PEP.

## Evidence classification

| Class | Status |
|---|---|
| Repository implementation | Exact reviewed GUG-220 commit only |
| Local and CI validation | Named gates for exact commit only |
| Identity Center/IAM readback | Live evidence only if complete and exact |
| Candidate A/B | Private report-only evidence |
| Independent approval | **Blocked** with one human |
| Protected effect / production | **Blocked / NO-GO** |

## Contract inventory

- `schemas/platform-authority-lambda-audit-provisioning-intent.v1.schema.json`
- `schemas/platform-authority-lambda-audit-execution-ledger.v1.schema.json`
- `schemas/platform-authority-lambda-audit-provisioning-receipt.v1.schema.json`

## References

- [ADR-046](../../ADR/ADR-046-lambda-audit-permission-set-provisioning.md)
- [Deployment contract](../deployment/platform-authority-lambda-audit-permission-set.md)
- [Operations runbook](../operations/platform-authority-lambda-audit-permission-set.md)
- [GUG-219 threat-model delta](gug-219-lambda-authority-materialization-threat-model-delta.md)
- [GUG-221 threat-model delta](gug-221-lambda-audit-provisioning-repair-threat-model-delta.md)
