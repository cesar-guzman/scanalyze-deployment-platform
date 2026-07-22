# GUG-220 — Lambda Audit Permission Set Provisioning

## Executive statement

GUG-220 closes the Identity Center provisioning boundary intentionally left by
GUG-219. It defines one exact least-privilege permission set, one bounded direct
user bootstrap assignment, one target-account provisioning operation and a
complete readback before the collector may run.

It does not authorize Lambda invocation, deployment, Change Set retirement or
production. Production remains **NO-GO**.

## Exact portable contract

The permission-set name is `ScanalyzeAuthorityLambdaAudit`, its session is
exactly `PT1H`, and its only policy source is the reviewed GUG-219 Lambda
inventory policy. It has no AWS-managed policy, customer-managed reference,
permissions boundary, Lambda invocation or IAM/Lambda mutation authority.
`DenyUnreviewedActions` denies every action outside the exact reviewed read
set, including resource-policy grants. The exact policy also denies
`sts:AssumeRole`, preventing a same-account role trust from turning the
collector session into a relay.
`DenyGetPolicyOutsideExactBroker` limits `lambda:GetPolicy` to the broker and
its qualifiers. `DenyFunctionReadsOutsideAuthorityAccount` explicitly denies
the resource-scoped Lambda list actions outside authority-account function
ARNs; only discovery actions without resource-level support retain
`Resource: "*"`.

The permission set is provisioned to exactly one approved dedicated platform-
authority account in `us-east-1`. The reviewed source pins the management and
authority account bindings because they are deployment contract values, not
secrets. Generated public evidence uses their digests; user IDs, assignment
IDs, generated ARNs and role suffixes remain private.

Each private intent is valid for no more than 15 minutes and binds canonical
digests of the live Identity Center `InstanceArn`, `IdentityStoreId` and the
unique authority-account AWS SSO SAML provider ARN. Expiry and all live
bindings are revalidated immediately before every mutation and final evidence.
Any intent v1 generated before those fields became mandatory is
obsolete, cannot be migrated or reused, and requires a new read-only plan in a
new create-only private evidence location.

The intent also binds an existing reviewed repository `source_commit`.
GUG-219 template, policy and runtime bytes plus the GUG-220 core and CLI must
equal that commit. One policy object is rendered, checked against both intent
digests and reused unchanged for effects and readback. Dirty, missing or
rebound critical source stops before provider effects or verified evidence.

`plan` and `apply` both require an explicit
`--execution-ledger-directory`. The intent binds its canonical directory
digest; the directory is owned by the current effective user, non-symlink and
mode exactly `0700`. Before the first AWS write, `apply` creates one
fixed-name `O_EXCL` ledger for the entire GUG-220 target and records the exact
`intent_digest`; it also reserves the final receipt.
Replay is `EXECUTION_LEDGER_ALREADY_CONSUMED`.

The only accepted ledger directory is
`~/.scanalyze-private-evidence/gug-220-live-v2`. The marker blocks cross-intent
replay on the same operator host/home, but is neither cross-host durable nor
resistant to deletion by that operator. It is therefore non-production
bootstrap evidence only; a multi-operator/live design needs an immutable
external ledger.

## Why readback is mandatory

Identity Center provisioning is asynchronous and creates an account-local IAM
role with an opaque suffix. An API success or permission-set name cannot prove
the effective authority.

`READBACK_VERIFIED` requires exact Identity Center name, description, duration,
policy, attachments, boundary, assignment and target plus IAM role trust bound
to the exact planned SAML provider, inline policy, attachments and boundary.
Any missing page, extra policy,
foreign assignment or target blocks the collector.

The verified receipt also requires non-null canonical digests for the exact
permission-set ARN and role ARN, and true assignment, provisioning and role
verification gates. Installing or changing the inline policy forces explicit
target reprovisioning even if the target was already provisioned.

## Ambiguous outcomes

Timeouts and unknown asynchronous responses are not retried. The state becomes
`UNCERTAIN_RECONCILE_ONLY`, and only read-only `List`, `Get` and `Describe`
reconciliation is allowed. A repair requires a new reviewed authorization.

After a write may have started, an `OSError`, provider timeout or post-write
readback failure also remains `UNCERTAIN_RECONCILE_ONLY`; the ledger is already
consumed and no retry is permitted. Readback exhausts every IAM page and
requires exactly one Identity Center instance with status `ACTIVE`.
If receipt persistence also fails, only a sanitized public uncertain status
with a null receipt digest is emitted and the ledger remains authoritative. A
later read-only observation failure is `READBACK_INCOMPLETE` with no mutation
attempt claim; it is not mislabeled as deterministic drift.

## Private evidence

The live intent, principal identifiers, permission-set and assignment ARNs,
generated role suffix, STS identity, effective policies and provider responses
remain outside Git, CI, Linear, NotebookLM, chat and public logs. Account IDs
exist only in the reviewed deployment binding; generated public evidence uses
sanitized states, counts and canonical digests.

Private files use owner-only directories, exact mode `0600`, descriptor-based
`O_NOFOLLOW`, `fstat`, regular-file and current-owner checks. Path-only symlink
checks are insufficient.

## Single-operator limitation

The current direct `USER` assignment exists only because the current roster
has one operator. It is a bootstrap assignment, not independent approval.
Using multiple profiles or sessions does not create a second human.

GUG-215 still requires two different humans for classifier and approver duties.
No GUG-220 or GUG-219 evidence may be relabeled as authorization to retire a
Change Set.

## Read-only handoff

After exact readback, the dedicated session is privately bound to GUG-219.
Candidate A materializes the deterministic allowlist and separate release
anchor; a fresh Candidate B is evaluated by GUG-218. Both captures are read-
only and a clean result remains report-only.

If the reviewed GUG-217 Lambda authority surface is absent, the sequence stops
as blocked. GUG-220 does not deploy or invoke it.

## Live outcome and repair boundary

The authorized GUG-220 execution consumed its one-shot ledger and ended
`UNCERTAIN_RECONCILE_ONLY`. A duplicate invocation was rejected before AWS
mutation. Sanitized read-only reconciliation proved the exact collector
permission set exists, but its inline policy, direct assignment, target
provisioning and account-local collector role are absent or unverified.

This is partial live evidence, not a retryable failure or a completed
collector. The GUG-220 ledger remains consumed and must not be deleted,
overwritten or reused. GUG-221 defines the only reviewed repair: an
invoke-only `ScanalyzeLambdaAuditRepair` human boundary, private server-side
PEP, exact partial-state gate, provider-backed DynamoDB CAS ledger, three
missing effects and complete SSO/IAM readback. Until GUG-221 reaches a durable
verified result, Candidate A/B remain blocked.

## Evidence state

| Evidence | State |
|---|---|
| Permission-set contracts, tests and documentation | Implemented only on exact reviewed GUG-220 commit |
| Local validation | Named gates only |
| CI validation | Exact required checks only |
| GUG-220 mutation | `UNCERTAIN_RECONCILE_ONLY`; ledger consumed |
| Identity Center and IAM state | Partial live observation; collector not verified |
| GUG-221 repair | Blocked until separate authorization and exact readback |
| Candidate A/B | Private report-only evidence only |
| Independent human approval | **Blocked** while one human is on the roster |
| GUG-215 retirement | **Blocked** pending two different humans |
| Deployment and production | **NO-GO** |

## Contract inventory

- provisioning intent v1;
- Lambda audit execution ledger v1; and
- provisioning receipt v1.

The ledger schema is
`schemas/platform-authority-lambda-audit-execution-ledger.v1.schema.json`.

## Authoritative references

Use [ADR-046](../ADR/ADR-046-lambda-audit-permission-set-provisioning.md), the
[deployment contract](../docs/deployment/platform-authority-lambda-audit-permission-set.md),
the [runbook](../docs/operations/platform-authority-lambda-audit-permission-set.md)
and the [threat-model delta](../docs/security/gug-220-lambda-audit-permission-set-threat-model-delta.md)
as the authoritative GUG-220 documentation package.

Use the sanitized
[GUG-221 source](36_GUG221_Lambda_Audit_Provisioning_Repair.md) only for the
separate repair boundary; it does not amend or reopen the GUG-220 ledger.
