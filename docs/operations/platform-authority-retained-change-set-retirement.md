# Runbook: Retire One Retained Platform-Authority Change Set

## Purpose and hard boundary

This runbook covers the separately authorized retirement of one exact,
unexecuted Change Set from the canonical empty platform-authority review shell
through the GUG-215 version-pinned Lambda PEP.

It never authorizes `ExecuteChangeSet`, `DeleteStack`, `CreateChangeSet`,
Terraform Apply, seed, customer deployment, production, migration, destruction
or redrive. The repository implementation did not deploy or invoke this path.

## ADR-050 exception route for the current one-person team

The normal procedure below remains authoritative for `TWO_HUMAN`. When César
is the only available human, the only permitted alternative is the explicit
`SINGLE_OPERATOR_NONPROD_EXCEPTION` from ADR-050. Do not simulate a second
person, reuse a normal alias or change a distinct-user assertion to `true`.

Before any AWS mutation, require a private canonical exception artifact whose
exact `authorization_digest` is reviewed and pinned by the owner. It must bind the one full Change Set ID
digest, template and inventory digests, immutable single-user digest, owner
authorization digest, exact authority account/Region and a maximum
fifteen-minute effect window. It must also bind the manually pinned Lambda
runtime-version ARN digest and prove
`RuntimeManagementConfig.UpdateRuntimeOn = Manual`. The repository artifact deliberately states
`deployment_authorized = false`.

The exception deployment exposes only:

```text
single-classify -> single-retire -> single-reconcile
```

It uses ledger v3 states `CLASSIFIED`, `EXCEPTION_ACCEPTED`, `ATTEMPTED` and
`RETIRED_RECONCILED`. Separate fresh proofs are required even though they name
the same user. The broker rechecks expiry immediately before its sole delete.
After `ATTEMPTED`, never invoke `single-retire` again; use only
`single-reconcile`, including after expiry.

The earlier owner authorization for `DeleteChangeSet` alone does not authorize
deployment of the broker, ledger, IAM, Lambda or Identity Center bindings.
Obtain a new exact deployment checkpoint before provisioning. Direct
`aws cloudformation delete-change-set` remains prohibited.

### Offline build chain required before that checkpoint

From the exact clean reviewed commit, and with all raw identifiers confined to
private owner-only JSON outside the repository:

```bash
umask 077

export PRIVATE_BROKER_VERSION_BINDING_JSON='<existing-private-0600-binding-input.json>'
export PRIVATE_EXCEPTION_INPUT_JSON='<existing-private-0600-exception-input.json>'
export SINGLE_OPERATOR_EXCEPTION='<new-private-0600-exception.json>'
export SOURCE_COMMIT="$(git rev-parse HEAD)"
export BROKER_RUNTIME_VERSION_ARN='<owner-reviewed exact runtime-version ARN>'
export PRIVATE_BROKER_PACKAGE_DIR='<new-private-package-directory>'

BROKER_VERSION_BINDING_RECEIPT="$(
  python3 scripts/deployment/platform-authority-single-operator-retirement-exception.py \
    broker-version-binding \
    --input "$PRIVATE_BROKER_VERSION_BINDING_JSON"
)"
export BROKER_VERSION_BINDING_SHA256="$(
  python3 -c \
    'import json, sys; print(json.loads(sys.stdin.read())["BrokerVersionBindingSha256"])' \
    <<< "$BROKER_VERSION_BINDING_RECEIPT"
)"

# The owner must place that exact digest in the already prepared private
# exception input. This read-only check stops before build on any mismatch.
python3 - "$PRIVATE_EXCEPTION_INPUT_JSON" "$BROKER_VERSION_BINDING_SHA256" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    exception_input = json.load(stream)
if exception_input.get("broker_version_binding_sha256") != sys.argv[2]:
    raise SystemExit("private exception input does not bind reviewed broker digest")
PY

python3 scripts/deployment/platform-authority-single-operator-retirement-exception.py \
  build \
  --input "$PRIVATE_EXCEPTION_INPUT_JSON" \
  --output "$SINGLE_OPERATOR_EXCEPTION"

python3 scripts/deployment/platform-authority-change-set-retirement-package.py \
  --source-commit "$SOURCE_COMMIT" \
  --broker-runtime-version-arn "$BROKER_RUNTIME_VERSION_ARN" \
  --broker-version-binding-sha256 "$BROKER_VERSION_BINDING_SHA256" \
  --output-directory "$PRIVATE_BROKER_PACKAGE_DIR"
```

The first command calculates the canonical binding across all published
function configuration and captures its exact digest without copying it from an
untrusted file. The read-only Python check proves the owner-prepared exception
input binds that same digest before build. The last command
rejects a dirty/non-HEAD tree, reads every package member from the exact Git
object, creates a fixed-metadata source-only ZIP, and emits a manifest whose
`lambda_code_sha256` is derived from those exact bytes. Review and pin both the
exception `authorization_digest` and package `manifest_digest` out of band.
Neither output authorizes deployment or AWS use.

## Current transport and runbook

The historical direct identity-enhanced invocation phases in this runbook
remain blocked by GUG-216 and must not be executed. ADR-043 / GUG-217 replaces
that transport with exact ordinary-session `AWS_IAM` Function URLs followed by
an in-broker deny-all STS identity proof. Use the
[GUG-217 runbook](platform-authority-identity-context-pep.md) for that future
path. It does not change the two-independent-human requirement, one-attempt
ledger or no-retry behavior in normal mode; ADR-050 replaces only the human
separation claim in its isolated exception mode.

No GUG-217 live deployment, token exchange, STS proof, Function URL invocation
or retirement has occurred. César is the sole current operator, so normal mode
stops before provisioning or invocation; ADR-050 may proceed only after its
separate exact deployment and execution checkpoint.

## Roles and separation in `TWO_HUMAN`

The workflow requires two genuinely independent IAM Identity Center users:

1. **Classifier user** — exact immutable `ClassifierIdentityStoreUserId`;
   assumes `ScanalyzeGug215ClassifierInvoker` with identity-enhanced context and
   may invoke alias `classify` only.
2. **Approver user** — a different immutable
   `ApproverIdentityStoreUserId`; assumes
   `ScanalyzeGug215ApproverInvoker` with identity-enhanced context and may
   invoke aliases `retire` and `reconcile` only.

The source permission sets are exactly `ScanalyzeAuthorityRetireClass` and
`ScanalyzeAuthorityRetireApprove`. Their provisioned roles may only call
`sts:AssumeRole` and `sts:SetContext` for the exact invoker role. The invoker
roles may call `lambda:InvokeFunction` only on their qualified aliases, and the
reviewed CLI forces `RequestResponse`. IAM does not distinguish synchronous
from asynchronous invocation for that action, so any alternate async invoke
path is a live inventory blocker. Humans receive no direct Change Set deletion
or retirement-ledger write permission.

Profiles, terminals or timestamps do not establish independent operators in
`TWO_HUMAN`. Stop that mode unless two distinct live Identity Store UserIds,
their assignments, provisioning and identity-enhanced contexts are read back.
In ADR-050 mode, require the one exact repeated UserId and never report it as
independent approval.

An ordinary SSO profile is insufficient. ADR-042 / GUG-216 implements an
offline adapter contract for `CreateTokenWithIAM` and STS `ProvidedContexts`,
but exposes no reviewed live entrypoint. The reviewed AWS-managed identity
context policy `v12` excludes `lambda:InvokeFunction`, so the current CLI fails
closed before OAuth, STS or Lambda. Stop before deployment or invocation.

## Phase 0 — Authorization and immutable deployment review

Before any AWS mutation, require a separately approved non-production change
that identifies:

- exact authority account and Region;
- exact GUG-215 implementation commit and required green CI checks;
- exact reviewed Change Set name and original-template/resource digests;
- exact versioned broker artifact, code digest, code-signing configuration and
  manually pinned runtime-version ARN;
- exact clean-commit package manifest digest, archive-derived Lambda
  `CodeSha256` and canonical `BrokerVersionBindingSha256`;
- canonical effective broker execution-policy digest;
- exact Identity Store, Identity Center Instance and Application;
- two distinct immutable Identity Store UserIds in normal mode, or one exact
  repeated UserId plus the active ADR-050 artifact digest in exception mode;
- exact source permission-set role ARNs;
- exact assignment and invoker-policy digests;
- rollback, revocation and evidence owners.

For `TWO_HUMAN`, the CloudFormation stack
`bootstrap/cfn-platform-authority-change-set-retirement-ledger.yaml` must be
planned, independently reviewed, executed and read back through a separately
authorized deployment process. For ADR-050, that review checkpoint is the
owner's review of the exact exception `authorization_digest`; it is not an
independent approval. This runbook contains no implicit authorization to deploy
either mode.

Stop if any parameter comes from a request, naming inference, chat history or
unreviewed live value.

## Phase 1 — Read back the deployed PEP boundary

Before invocation, read back and prove:

1. one dedicated table named
   `scanalyze-platform-authority-change-set-retirements` is `ACTIVE`;
2. the table has exact `retirement_id` hash key, deletion protection, KMS
   encryption, PAY_PER_REQUEST billing, no stream/replica and 35-day PITR;
3. its resource policy denies all writes outside the exact broker execution
   role;
4. the broker execution role has exactly one inline policy, no attached policy,
   no permissions boundary and Lambda-service-only trust;
5. the live canonical broker policy digest matches the deployment binding;
6. the function uses the reviewed versioned artifact, code SHA, execution role,
   code-signing configuration, `RuntimeManagementConfig.UpdateRuntimeOn = Manual`
   and exact reviewed `RuntimeVersionArn`;
7. reserved concurrency equals one;
8. exactly the three mode-specific aliases (`classify`/`retire`/`reconcile` or
   `single-classify`/`single-retire`/`single-reconcile`) point to the same
   reviewed published version, never `$LATEST`, with no weighted routing;
9. the classifier and approver permission-set assignments are bound to the two
   reviewed distinct UserIds in normal mode, or both bind the one exact UserId
   in ADR-050 mode, and are provisioned to the authority account;
10. the invoker trusts and policies contain exact identity-enhanced conditions,
    no `IfExists`, and only the expected alias invocation;
11. the Lambda function, invoked alias and resolved version have no
    resource-based policy;
12. an account-wide IAM inventory proves no foreign principal can invoke the
    function or its aliases;
13. no human role has an allow for `DeleteChangeSet` or DynamoDB writes.

Any missing, denied, partial or ambiguous readback blocks the workflow. Do not
add a broad managed policy as a shortcut.

## Phase 2 — Historical classifier command; currently blocked

The command below is retained only as historical GUG-215 interface
documentation. Do not execute it. Under GUG-216 the CLI returns
`DENY: BLOCKED_AWS_IDENTITY_CONTEXT_ACTION_UNSUPPORTED` before it creates a
token, assumes a role or invokes the qualified alias:

```bash
python3 scripts/deployment/platform-authority-change-set-retirement.py \
  broker-classify \
  --authority-account-id '<12-digit-authority-account-id>' \
  --region '<authority-region>' \
  --allow-broker-classification
```

The broker fails closed unless it proves:

- exact empty `REVIEW_IN_PROGRESS` shell;
- no service role, notifications, parent or root metadata;
- zero stack resources;
- exactly one active Change Set across all pages;
- exact full ID, `CREATE`, `CREATE_COMPLETE`, `AVAILABLE` state;
- exact original template digest, parameters, tags and four reviewed resource
  additions;
- exact runtime, identity and ledger controls.

For each of those four additions, accept only exact `Action: "Add"` with either
an omitted `Replacement` member or exact string `Replacement: "False"`.
CloudFormation documents `Replacement` as an optional `ResourceChange` member
for `Modify`; the broker converts only omitted `Add` to canonical `"False"`.
Explicit null, boolean `false`, numeric zero, case or whitespace variants,
`True`, `Conditional`, unknown strings, missing action, and every non-`Add`
action must deny as `CHANGE_SET_RESOURCES_CHANGED` before a ledger write or
delete. The accepted forms must retain the same exact inventory digest.

The repository tests for this rule use sanitized synthetic provider responses.
They are not live inventory or retirement authorization. No command in this
runbook is authorized by repository or CI evidence alone, and production
remains **NO-GO**.

In a future separately reviewed compatible implementation, only the Lambda
could create
`retirement_id = gug215#sha256:<64-hex-change-set-id-digest>` in state
`CLASSIFIED`, version 1, attempt count zero with `attribute_not_exists`.
The historical success output would be:

```text
BROKER_STATUS: CLASSIFIED
NEXT_REQUIRED_CONTROL: INDEPENDENT_APPROVAL_REQUIRED
AWS_CHANGE: exact GUG-215 broker invocation only
```

That output is not expected from the current CLI. Any future printed ledger
digest would be evidence for review, not authority outside the durable item.

## Phase 3A — Independent review (`TWO_HUMAN` only)

The second operator must review the approved private change package and live
readback without receiving direct target mutation authority. At minimum,
confirm:

- classifier and approver are the two reviewed different Identity Store users;
- the ledger is exactly `CLASSIFIED` version 1 with zero attempts;
- target, template and inventory digests match the reviewed baseline;
- broker code, effective broker policy, assignments and invoker policies match
  their deployment-bound digests;
- no original bootstrap Plan is being asserted or reconstructed;
- the approver invoker can call only `retire` and `reconcile`.

The approver's identity-enhanced invocation of `retire` is the only accepted
approval action; caller-supplied identity or approval data is rejected.

## Phase 3B — Owner checkpoint (ADR-050 only)

Do not execute Phase 3A in the single-operator mode and do not invent a second
person. Instead, the owner must compare the deployed readback to the exact
clean-commit package `manifest_digest`, package-derived `CodeSha256`,
`BrokerVersionBindingSha256`, exception `authorization_digest`, runtime pin,
target/template/inventory digests and one immutable UserId. Record
`two_human_status = NOT_PROVEN` and `independent_approval_present = false`.
This checkpoint is evidence for a later exact execution authorization; it is
not that authorization itself.

## Phase 4 — Historical approver command; currently blocked

The command below is retained only as historical GUG-215 interface
documentation. Do not execute it. The current CLI must deny before the
`ScanalyzeGug215ApproverInvoker` role or `retire` alias is reached:

```bash
python3 scripts/deployment/platform-authority-change-set-retirement.py \
  broker-retire \
  --authority-account-id '<12-digit-authority-account-id>' \
  --region '<authority-region>' \
  --allow-retire-exact-change-set
```

In a future separately reviewed compatible implementation, the broker would:

1. verify runtime, identity and ledger controls;
2. require `CLASSIFIED` version 1 or the exact resumable `APPROVED` version 2;
3. revalidate the exact target;
4. when starting from `CLASSIFIED`, write `APPROVED` version 2 through CAS;
5. write `ATTEMPTED` version 3, attempt count one through CAS;
6. revalidate the target again after the durable attempt claim;
7. compare the retirement key and every target digest to the claimed ledger;
8. issue at most one `DeleteChangeSet` request by the final full Change Set ID and
   full Stack ID, with SDK retries disabled.

Those future statuses could be `RETIREMENT_ATTEMPTED` or
`RECONCILIATION_REQUIRED`. Both require reconciliation. Never wrap this command
in a shell retry, CI retry, workflow retry, SDK retry or manual second-attempt
procedure.

If the process stops after the `APPROVED` CAS, the same reviewed approver may
resume `broker-retire`. The broker accepts that exact state and proceeds only
to the one `ATTEMPTED` claim; it does not recreate approval or delete before
the claim.

Re-invoking `broker-retire` while the ledger is `ATTEMPTED` cannot issue another
delete; it returns reconciliation required. Treat every lost or malformed
response as uncertain regardless of what the terminal displayed.

## Phase 5 — Historical reconciliation command; currently blocked

The command below is retained only as historical GUG-215 interface
documentation. Do not execute it. The current CLI must deny before the
non-delete `reconcile` alias is reached:

```bash
python3 scripts/deployment/platform-authority-change-set-retirement.py \
  broker-reconcile \
  --authority-account-id '<12-digit-authority-account-id>' \
  --region '<authority-region>' \
  --allow-broker-reconciliation
```

In a future separately reviewed compatible implementation, this alias would
have no delete branch. It compares the current full Stack ID digest
to the claimed ledger and uses that full ID for the complete resource and
Change Set inventories. If the target remains present, it returns
`RECONCILIATION_REQUIRED` without changing the ledger. A foreign or ambiguous
inventory denies. Immediately before CAS it repeats the exact Stack ID,
zero-resource and zero-Change-Set proofs. Only exact target absence and the
preserved empty `REVIEW_IN_PROGRESS` shell permit CAS to
`RETIRED_RECONCILED`, version 4, attempt count one.

The terminal ledger records effect attribution as `UNPROVEN`. Do not claim the
client response proved which path removed the metadata.

## Phase 6 — Revoke and re-run recovery preflight

After terminal reconciliation, or immediately while containing an uncertain
attempt:

1. remove both temporary Identity Center assignments;
2. provision the removals to the exact authority account;
3. read back zero matching assignments;
4. revoke/invalidate active classifier and approver sessions;
5. read back the absence of usable temporary authority;
6. verify account-level S3 Public Access Block is present and all true;
7. run a fresh, separately authorized GUG-214 recovery preflight.

GUG-215 never returns `READY`. It returns
`RETIREMENT_ROLE_REVOCATION_REQUIRED`, `PAB_AND_REVOCATION_REQUIRED`, or a
blocking/reconciliation state. Missing PAB does not authorize this runbook to
repair it.

## Stop conditions

Stop before any broker invocation, or continue only with the active mode's
reconciliation path (`reconcile` in `TWO_HUMAN`, `single-reconcile` in ADR-050)
after an attempt, when any of these is true:

- wrong account, Region, invoker role, UserId, Identity Store, Instance or
  Application;
- fewer than two genuinely independent operators in `TWO_HUMAN`, or any
  different/missing operator binding in `SINGLE_OPERATOR_NONPROD_EXCEPTION`;
- assignment, invoker policy, broker policy, code, alias, signing or concurrency
  digest/readback mismatch;
- ledger missing, malformed, unprotected, not KMS encrypted, without PITR, or
  writable by a non-broker principal;
- request payload or local artifact is proposed as target/identity authority;
- shell or Change Set metadata differs from the reviewed contract;
- target inventory is empty/multiple/foreign before classification;
- target, template, tag, parameter or four-change inventory drift;
- durable state/version/attempt count is unexpected;
- delete response is ambiguous or any attempt already exists;
- assignment/session revocation cannot be proved.
- the identity-enhanced credential adapter is absent or its context cannot be
  read back;
- the reviewed identity-context managed policy excludes the exact downstream
  `lambda:InvokeFunction` action, or its version/digest cannot be proven;
- any foreign identity or resource-based policy can invoke the broker;
- invocation is asynchronous or wrapped in an automatic retry mechanism.

## Evidence handling

Publish only sanitized status classes, digests, counts, exact commit/PR checks
and whether deployment/invocation occurred. Keep Identity Store UserIds,
assignment records, role/function/table ARNs, Lambda artifact locators, code
signing configuration, Change Set names/UUIDs, templates, ledger documents,
CloudTrail and AWS responses in the approved private evidence system.

No live stack deployment, broker invocation or Change Set deletion occurred
during GUG-215 repository implementation. Live retirement remains blocked and
production is **NO-GO**.
