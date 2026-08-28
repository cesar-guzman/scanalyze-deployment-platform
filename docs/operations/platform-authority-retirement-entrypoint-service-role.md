# Runbook: GUG-365 bounded CloudFormation service-role prerequisite

## Current status

The fixed GUG-363 CloudFormation service role is live-verified absent. The
repository contract now keeps all seven roles, the retained ledger and two
signed functions outside the GUG-363 stack. No GUG-365 IAM/DynamoDB/Lambda write, GUG-357 CloudFormation call,
broker invocation or GUG-215 effect is authorized by this runbook. Production
is **NO-GO**.

The explicitly supplied `AWSReadOnlyAccess` profile is eligible only for
authorized inventory. `ScanalyzeAuthorityBootstrapPlan` is a GUG-206 Plan duty
and is not an eligible GUG-365 executor. Do not substitute a generic
administrator profile.

## Phase 0 — repository and custody gates

Use the exact GUG-365 issue worktree. The implementation must be reviewed,
merged and revalidated on current `main` before a live plan is eligible.

```bash
git status --short --branch
git diff --check
make platform-authority-retirement-service-role-check
make platform-authority-retirement-entrypoint-check
make platform-authority-bootstrap-check
make docs-check
make security-check
```

The private GUG-363 plan and every GUG-365 artifact must remain outside Git in
an approved owner-only local root. Directories are current-owner `0700`; files
are regular one-link `0600` objects; symlinks, hard links, cloud-synchronized
paths, pre-existing outputs and copied historical plans fail closed.

## Phase 1 — build the GUG-363 plan first

Build a new GUG-363 plan from the exact merged GUG-365-hardened template and
the current signed artifact handoff. The plan remains
`deployment_authorized=false` and no AWS client is constructed.

Do not reuse a historical GUG-363 plan: its template digest and resource graph
predate the external-role-and-ledger pivot. Deliver the expected plan digest
independently from the plan file.

Build the dedicated unsigned factory package only through the offline wrapper:

```bash
python3 scripts/deployment/platform-authority-retirement-entrypoint-service-role.py package \
  --private-root "$APPROVED_PRIVATE_ROOT" \
  --source-commit "$EXACT_SOURCE_COMMIT" \
  --runtime-version-arn "$REVIEWED_RUNTIME_VERSION_ARN"
```

The explicit root must already satisfy the owner-only custody checks. The
wrapper refuses links, cloud/FileProvider paths, pre-existing outputs and
unsafe modes; it writes atomically with `0600` files and performs no AWS call.

## Phase 2 — build the GUG-365 plan offline

The GUG-365 compiler consumes only the validated GUG-363 plan and its separately
reviewed expected digest plus a separately validated factory-package signing
contract and expected digest. It must emit a new owner-only plan whose
projections show:

- the exact six managed policies and their canonical documents;
- the exact CloudFormation-only trust policy;
- all seven fixed roles, their trusts, paths, maximum sessions, tags and exact
  main/factory terminal states;
- zero inline policies, exactly one attached policy per main role and the
  proof-bound/detached terminal factory state;
- the retained table, exact resource policy, deletion protection, KMS
  encryption and 35-day PITR contract;
- both dedicated package manifests and exact signed S3 object version, KMS key,
  code digest and Code Signing Config bindings;
- all ordered, non-overlapping authorization phases plus a forward-disabled
  revocation contract, with one attempt per operation and no
  retry/repair/delete;
- an explicit deny-all proof policy, causal factory receipt and consistent
  count-only ledger `Scan` gate proving zero items before activation;
- complete IAM and DynamoDB readbacks and closed pagination; and
- `deployment_authorized=false`, `production=false` and
  `independent_approval_present=false`.

Keep raw account/caller/ARN/policy data private. Only sanitized classifications
and digests may be copied to Linear.

Compile the exact private plan with independently delivered expected digests:

```bash
python3 scripts/deployment/platform-authority-retirement-entrypoint-service-role.py plan \
  --private-root "$APPROVED_PRIVATE_ROOT" \
  --gug363-plan "$PRIVATE_GUG363_PLAN" \
  --expected-gug363-plan-digest "$EXPECTED_GUG363_PLAN_DIGEST" \
  --ledger-factory-signing-contract "$PRIVATE_FACTORY_SIGNING_CONTRACT" \
  --expected-ledger-factory-signing-contract-digest \
    "$EXPECTED_FACTORY_SIGNING_CONTRACT_DIGEST"
```

This command is create-only and refuses to overwrite an earlier output. A new
attempt requires a new reviewed private root; historical artifacts are never
resumed in place.

## GUG-390 — guarded live CLI mechanism

GUG-390 provides a reviewed bridge from the offline plan to a guarded provider.
The mechanism is present; no AWS execution, deployment or production use is
authorized by this runbook. Every command takes one owner-only request under a
private root:

Before creating that request, refresh the source binding. The CLI intentionally
does not fetch; its `HEAD == refs/remotes/origin/main` check only proves equality
with the local remote-tracking ref. Run the following in the same maximum
15-minute window used by the new owner checkpoint:

```console
git fetch --no-tags origin refs/heads/main:refs/remotes/origin/main
git rev-parse --verify HEAD^{commit}
git rev-parse --verify HEAD^{tree}
git rev-parse --verify refs/remotes/origin/main^{commit}
git rev-parse --verify refs/remotes/origin/main^{tree}
test "$(git rev-parse --verify HEAD^{commit})" = "$(git rev-parse --verify refs/remotes/origin/main^{commit})"
test "$(git rev-parse --verify HEAD^{tree})" = "$(git rev-parse --verify refs/remotes/origin/main^{tree})"
git diff --quiet
git diff --cached --quiet
test -z "$(git ls-files --others --exclude-standard)"
```

Require the fetched commit to equal `HEAD`, bind that commit and its tree into
both request and owner checkpoint, and record the fetch time privately. Stop on
a failed/stale fetch, mismatch, dirty or untracked file, or any source change
after fetch. Re-fetch and issue a new request/checkpoint; never refresh only the
digest on an old request.

```console
env -u PYTHONPATH -u PYTHONHOME -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME python3 -I scripts/deployment/platform-authority-gug390-live-provider.py inventory --private-root "$APPROVED_PRIVATE_ROOT" --request "$PRIVATE_REQUEST_BASENAME"
env -u PYTHONPATH -u PYTHONHOME -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME python3 -I scripts/deployment/platform-authority-gug390-live-provider.py execute-phase --private-root "$APPROVED_PRIVATE_ROOT" --request "$PRIVATE_REQUEST_BASENAME"
env -u PYTHONPATH -u PYTHONHOME -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME python3 -I scripts/deployment/platform-authority-gug390-live-provider.py reconcile --private-root "$APPROVED_PRIVATE_ROOT" --request "$PRIVATE_REQUEST_BASENAME"
env -u PYTHONPATH -u PYTHONHOME -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME python3 -I scripts/deployment/platform-authority-gug390-live-provider.py certify --private-root "$APPROVED_PRIVATE_ROOT" --request "$PRIVATE_REQUEST_BASENAME"
```

The CLI selects no default command. Do not run these commands with an
improvised request or profile; a later owner checkpoint must name the exact
command, phase, account, region, profile, source commit/tree, plan, validity
window and custody bindings. AWS-capable requests also bind the exact STS
principal digest and direct SSO role-name digest; `execute-phase` binds both
inventory snapshot digests and their complete facts digest; `certify` binds
all eight phase-run digests, both final snapshot digests and the independent
ACTIVATOR checkpoint digest.

Set `APPROVED_PRIVATE_ROOT` to the already reviewed absolute owner-only `0700`
directory. Before each invocation, set `PRIVATE_REQUEST_BASENAME` to that
command's exact `0600` request filename inside the root; it must be a basename
ending in `.json`, never a path or one request reused across commands.

Do not omit the environment cleanup or `-I`. The CLI fails closed before
repository imports if any listed variable is present, if a `tooling` or
boto3/botocore module is already loaded, if another `tooling` package would win
resolution, or if any loaded repository module's `__file__`, import origin or
package path is outside the exact Git root. The bootstrap replaces custom
meta/path finders with a closed standard loader set, removes every repository
path from `sys.path`, and explicitly loads the package entry modules from the
Git-blob manifest. The manifest-bound `tooling` loader reads reviewed `.py`
bytes directly and cannot fall back to an ignored `.pyc`, extension or
sourceless module. A separately installed, unimported `tooling` package is
admissible only below the isolated interpreter's exact `purelib`/`platlib`
root; it remains discoverable for dependency resolution but is never executed
or accepted as repository provenance. That exact site root is retained even
for an in-repository clean-clone `.venv`; other repository paths are removed.
The gate rejects `PYTHONPATH`, `PYTHONHOME`, `_PYTHON_PROJECT_BASE` and
`_PYTHON_SYSCONFIGDATA_NAME` before discovering those roots.
Use `-S` only for
parser/help import-inert checks: an authorized
live command intentionally retains isolated non-repository site-package
discovery so the pinned boto3 runtime remains available, and the provider
imports it only after all local source, request, custody and
provider-construction gates pass.

Keep the similarly named digests distinct throughout custody and review:

| Binding | Meaning |
| --- | --- |
| `owner_checkpoint_digest` | Seal of the fresh owner checkpoint consumed by the command. |
| Private `request_digest` / public `live_request_digest` | Seal of the complete private live request. The public record must use `live_request_digest`, never the ambiguous private name. |
| `checkpoint_digest` | Result checkpoint for inventory, phase ledger or ACTIVATOR certification; it is not the owner checkpoint. |
| Ledger operation `request_digest` | Seal of one exact provider operation request in the ordered phase plan. |

For `execute-phase`, the ledger claim's GUG-390 `execution_context` binds the
owner checkpoint, live request, nullable ACTIVATOR checkpoint and their
`context_digest`. Each durably recorded provider outcome may bind the exact
identity receipt, transcript, request/result and optional causal receipt in
`durable_provider_evidence`. Legacy claims/outcomes omit these fields. Omission
after a hard crash remains visible and is never treated as complete evidence.

The closed verb contract is:

| Verb | AWS effect boundary | Admissible result |
| --- | --- | --- |
| `inventory` | Read-only, with STS first, all pagination closed and canonical plan-vs-provider comparison. | Two equal complete snapshots and a classification; never mutation. |
| `execute-phase` | One explicitly named phase in one fresh process. | One terminal phase receipt or `UNCERTAIN_RECONCILE_ONLY`; never automatic continuation. |
| `reconcile` | Read-only provider state for one recorded ambiguous/in-flight operation. | Conclusive reconciled receipt or preserved uncertainty; never a repeated write. |
| `certify` | Receipt/readback validation only. | Sanitized manifest or fail-closed rejection; never AWS mutation. |

Repository and CI exercises must use injected fakes. Their maximum truthful
claim is `AWS_CALLS=0`, `AWS_MUTATIONS=0`, `LIVE_PROVIDER_EVIDENCE=false`,
`status=LIVE_PROVIDER_NOT_PROVEN`, `deployment_authorized=false`,
`deployment_status=NOT_DEPLOYED` and `production_status=NO-GO`. Passing tests
or merging the implementation does not prove AWS identity, inventory,
authorization, execution or deployment.

Before any separately authorized live process constructs an effect-capable
client, all of the following must be present and exact:

- the reviewed merged commit/tree, private plan and independently delivered
  expected digests;
- an explicit non-default short-lived profile, exact account and `us-east-1`;
- a fresh phase-specific owner checkpoint, exact principal/SSO-role binding, validity window,
  workstation/custody binding and unused ledger root;
- stable complete before-state snapshots whose independent digests and full
  facts digest are request-bound, closed pagination, exact predecessor
  receipts and the phase's closed operation/request digests; and
- effective-authority evidence proving the phase grant is both the sole grant
  and its maximum cap, with no ambient/default/chained credential fallback.

STS caller identity is the first AWS call and must match the checkpoint. The
window gate runs again immediately before initial STS and before every later
SDK call or page; expiration stops before that call.
Missing, stale, incomplete or extra evidence is `STOP_NO_MUTATION`; a process
must not borrow another phase's session or authority.

The two live snapshots must also pass semantic comparison against the sealed
plan. Equality of two observed digests alone is insufficient: signed S3 body,
version and KMS binding; KMS metadata; Code Signing Config; IAM documents,
relationships and tags; Lambda configuration/runtime/concurrency/version/tag
state; log-group controls/tags; and DynamoDB table/PITR/TTL/policy/tag/count
state must match their exact projections. Stable drift remains no-touch.

## GUG-395 pre-plan seed and downstream GUG-393 verification

### Step 1 — materialize only the offline GUG-395 seed and pending plan

Fetch the exact merged `origin/main` commit/tree and require a clean isolated
checkout. Create one owner-only directory outside Git, worktrees, synced/File
Provider paths and repository roots. Set the directory to `0700`, every input
and output to `0600`, `umask 077`, and `set -o noclobber` before creating any
final artifact.

Prepare `gug395-owner-input.json` privately from the closed GUG-395 contract.
It binds the exact source commit/tree, the complete ordered owner-decision set
and both deterministic package inputs. It must not contain a GUG-363 plan, a
GUG-365 plan or invented provider-generated slots. Never paste its contents,
accounts, user identifiers, ARNs or paths into Git, CI or issue comments.

Use the reviewed Python 3.11.14 runtime and clear Python path and AWS credential
bindings. Capture `GUG395_CREATED_AT` from the actual current UTC action time;
do not reuse an example or prior receipt timestamp. These commands perform no
AWS call:

```console
umask 077
set -o noclobber
GUG395_PYTHON=/absolute/path/to/reviewed-python-3.11.14
GUG395_PRIVATE_ROOT=/absolute/private/root
GUG395_REPO_ROOT=/absolute/clean/origin-main/checkout
GUG395_CREATED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

test -d "$GUG395_PRIVATE_ROOT"
chmod 0700 "$GUG395_PRIVATE_ROOT"

env -u PYTHONPATH -u PYTHONHOME \
  -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME \
  -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_ACCESS_KEY_ID \
  -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  "$GUG395_PYTHON" -I -S \
  scripts/deployment/platform-authority-gug395-preplan-seed.py catalog

env -u PYTHONPATH -u PYTHONHOME \
  -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME \
  -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_ACCESS_KEY_ID \
  -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  "$GUG395_PYTHON" -I -S \
  scripts/deployment/platform-authority-gug395-preplan-seed.py seed \
  --repo-root "$GUG395_REPO_ROOT" \
  --private-root "$GUG395_PRIVATE_ROOT" \
  --owner-input gug395-owner-input.json \
  --output gug395-preplan-seed.json \
  --created-at "$GUG395_CREATED_AT"

env -u PYTHONPATH -u PYTHONHOME \
  -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME \
  -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_ACCESS_KEY_ID \
  -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  "$GUG395_PYTHON" -I -S \
  scripts/deployment/platform-authority-gug395-preplan-seed.py plan \
  --repo-root "$GUG395_REPO_ROOT" \
  --private-root "$GUG395_PRIVATE_ROOT" \
  --seed gug395-preplan-seed.json \
  --output gug395-mutation-plan.json
```

Review only the emitted status and digests. Expected status remains offline
with `AWS_CALLS=0`, `AWS_MUTATIONS=0`, `deployment_authorized=false` and
production `NO-GO`. The `seed` command validates and source-verifies its public
receipt before publishing the create-only seed, then rereads the seed and
revalidates the same receipt after publication. An invalid receipt timestamp
therefore leaves no seed output to recover or overwrite.

GUG-395 itself stops here. ADR-056 now provides the next additive read-only
collision boundary, but a merge or offline test is not a connected run.
This iteration makes the collision request, concrete read-only provider,
four-session executor, durable blocked-attempt evidence and public receipt
repository-ready. It does not authorize or implement a mutation run, staging
acceptance or production deployment. Do not run GUG-393/GUG-392 v1 as a
substitute: their exact collectors require final ARNs and are post-run only.

### Step 1b — materialize and run the ADR-056 collision probe

Do not use the dirty primary checkout. After this implementation is reviewed,
merged and fetched, use one clean worktree at exact `origin/main`. The private
root must be the same owner-only `0700` root bound by the GUG-395 seed. The
profile-binding input is a `0600` private JSON file and contains both exact
direct-SSO read-only profile bindings; never pass a profile or principal on the
command line and never use a default, administrator, bootstrap, seed, deploy
or destroy profile.

Its exact shape is shown below. Replace every placeholder privately; each
digest is `sha256:` plus 64 lowercase hexadecimal characters. The principal
digest is over the exact expected STS assumed-role ARN, not over the profile
name, and no ARN is copied into the public receipt.
`canonical_digest(string)` is SHA-256 over that string's canonical JSON bytes,
including the JSON quotes and escapes; it is not the digest of the raw unquoted
bytes. Generate each principal-ARN and direct-role-name digest without echoing
the private value or putting it in shell history:

```console
env -u PYTHONPATH -u PYTHONHOME \
  -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME \
  "$GUG395_PYTHON" -I -S -c 'import getpass,hashlib,json; value=getpass.getpass("Exact private string: "); encoded=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("utf-8"); print("sha256:"+hashlib.sha256(encoded).hexdigest())'
```

Run it once for each exact value and copy only the digest into the private
binding file. Each `authority_verification_digest` must come from an
independently reviewed effective-authority evidence record for that exact
profile, account and validity window. It is not the digest of the checked-in
policy template and must not be invented or self-asserted. If that evidence is
missing or does not prove the closed read-only surface, stop with
`HUMAN_DECISION_REQUIRED` before materialization.

```json
{
  "authority": {
    "name": "REDACTED_DIRECT_SSO_READ_ONLY_PROFILE",
    "expected_account_id": "000000000000",
    "expected_principal_digest": "sha256:REDACTED_64_HEX",
    "expected_sso_role_name_digest": "sha256:REDACTED_64_HEX",
    "authority_verification_digest": "sha256:REDACTED_64_HEX"
  },
  "identity_center": {
    "name": "REDACTED_DISTINCT_DIRECT_SSO_READ_ONLY_PROFILE",
    "expected_account_id": "111111111111",
    "expected_principal_digest": "sha256:REDACTED_64_HEX",
    "expected_sso_role_name_digest": "sha256:REDACTED_64_HEX",
    "authority_verification_digest": "sha256:REDACTED_64_HEX"
  }
}
```

Before materialization, record the exact merged commit and tree:

```console
umask 077
set -o noclobber
GUG395_COLLISION_SOURCE_COMMIT="$(git rev-parse HEAD)"
GUG395_COLLISION_SOURCE_TREE="$(git rev-parse HEAD^{tree})"
test "$(git rev-parse origin/main)" = "$GUG395_COLLISION_SOURCE_COMMIT"
test -z "$(git status --porcelain)"

# Replace both reviewed values privately before running this block.
GUG395_SDK_RUNTIME_ROOT=/absolute/reviewed/sdk-runtime-root
GUG395_COLLISION_APPROVAL_DIGEST=sha256:REVIEWED_64_LOWERCASE_HEX

test -d "$GUG395_SDK_RUNTIME_ROOT"
case "$GUG395_SDK_RUNTIME_ROOT" in /*) ;; *) exit 1 ;; esac
"$GUG395_PYTHON" -I -S -c \
  'import re,sys; assert re.fullmatch(r"sha256:[0-9a-f]{64}",sys.argv[1])' \
  "$GUG395_COLLISION_APPROVAL_DIGEST" || exit 1

# Capture the freshly approved action-time window. The implementation accepts
# at most fifteen minutes and treats expires-at as exclusive.
GUG395_COLLISION_NOT_BEFORE="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
GUG395_COLLISION_EXPIRES_AT="$(
  "$GUG395_PYTHON" -I -S -c \
  'from datetime import datetime,timedelta,timezone; import sys; value=datetime.fromisoformat(sys.argv[1].replace("Z","+00:00"))+timedelta(minutes=15); print(value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z"))' \
  "$GUG395_COLLISION_NOT_BEFORE"
)"

GUG395_COLLISION_REQUEST_FILE="$GUG395_PRIVATE_ROOT/gug395-preplan-collision-request.json"
GUG395_COLLISION_MATERIALIZATION_OUTPUT="$GUG395_PRIVATE_ROOT/gug395-preplan-collision-materialization-output.json"
test ! -e "$GUG395_COLLISION_REQUEST_FILE"
test ! -e "$GUG395_COLLISION_MATERIALIZATION_OUTPUT"
```

Materialization is offline and create-only:

```console
env -u PYTHONPATH -u PYTHONHOME \
  -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME \
  -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_ACCESS_KEY_ID \
  -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  "$GUG395_PYTHON" -I -S \
  scripts/deployment/platform-authority-gug395-preplan-collision-probe.py \
  materialize-request \
  --private-root "$GUG395_PRIVATE_ROOT" \
  --seed-file gug395-preplan-seed.json \
  --plan-file gug395-mutation-plan.json \
  --profile-bindings-file gug395-preplan-collision-profile-bindings.json \
  --sdk-runtime-root "$GUG395_SDK_RUNTIME_ROOT" \
  --source-commit-sha "$GUG395_COLLISION_SOURCE_COMMIT" \
  --source-tree-sha "$GUG395_COLLISION_SOURCE_TREE" \
  --approval-reference-digest "$GUG395_COLLISION_APPROVAL_DIGEST" \
  --not-before "$GUG395_COLLISION_NOT_BEFORE" \
  --expires-at "$GUG395_COLLISION_EXPIRES_AT" \
  > "$GUG395_COLLISION_MATERIALIZATION_OUTPUT" || exit 1

chmod 0600 "$GUG395_COLLISION_MATERIALIZATION_OUTPUT"
GUG395_COLLISION_REQUEST_DIGEST="$(
  "$GUG395_PYTHON" -I -S -c \
  'import json,re,sys; from pathlib import Path; request=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")); output=json.loads(Path(sys.argv[2]).read_text(encoding="utf-8")); digest=request.get("request_digest"); assert isinstance(digest,str) and re.fullmatch(r"sha256:[0-9a-f]{64}",digest) and output.get("request_digest")==digest; print(digest)' \
  "$GUG395_COLLISION_REQUEST_FILE" \
  "$GUG395_COLLISION_MATERIALIZATION_OUTPUT"
)" || exit 1
```

Expected output is digest-only with
`PRIVATE_COLLISION_REQUEST_MATERIALIZED`, `AWS_CALLS=0`, `AWS_MUTATIONS=0`,
`deployment_authorized=false` and `production_status=NO-GO`.
The command above captures that output create-only under the private root and
derives `GUG395_COLLISION_REQUEST_DIGEST` only after the persisted request and
the digest-only output agree. Review those status fields and digests before
continuing; do not paste either private file into Git, CI or issue comments.

The connected command is permitted only after the owner freshly confirms both
profile names, expected accounts, exact expected SSO roles, `us-east-1`, the
maximum fifteen-minute window and every action in ADR-056. It performs four
direct-SSO session bootstraps and zero to four actual credential-vending
requests depending on valid SDK cache state. It performs only the closed
read-only inventory and no AWS mutation. Launch it from an empty environment
and restore only `HOME`, `PATH` and `TMPDIR`; a partial `env -u` list is not
sufficient because every ambient `AWS_*` override is fail-closed:

IAM Identity Center may require the dependent `kms:Decrypt` permission for
List/Describe reads when its instance uses a customer managed KMS key. The
deployable Identity policy template includes only the reviewed indirect grant:
`${identity_center_kms_key_arn}`, `${management_account_id}`,
`kms:ViaService=sso.us-east-1.amazonaws.com`, the exact
`${identity_center_instance_arn}` encryption context and the same window. The
adapter never constructs a KMS client or dispatches a KMS call; it sends only
the request-bound SSO operations. Before the connected command, the independent
effective-authority evidence must bind that exact CMK grant. A missing or
mismatched key/context/grant is reconciliation-only; do not broaden it during a
running request.

```console
GUG395_COLLISION_NOW="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
GUG395_COLLISION_PROBE_OUTPUT="$GUG395_PRIVATE_ROOT/gug395-preplan-collision-probe-output.json"
test ! -e "$GUG395_COLLISION_PROBE_OUTPUT"
GUG395_COLLISION_PROBE_EXIT=0

env -i \
  HOME="$HOME" \
  PATH="$PATH" \
  TMPDIR="${TMPDIR:-/tmp}" \
  "$GUG395_PYTHON" -I -S \
  scripts/deployment/platform-authority-gug395-preplan-collision-probe.py \
  probe \
  --private-root "$GUG395_PRIVATE_ROOT" \
  --request-digest "$GUG395_COLLISION_REQUEST_DIGEST" \
  --source-commit-sha "$GUG395_COLLISION_SOURCE_COMMIT" \
  --source-tree-sha "$GUG395_COLLISION_SOURCE_TREE" \
  --now "$GUG395_COLLISION_NOW" \
  > "$GUG395_COLLISION_PROBE_OUTPUT" || GUG395_COLLISION_PROBE_EXIT=$?

chmod 0600 "$GUG395_COLLISION_PROBE_OUTPUT"
case "$GUG395_COLLISION_PROBE_EXIT" in 0|2) ;; *) exit "$GUG395_COLLISION_PROBE_EXIT" ;; esac
```

Exit `0` means a completed collision classification; exit `2` means the
attempt was durably sealed as blocked. Any other exit is an execution failure:
preserve the request, claim, output and result paths exactly as written and do
not delete or overwrite them.

The executor publishes one authoritative create-only private file,
`gug395-preplan-collision-result.json`, containing private evidence and the
deterministically reconstructed digest-only receipt. The bundle also binds the
exact private-root, request and claim digests, and every snapshot binds its
session transcript segment; copying the bundle without the same request and
claim custody is invalid. This single-file commit avoids treating two separate
filesystem writes as atomic. Validate it without AWS calls using:

```console
env -u PYTHONPATH -u PYTHONHOME \
  -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME \
  -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_ACCESS_KEY_ID \
  -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  "$GUG395_PYTHON" -I -S \
  scripts/deployment/platform-authority-gug395-preplan-collision-probe.py \
  validate-receipt \
  --private-root "$GUG395_PRIVATE_ROOT" \
  --result-file gug395-preplan-collision-result.json
```

Interpret only the sealed public classification:

| Classification | Meaning and next action |
|---|---|
| `ABSENT_READY_FOR_PROVIDER_IMPLEMENTATION` | Contract classification requiring independently conclusive absence for all seven targets. The current concrete HeadBucket route cannot establish it, so it is not reachable from this connected read-only implementation. |
| `COLLISION_BLOCKED_NO_MUTATION` | At least one name, alias or tag matched. Preserve evidence; do not adopt, repair, delete or retry. |
| `UNCERTAIN_RECONCILE_ONLY` | Partial, denied, over-budget, unstable, malformed or prerequisite evidence. Preserve the claim and reconcile read-only under a new reviewed request. |

`s3:HeadBucket` is mandatory for the global bucket name. A non-followed `301`
or successful response is collision. AWS documents `400`, `403` and `404` as
generic results for either a missing bucket or missing permission and supplies
no response body that disambiguates them. All three are uncertainty, never
absence. Automatic S3 region redirection is disabled so one logical call cannot
conceal a second unbudgeted request. Because no operation in this read-only
surface proves global bucket-name absence, do not promote a connected run to
`ABSENT_READY_FOR_PROVIDER_IMPLEMENTATION`.

Signer inventory explicitly includes `Active`, `Canceled` and `Revoked`
profiles, and every retained name or reviewed-tag match blocks mutation.

Any denied, timed-out, malformed, over-budget or otherwise blocked attempt is
sealed as `LIVE_READ_ONLY_PROBE_BLOCKED` when private custody remains writable.
That receipt leaves `aws_calls`, `network_calls` and
`modeled_cost_usd_upper` as `null`, reports reconciliation-only, and the CLI
exits with status `2`. Preserve the atomic bundle and claim; a claim is
one-shot and must never be deleted to retry.

### Step 2 — require nine phases and an independently verified handoff

There is no live mutation-phase command in this step. A future separately
reviewed mutation provider/nine-phase executor must perform its own name/tag
collision preflight, obtain a
fresh action-time authorization for each phase, consume one durable attempt
before each write, and certify all nine phases and thirty operations.

After that future run, `validate-terminal` may check the serialized handoff's
shape and bindings:

```console
env -u PYTHONPATH -u PYTHONHOME \
  -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME \
  -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_ACCESS_KEY_ID \
  -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  "$GUG395_PYTHON" -I -S \
  scripts/deployment/platform-authority-gug395-preplan-seed.py \
  validate-terminal \
  --repo-root "$GUG395_REPO_ROOT" \
  --private-root "$GUG395_PRIVATE_ROOT" \
  --seed gug395-preplan-seed.json \
  --plan gug395-mutation-plan.json \
  --handoff gug376-mutation-terminal-handoff.json
```

Current v1 always stops with `STOP_LIVE_EXECUTION_PLAN_NOT_IMPLEMENTED`; it
cannot reach `EXTERNAL_ATTESTATION_REQUIRED` and cannot mint terminal
authority. GUG-395 deliberately exposes no terminal-capability minter. The
checked-in downstream fixture therefore reports
`SYNTHETIC_CONTRACT_ONLY_BLOCKED`, and its shape validator is non-certifying.

After a future separately reviewed provider, executor, terminal contract and
trusted capability minter close those gates, the in-process downstream builder
may validate only the post-phase GUG-363 intent/plan, actual package archives
and both signing contracts. Its capability-gated receipt must report
`READY_FOR_GUG365_FRESH_CHECKPOINT`,
`gug365_plan_materialized=false`, zero new AWS calls and zero mutations. It
does not accept or emit a GUG-365 plan or `source-bundle.json`.

Next, the original GUG-365 run performs a fresh read-only provider checkpoint
and compiles its own plan. Its capability must bind the authoritative
downstream receipt digest and private-manifest digest. Only a separate
post-checkpoint helper may validate that receipt and fresh plan and derive
`source-bundle.json`; it must require the exact verifier, source, seed,
mutation-plan, terminal-handoff, GUG-363, package and signing digests from one
causal run, then prove that the derived exact target projections equal the
terminal provider handoff. The repository intentionally exposes no CLI that
can replace either in-process capability with a self-sealed JSON document.

### Step 3 — run GUG-393/GUG-392 exact verification post-phase

Use the remaining lane only after all nine phases, independent terminal
verification, and certified downstream materialization produced the complete
GUG-363 plan, fresh GUG-365 plan and `source-bundle.json` from the same source
commit/tree. It is a non-production read-only verification, not a shortcut to
deployment. Do not use any administrator, bootstrap, seed, deploy, destroy,
default, chained, or production-write profile.

Use the reviewed `GUG392_PYTHON` runtime prepared by the GUG-392 prerequisite
runbook. It must report exactly Python 3.11.14. Every operational invocation
below deliberately disables Python path overrides and starts in isolated,
no-site mode.

Keep the certified `source-bundle.json` create-only in the same private
custody. Do not hand-author it from the
[legacy source-bundle template](platform-authority-gug393-source-bundle.example.json);
that file illustrates the closed post-phase shape only and its empty plans
remain deliberately non-runnable. Prepare only these additional private
inputs from their templates:

- the [profile-bindings template](platform-authority-gug393-profile-bindings.example.json),
  replacing both direct-SSO profile names, accounts, expected STS principals,
  expected SSO role names, and authority-verification digests; and
- the [global-budget template](platform-authority-gug393-discovery-budget.example.json),
  replacing every illustrative USD value, pricing-reference digest and window
  with an owner-reviewed model. The selected call/page/byte ceilings may be
  lower than, but never exceed, the template's hard ceilings.

The templates are deliberately non-runnable: replacement markers, placeholder
accounts and zero digests fail closed. Never modify a template in the
repository.

Record a digest-only custody readback for all three final inputs. These three
file digests prove local canonical integrity only; they are not aliases for
the derived `source_contract_digest`, transformed `profile_binding_digest`, or
validated `budget_digest` later sealed in the request/checkpoint:

```console
for GUG393_INPUT_BASENAME in \
  source-bundle.json profile-bindings.json discovery-budget.json
do
  env -u PYTHONPATH -u PYTHONHOME \
    -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME \
    GUG393_INPUT_FILE="/absolute/private/root/$GUG393_INPUT_BASENAME" \
    "$GUG392_PYTHON" -I -S -c 'import hashlib,json,os; from pathlib import Path; path=Path(os.environ["GUG393_INPUT_FILE"]); value=json.loads(path.read_text(encoding="utf-8")); encoded=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("utf-8"); print(path.name+" sha256:"+hashlib.sha256(encoded).hexdigest())'
done
unset GUG393_INPUT_BASENAME GUG393_INPUT_FILE
```

First materialize the request and checkpoint offline. Replace every bracketed
token locally; do not paste private values into logs or issue comments.

```console
env -u PYTHONPATH -u PYTHONHOME \
  -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME \
  "$GUG392_PYTHON" -I -S \
  scripts/deployment/platform-authority-gug392-live-provider.py \
  materialize-discovery-request \
  --private-root /absolute/private/root \
  --source-bundle-file source-bundle.json \
  --profile-bindings-file profile-bindings.json \
  --budget-file discovery-budget.json \
  --sdk-runtime-root /absolute/reviewed-sdk-target \
  --not-before 2099-01-01T00:00:00Z \
  --expires-at 2099-01-01T00:15:00Z \
  --approval-reference-digest sha256:REDACTED
```

The illustrative future timestamps and redacted digest above are not valid
runtime substitutions. The owner must review the real source-contract,
request, checkpoint, profile-binding, and budget digests. Only then run the
connected preflight with the exact independently delivered values:

```console
GUG393_DISCOVERY_RECEIPT=/absolute/private/root/gug393-discovery-receipt.json
test ! -e "$GUG393_DISCOVERY_RECEIPT"
env -u PYTHONPATH -u PYTHONHOME \
  -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME \
  "$GUG392_PYTHON" -I -S \
  scripts/deployment/platform-authority-gug392-live-provider.py \
  discover-inputs \
  --private-root /absolute/private/root \
  --expected-request-digest sha256:REDACTED \
  --expected-checkpoint-digest sha256:REDACTED \
  --approval-reference-digest sha256:REDACTED \
  > "$GUG393_DISCOVERY_RECEIPT"
env -u PYTHONPATH -u PYTHONHOME \
  -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME \
  "$GUG392_PYTHON" -I -S \
  scripts/deployment/platform-authority-gug392-live-provider.py \
  validate-discovery-receipt "$GUG393_DISCOVERY_RECEIPT"
```

This command claims the request once, rechecks the host/source/private-root/
SDK/window/budget bindings, and then constructs the connected provider. It
also proves every fixed provider-evidence, proposal, decision, GUG-392
input/plan, snapshot, and manifest target absent before the claim or any
provider call. A custom request or checkpoint filename cannot reuse any
reserved lifecycle output name. It counts actual SSO credential-vending
attempts plus every closed inventory API call in one atomic budget. Each
session performs STS first. Authority uses two sessions. Identity Center
absence uses two sessions; exact state uses two discovery/exact session pairs.
All snapshots, the fixed create-only
`gug393-discovery-provider-evidence.json`, and the proposal remain private.
The provider-evidence file is written before the proposal, is never selected
by the caller, and seals both the provider transcript events and the global
budget event journal. The journals use fixed, self-describing compact rows,
and validation reconstructs the exact full events before replay. The complete
document remains inside the unchanged 4 MiB private JSON custody limit at the
hard ceilings of 5,000 provider calls, 4,300 page calls, and six
credential-vending calls. Only the digest-only receipt is captured; it
includes `provider_evidence_digest`, and the second command reconstructively
validates its seal and closed no-mutation/no-production fields before owner
review.

Every session is one-shot and exact-policy bound. The Identity exact stage is
opened only after the same capture's concrete discovery reader attests the
successful STS/discovery transcript and normalized discovery result; targets
are recomputed from that attested result. A free-form target mapping or an
unexecuted discovery authorization cannot authorize an exact session.

Both post-discovery commands enforce the same full private provenance chain.
They reread the fixed canonical provider evidence, proposal, original
request/checkpoint, fixed claim, and the two canonical snapshots for each
domain; validate the exact root, host, source, profile, policy, budget, window,
and artifact digests; independently replay the provider and global-budget
events; and reconstruct the complete proposal using the evidence's sealed
time. The replayed counters, transcript digest, operation order, session
bindings, and modeled cost must match value-for-value. Proposal `created_at`
must equal provider-evidence `sealed_at`; it cannot be self-resealed later to
extend the owner-review deadline. The reconstruction must equal the persisted
proposal value-for-value before an owner decision or GUG-392 materialization
is accepted. The claim timestamp must be no later than every provider event
and snapshot identity observation, and the latest observation must be no
later than evidence sealing/proposal creation. A missing or changed
`gug393-discovery-provider-evidence.json`, alternate filename, self-resealed
proposal, or proposal recomputed from altered profile/principal inputs stops
without producing downstream files.

If the receipt is `READY_FOR_OWNER_DECISION`, obtain a new approval that names
the exact proposal digest within 15 minutes of proposal creation. Seal that
decision separately. Its approval and expiry timestamps establish the fresh
maximum 15-minute window that will be written into both GUG-392 plans; it does
not reopen or extend the completed discovery authorization:

```console
env -u PYTHONPATH -u PYTHONHOME \
  -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME \
  "$GUG392_PYTHON" -I -S \
  scripts/deployment/platform-authority-gug392-live-provider.py \
  materialize-discovery-decision \
  --private-root /absolute/private/root \
  --expected-proposal-digest sha256:REDACTED \
  --approval-reference-digest sha256:REDACTED \
  --expires-at 2099-01-01T00:15:00Z
```

Finally, provide both exact digests to materialize the two GUG-392 inputs and
their recomputed closed plans. The existing decision file is verified and is
never overwritten; the manifest is written last as the commit marker. The
proposal, decision, four GUG-392 artifacts, and manifest have fixed canonical
filenames, and the CLI intentionally exposes no filename override for this
one-shot transition. Run both post-discovery commands on the same operational
host, private root, and exact merged source commit/tree that created the
proposal; any host or `origin/main` drift fails closed and requires a new
request.

```console
env -u PYTHONPATH -u PYTHONHOME \
  -u _PYTHON_PROJECT_BASE -u _PYTHON_SYSCONFIGDATA_NAME \
  "$GUG392_PYTHON" -I -S \
  scripts/deployment/platform-authority-gug392-live-provider.py \
  materialize-approved-inputs \
  --private-root /absolute/private/root \
  --expected-proposal-digest sha256:REDACTED \
  --expected-decision-digest sha256:REDACTED
```

Any denial, timeout, malformed or repeated page token, budget limit, unstable
pair, partial state, collision, expired approval, readback mismatch, or
existing output is terminal for that request. Preserve the private artifacts
and start a fresh owner-reviewed request; never remove a claim to retry.

The resulting plans still require the separate GUG-392 request/checkpoint and
live read-only execution. A GUG-395 seed/plan, structural terminal validation,
green repository check, GUG-393 receipt, GUG-392 receipt, or merged PR does not
satisfy staging or production. GUG-127 must
certify staging first; GUG-128 requires its own independent production pilot
approval. Until then: `AWS_MUTATIONS=0`, `NOT_DEPLOYED`, `PRODUCTION_NO_GO`.

### One phase per process

`execute-phase` accepts exactly one named phase. It creates one fresh
phase-specific session, consumes that phase's ledger root and exits after a
terminal or ambiguous result; it never selects or starts the next phase. A
phase may contain multiple ordered operations. Each top-level provider/SDK
operation is locally invoked once with retries disabled, after its durable
pre-invocation CAS transition and before its durable outcome receipt.
After a delivered mutation the provider executes only the action's closed
canonical readback sequence. Policy/role/function/log creation is not
successful until documents or configuration and tags match. A readback error,
missing field or mismatch is persisted as ambiguous and never triggers a
write retry.

The `LEDGER_FACTORY_INVOKER` top-level operation invokes the exact signed
immutable version once. Its internal `CreateTable` and PITR writes are not
additional CLI operations; they are accepted only through the factory's own
causal receipt and exact `1/1` call counts. A single local invocation does not
eliminate ambiguous provider delivery.

Use the ledger, not the process exit or output file, to decide recovery:

| Last durable state | Operator action |
| --- | --- |
| No claim or no `OPERATION_IN_FLIGHT` transition | Confirm that no provider operation started, then revalidate the exact request/authority window. Never infer a call from a missing output. |
| `CLAIMED`, prior outcomes complete, no in-flight operation | The exact same request, execution context, claim nonce, caller/session/authority and unexpired window may resume only `next_operation_sequence`. It must not repeat an earlier outcome. Expiry requires a recovery issue. |
| `IN_FLIGHT`, including a crash after delivery/readback but before outcome CAS | Stop writes. Preserve artifacts and use only the operation-derived read-only reconciliation contract. |
| Outcome plus `durable_provider_evidence` committed, output file missing | Trust the ledger. Do not recreate the provider call; continue only under the exact non-terminal rule above or inspect the terminal state. |
| Outcome without `durable_provider_evidence` | Preserve as incomplete crash evidence. Do not backfill it from memory and do not certify it. |

### Ambiguity, activation and no-go

Timeout, lost response, ambiguous provider delivery or an in-flight ledger
record is `UNCERTAIN_RECONCILE_ONLY`. Stop the process and preserve all private
artifacts. `reconcile` may issue only bounded provider reads and must never
call the write callback again, repair, adopt, delete, roll back or advance the
phase. The request binds the ambiguous ledger/operation digests, exact derived
readback-contract digest, current session digest, effect/no-effect state
digests and their combined binding digest. The executor derives that contract
from the final ambiguous ledger outcome; no caller-selected plan readback or
slot substitution is accepted. It takes two equal complete read captures,
checks fresh STS continuity before reads and before CAS, and persists the
causal expectation/transcript binding. `lambda:InvokeFunction` has no
sufficient post-hoc causal read contract, so its ambiguity remains unresolved.
Non-conclusive or unstable reconciliation requires a separate recovery issue
and owner decision.

A `RECONCILED` ledger is recovery evidence only, even when its classification
is `EFFECT_PROVEN`. It cannot satisfy the next phase's predecessor gate and
cannot enter the eight-record certification bundle. Do not advance, certify or
translate it into authority; open a separate recovery issue and obtain a fresh
owner decision for any subsequent action. This is the phase-ledger status; the
separate ledger-factory causal outcome `CREATED_RECONCILED` remains governed by
its own exact receipt checks.

`ACTIVATOR` must reject unless every predecessor phase is `CONSUMED` with
complete durable evidence (`RECONCILED` is expressly excluded), the
ledger-factory receipt is causally accepted as
`CREATED|CREATED_RECONCILED`, the factory role is proof-bound and detached,
and a separately produced GUG-357 `FUNCTION_CONFIGURATOR` checkpoint and
provider readback are supplied. GUG-390 neither creates that checkpoint nor
authorizes GUG-357 configuration or CloudFormation `CreateStack`.

`certify` runs with no AWS client. It accepts exactly eight `CONSUMED` phase
records with complete durable evidence and eight independently bound phase-run
digests, recomputes every private seal, recertifies the full ledger-factory
receipt and its consumed provider-result binding, and requires two fresh
post-ACTIVATOR snapshot digests in causal time order. A filename or self-resealed
run without its expected digest is rejected.

Offline repository validation is:

```console
make platform-authority-gug390-live-provider-check
```

That target uses injected clients and schema fixtures only; its truthful
result remains `AWS_CALLS=0`, `AWS_MUTATIONS=0` and
`LIVE_PROVIDER_NOT_PROVEN`.

Rollback of a repository-only change is a reviewed revert. No live rollback
is automatic. Ambiguous/drifted state stays preserved for read-only
reconciliation; remediation, revocation or deletion requires a separate issue
and authorization. Without a separately authorized live run, exact owner
checkpoint and conclusive provider evidence, stop at
`production_status=NO-GO`.

## Phase 3 — live read-only before-state

This phase requires an explicitly approved read-only profile and `us-east-1`.
STS caller identity is the first AWS call. Collect two complete, stable IAM and
DynamoDB snapshots with all pagination closed.

For every managed policy target, prove exact absence or read:

- policy ARN/path/tags;
- default version ID and complete default document;
- all policy versions; and
- attachment/use counts.

For every one of the seven roles, prove exact absence or read:

- role ARN/name/path/ID, create date and maximum session;
- trust policy;
- tags and permissions boundary;
- zero inline policy names;
- exactly one attached managed policy identical to a main role's final
  boundary, or proof-bound/zero-attachment for the revoked factory role;
  and
- `RoleLastUsed`.

For the retained table, prove exact absence or read its key schema, billing
mode, KMS configuration, deletion protection, class, tags, exact resource
policy, empty contents and 35-day PITR state.

`AccessDenied`, timeout, truncation, malformed pagination or any error other
than exact `NoSuchEntity` is not absence. A mixed/partial/existing drifted
bundle is `DRIFT_BLOCKED_NO_REPAIR`.

## Phase 4 — mandatory owner checkpoint

Stop before the first AWS mutation. The owner must provide a new GUG-365-only
authorization no longer than fifteen minutes and separately deliver its
expected digest. It must name/bind:

- the exact non-production account and `us-east-1`;
- one newly refreshed short-lived least-privilege GUG-365 executor profile and
  exact caller digest;
- complete authenticated effective-policy inventory proving the phase document
  is the sole identity grant and the identical permissions boundary/session
  cap, with zero extra inline, attached or group policies;
- the reviewed merged commit/tree and fresh GUG-363/GUG-365 plan digests;
- all six policy-document digests, seven trust digests, both signed-function
  contracts and retained-table contract digest;
- each phase's complete ordered operation list, executor-policy digest and
  target digests;
- the stable absent-before-state digest;
- one operator/workstation and private ledger digest;
- issue, not-before, expiry and one-attempt semantics; and
- reconcile-only recovery with no automatic rollback or deletion.

The private phase ledger is a create-only causal guard, not an authorization
artifact. Its immutable root binds the exact plan, bundle, target, phase,
executor evidence, host and ordered requests. Claiming it consumes one attempt
through CAS. The runner must persist the next exact operation as in-flight
before calling the injected provider callback, then persist exactly one
outcome and digest-linked receipt before any later operation. The library has
no AWS adapter, creates no session or client and cannot make this phase live.

Each authority has a separate least-privilege executor policy.
`POLICY_FACTORY` can create only the six policies; `FOUNDATION_FACTORY` can
create only the seven roles under the explicit deny-all proof boundary and has
zero DynamoDB authority; `FUNCTION_FACTORY` creates only the inert signed
broker function, while the separate `LEDGER_FACTORY_FUNCTION_FACTORY` creates
the dedicated log group and only the inert, separately packaged/signed,
empty-environment ledger factory. Each certifies its own function after its
distinct authority expires. `LEDGER_FACTORY_ACTIVATOR` can only attach and
activate the factory role; `LEDGER_FACTORY_INVOKER` can only invoke the exact
qualified immutable version synchronously with event `{}` and read it back;
`LEDGER_FACTORY_REVOKER` moves the role to proof before detaching its policy.
Only a causal `CREATED` or `CREATED_RECONCILED` receipt with exact one-create/
one-PITR counts and final empty-table certification permits progress;
`ALREADY_EXACT` blocks for owner recovery. GUG-357
`FUNCTION_CONFIGURATOR` must atomically replace the entire environment under a
fresh checkpoint before `ACTIVATOR` can attach only the plan-bound policies
and set only the plan-bound final boundaries. `REVOCATOR` is separately
authorized and can only move the four effect-capable roles back to the proof
boundary; it cannot perform a forward operation. No session can hold the union
of these authorities. Every authority except the two narrowly scoped
function-factory sessions denies PassRole; each factory session has only its
one exact proof-bound role edge. Every authority denies CloudFormation,
AssumeRole, service-role assumption, Identity Center mutation, broker
invocation, update, delete, detach and unrelated creation. The GUG-357 and
GUG-206 profiles are not reusable substitutes.

The phase JSON is not safe as an additive identity policy. Before every phase,
provider-backed evidence must prove it is both the sole grant and the maximum
effective-authority cap for a fresh unchained session (or a trusted broker
enforces the identical document as a session cap). Missing, incomplete, stale
or extra policy evidence is `STOP_NO_MUTATION`.

## Phase 5 — future create-only execution

This phase is currently `NOT_AUTHORIZED`. When a later task carries the exact
checkpoint, the implementation must:

1. validate plan, authorization, expected digests, custody and expiry before
   constructing effect-capable clients;
2. call STS first and match the exact caller/account;
3. repeat the complete IAM/Lambda/table absent snapshot for the active phase;
4. consume the private attempt ledger for the authorized phase;
5. revalidate authorization immediately before every ordered write and commit
   the operation-specific pre-invocation CAS transition;
6. call each operation at most once through the injected callback with SDK
   retries disabled, then durably record its single outcome and receipt before
   continuing;
7. immediately perform complete readback after every conclusive response;
8. create each signed function at most once under its separate function-factory
   authority with an empty environment, wait boundedly for Active/Successful,
   pin runtime/concurrency, certify its complete inert state, and expire that
   authority; the ledger-factory phase also creates and certifies only its
   dedicated log group;
9. activate only the factory role, then use a distinct invoke-only session to
   call the exact immutable version with `InvocationType=RequestResponse`,
   payload `{}` and SDK retries disabled; consume the attempt ledger before the
   call and never invoke again after an ambiguous outcome;
10. inside that signed runtime, call `CreateTable` once with the canonical
    resource-policy JSON string in the same request, poll only read APIs until
    exact `ACTIVE`, call `UpdateContinuousBackups` once, and require exact
    controls, policy revision and empty count-only `Scan`;
11. revoke the factory to proof first, detach second, expire the invoker and
    certify the terminal factory state before main activation;
12. require a fresh GUG-357 configuration checkpoint to atomically replace the
    entire environment using the observed RevisionId, then certify and expire
    that authority before any role activation or CreateStack; and
13. close the current session and obtain a fresh checkpoint before the next
   phase.

If any response is ambiguous, stop. Do not infer success, retry, continue to a
dependent write, repair, delete or recreate. Run only the read-only reconcile
path under separately allowed reads. A restart that observes an in-flight
operation also enters read-only reconciliation; it must not call the provider
again. Resealing a modified record, replaying a consumed root or presenting
only equal final digests is not acceptable causal evidence.

## Phase 6 — certification and handoff

Two stable final snapshots must exactly match every policy version/document,
policy tag, trust statement, role tag, boundary, zero-inline state, sole main
attachment, proof-bound/detached factory state, path/session duration, both
function surfaces and expected unused state, plus the complete retained-table/
resource-policy/PITR contract. Provider equivalence without the
causal consumed phase ledgers does not prove that this run created the bundle.
Certification must validate all eight forward-phase ledgers in exact plan
order, including each independently delivered root, claim nonce and terminal
receipt binding; partial phase evidence is not a bundle receipt.

Publish a sanitized terminal manifest to GUG-365 and keep raw receipts private.
The terminal status may be `LIVE_BUNDLE_CERTIFIED_NO_STACK_EXECUTION`; it must
not claim GUG-357, GUG-215, deployment or production completion.

GUG-357 then starts a new continuation, rebuilds its own fresh read-only
checkpoint and revalidates the bundle. It never reuses GUG-365 evidence as a
current identity/session claim.

## Recovery

| Observed state | Classification | Action |
|---|---|---|
| All targets absent, no fresh authorization binding | `NOT_AUTHORIZED` | Await a fresh checkpoint |
| All targets absent, fresh exact authorization binding | `ABSENT_READY` | Claim the phase ledger, then ordered creates |
| Exact full bundle, causal ledger complete | `EXACT_PRESENT_NO_TOUCH` | Certify and return to GUG-357 |
| Exact full bundle without causal ledger | `PREEXISTING_NO_TOUCH` | Preserve; separate owner decision |
| Partial or drifted bundle | `DRIFT_BLOCKED_NO_REPAIR` | Open a new recovery issue |
| Any write attempted with unknown outcome | `UNCERTAIN_RECONCILE_ONLY` | Read-only reconcile; never retry |

This runbook authorizes no cleanup. Deleting a role or managed policy, changing
trust/boundaries, rolling back, repairing, or recreating requires a new atomic
issue and a separately explicit destructive checkpoint.

## References

- [ADR-052](../../ADR/ADR-052-gug357-cloudformation-service-role-boundaries.md)
- [ADR-055](../../ADR/ADR-055-gug395-preplan-seed-and-downstream-materialization.md)
- [Deployment contract](../deployment/platform-authority-retirement-entrypoint-service-role.md)
- [Threat model](../security/gug365-retirement-entrypoint-service-role-threat-model.md)
