# GUG-219 Lambda Authority Materialization Runbook

## Safety boundary

This runbook covers deterministic materialization and read-only evidence
collection. It does not authorize Identity Center mutation, provisioning,
assignment changes, Lambda invocation, IAM/Lambda mutation, token exchange,
STS context creation, Change Set operations, Terraform Apply, customer
deployment, migration, destruction, redrive or production.

Production remains **NO-GO**.

The current roster has one human. That operator may prepare and collect
report-only evidence under explicit authorization, but cannot independently
approve it in `TWO_HUMAN`. ADR-050 permits an exact owner-reviewed v2 chain for
`SINGLE_OPERATOR_NONPROD_EXCEPTION`; every v2 record remains
`two_human_status = NOT_PROVEN` and
`independent_approval_present = false`.

The ADR-050 chain uses only
`single-classify -> single-retire -> single-reconcile`, duties
`single_operator_classifier`/`single_operator_retirement` and matching
`EXACT_SINGLE_*_ALIAS` scopes. The owner must review and pin the exact exception
`authorization_digest` and release digest. Mixed v1/v2 aliases, duties, scopes
or digests stop the run.

Before either mode can support retirement, the separate GUG-215 readback must
prove `RuntimeManagementConfig.UpdateRuntimeOn = Manual` and the exact reviewed
`RuntimeVersionArn`. This GUG-219 runbook does not itself certify that live
runtime-management setting.

## Required duties

| Duty | Current handling | Authority |
|---|---|---|
| Materializer operator | May be the current sole operator | Local/private file generation only |
| Read-only collector A | May be the current sole operator under explicit AWS read authorization | Exact List/Get/Describe and STS identity only |
| Read-only collector B | May be the same current operator under a separately pre-authenticated profile | Immediate STS revalidation and fresh report-only capture only; machine evidence does not prove session uniqueness |
| Independent reviewer | **Unavailable** on current roster | Required before a `TWO_HUMAN` rollout; not fabricated in ADR-050 |
| ADR-050 owner | Current sole operator | Reviews and pins exact exception/release digests; remains `NOT_PROVEN` |
| Effect operator | Not in scope | No effect authority granted |

The record must preserve the fact that one person performed multiple duties.
Do not create placeholder users or claim profile/session separation as human
independence.

## Phase 0 — Repository and authorization preflight

1. Record the exact issue, branch, worktree, commit candidate and evidence
   owner.
2. Verify the GUG-217, GUG-218 and GUG-219 source commits are reviewed and
   linearly related.
3. Verify the target partition, account, Region and canonical broker function
   come from an approved operational binding.
4. For ADR-050 v2, require the clean-commit deterministic GUG-215 broker
   package manifest, its separately supplied owner-reviewed manifest digest and
   its archive-derived `lambda_code_sha256`. V1 retains its separate artifact
   rollout gate.
5. Verify candidate A has an explicit, time-bounded read-only authorization.
6. Define private output paths outside the repository and evidence retention.
7. Select the authorization mode: record that no independent reviewer exists
   for v1, or record the exact ADR-050 owner-reviewed exception/release digests
   and `NOT_PROVEN` status for v2.

Stop if any source, binding, digest, authorization or retention owner is
missing. Never use the default AWS profile.

The executable command shapes below are ADR-050 v2 and include
`--authorization-mode SINGLE_OPERATOR_NONPROD_EXCEPTION` plus the private
exception input. Materialization and GUG-218 evaluation also include the
deterministic package manifest and its separately owner-reviewed exact digest.
For backward-compatible v1 `TWO_HUMAN`, omit the applicable
authorization/package options shown in each command; do not mix modes.

## Phase 1 — Dedicated collector readiness

The live GUG-220 ledger is consumed and its sanitized reconciliation is
partial: permission set present, policy/assignment/provisioning/collector role
absent or unverified. Do not execute Candidate A and do not rerun GUG-220.
Follow the separately reviewed GUG-221 repair runbook and require its
`READBACK_VERIFIED` receipt first.

Before candidate A, separately prove through authorized read-only Identity
Center/IAM inspection that
the active session corresponds to the dedicated permission set:

```text
ScanalyzeAuthorityLambdaAudit
```

Require all of the following:

- exact inline-policy digest matching
  `policies/iam/platform-authority-lambda-invocation-inventory-role.json`;
- exact `PT1H` session duration;
- no AWS-managed policy;
- no customer-managed policy reference;
- no permissions boundary;
- no additional inline statement;
- no role relay or secondary assume-role path;
- explicit denies for Lambda invocation and IAM/Lambda mutation; and
- assignment only within the separately authorized target account.

Provisioning, changing or assigning the permission set is a stop condition for
this runbook. Use only the separately authorized GUG-220 provisioning and
exact-readback package. The GUG-219 CLI does not perform this readback; it
consumes the resulting private binding and validates the account-local IAM/STS
role and effective IAM policy surface.

Treat the configured `AWS_PROFILE` as a selector, not evidence. Call
`sts:GetCallerIdentity`, verify the exact account, normalize the returned
assumed-role ARN to its base role by removing the session name, and require the
actual role name to have the exact
`AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_<opaque-suffix>` form.

Keep the exact suffix and role ARN private. Publish only the separate canonical
IAM-role and normalized STS-role digests. Stop before EC2, IAM or Lambda reads
if STS returns root, an IAM user,
a foreign account, a generic read-only role, a different permission set or an
unexpected suffix binding.

## Phase 2 — Candidate capture A

The following is a sanitized command shape only. Use it after merge from the
exact reviewed `main` commit and only inside a separately authorized read-only
window. Do not place substituted values in Git, Linear or logs.

Create the private binding obtained from the separate Identity Center/IAM
readback:

```bash
export AWS_PROFILE_A='<exact dedicated collector profile for capture A>'
export AWS_PROFILE_B='<second local profile for the same exact collector role>'
export AWS_REGION='<approved region>'
export IDENTITY_CENTER_REGION='<home region of the Identity Center instance>'
export AUTHORITY_ACCOUNT_ID='<approved 12-digit authority account>'
export FUNCTION_NAME='scanalyze-platform-authority-gug215-retirement'
export EVIDENCE_ROOT='<absolute private path outside the repository>'
export COLLECTOR_IAM_ROLE_ARN='<exact AWSReservedSSO IAM role ARN>'
# ADR-050 only: all three are existing, distinct owner-only inputs or exact
# values reviewed outside this command invocation.
export SINGLE_OPERATOR_EXCEPTION='<existing-private-0600-exception.json>'
export BROKER_ARTIFACT_MANIFEST='<existing-private-0600-package-manifest.json>'
export BROKER_ARTIFACT_MANIFEST_DIGEST='sha256:<owner-reviewed-64-hex>'

# Complete both interactive logins before candidate A starts. Never spend the
# bounded release window waiting on a browser or device-code flow.
aws sso login --profile "$AWS_PROFILE_A"
aws sso login --profile "$AWS_PROFILE_B"
export COLLECTOR_STS_SESSION_ARN="$(
  aws sts get-caller-identity \
    --profile "$AWS_PROFILE_A" \
    --region "$AWS_REGION" \
    --query Arn \
    --output text
)"

umask 077
mkdir -m 700 "$EVIDENCE_ROOT"
( set -e
  set -o noclobber
  jq -n \
    --arg identity_center_region "$IDENTITY_CENTER_REGION" \
    --arg collector_iam_role_arn "$COLLECTOR_IAM_ROLE_ARN" \
    --arg collector_sts_session_arn "$COLLECTOR_STS_SESSION_ARN" \
    '{identity_center_region:$identity_center_region,
      collector_iam_role_arn:$collector_iam_role_arn,
      collector_sts_session_arn:$collector_sts_session_arn}' \
    > "$EVIDENCE_ROOT/collector-binding.json"
  chmod 600 "$EVIDENCE_ROOT/collector-binding.json"
)
```

The binding must contain exactly those three keys. Then collect A into a new
directory that does not already exist:

```bash
export A_CREATED="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
export A_DIR="$EVIDENCE_ROOT/candidate-a-$(date -u '+%Y%m%dT%H%M%SZ')"

python scripts/deployment/platform-authority-lambda-invocation-materializer.py \
  candidate-aws-readonly \
  --collector-binding "$EVIDENCE_ROOT/collector-binding.json" \
  --created-at "$A_CREATED" \
  --profile "$AWS_PROFILE_A" \
  --ttl-minutes 5 \
  --output-dir "$A_DIR" \
  --authority-account-id "$AUTHORITY_ACCOUNT_ID" \
  --region "$AWS_REGION" \
  --function-name "$FUNCTION_NAME" \
  --authorization-mode SINGLE_OPERATOR_NONPROD_EXCEPTION \
  --single-operator-exception "$SINGLE_OPERATOR_EXCEPTION"
```

1. Start an explicitly authorized collector session.
2. Generate a unique opaque candidate-A scan nonce.
3. Use the GUG-219 materialization-capture entry point, backed by the hardened
   GUG-218 adapter, to collect every required IAM and Lambda page using only
   the reviewed read APIs. Do not call the normal GUG-218 `aws-readonly`
   evaluation before its allowlist and release anchor exist.
4. Require complete pagination, canonical endpoints and the GUG-218 five-minute
   capture limit.
5. Seal source mode, principal digest, start/completion time, nonce and raw
   snapshot digest.
6. Store the raw snapshot create-only and owner-only outside the repository.
7. Record it as candidate A in private evidence; never relabel it
   `REVIEW_SAFE_REPORT_ONLY`.

Candidate A may supply only live provider facts needed to bind the materialized
record. It may not define allowed principals, actions, aliases, conditions or
edges. A foreign/missing edge, policy mismatch, unsupported semantics or
observed code/configuration drift blocks materialization. Candidate A alone
does not prove archive provenance; the v2 materializer must compare it with the
separately reviewed deterministic package manifest.

Do not print provider responses, account identifiers, ARNs, policies, Function
URLs, environment data or profile names.

## Phase 3 — Deterministic materialization

Run the offline `materialize` subcommand with separate private inputs for:

- reviewed GUG-217 template and ordered policies;
- candidate-A observed broker code/configuration;
- exact target binding;
- exact collector contract; and
- sealed candidate A; and, for ADR-050 v2,
- the deterministic package manifest plus its independently supplied
  owner-reviewed expected digest.

The materializer must:

1. reject duplicate JSON keys, symlink inputs, unexpected GUG-219 record
   fields and unreviewed Lambda configuration fields;
2. hash exact template bytes and canonical ordered policy documents;
3. in v2, validate the clean-commit package manifest and require its
   archive-derived `lambda_code_sha256` to equal candidate A; bind the observed
   configuration digest without claiming independent human review;
4. construct exactly fourteen authority edges from observed policies under
   hard-coded reviewed invariants and bind exact source-file digests;
5. compare candidate A to that topology without adding observed edges;
6. bind the actual canonical collector-role principal digest;
7. bind the complete published-configuration digest;
8. compute the allowlist self-digest;
9. compute a distinct release anchor over the allowlist and complete source
   binding; and
10. write both outputs with exclusive creation, no symlink following and
    owner-only modes outside the repository.

The output paths must be different and must not resolve to the same inode. The
current clock, filesystem order and profile name must not affect canonical
bytes. Re-rendering the same immutable input set to new empty paths must
produce byte-identical records.

Stop rather than infer when the published configuration contains a provider
field outside the pinned reviewed manifest.

The release must remain `MATERIALIZED_REVIEW_REQUIRED`. An
`aws_readonly_inventory_eligible = true` value permits only the subsequent
fresh read-only B validation and grants no approval or effect authority.

Immediately compute an expiry inside A's remaining validity and materialize to
another new directory. The producer verifies that `SOURCE_COMMIT` exists, is
reachable and contains the exact materializer, template and policy bytes:

```bash
export SOURCE_COMMIT="$(git rev-parse HEAD)"
read -r RELEASE_CREATED RELEASE_EXPIRES < <(
  python - "$A_DIR/candidate-snapshot.json" <<'PY'
import json
import sys
from datetime import UTC, datetime, timedelta

with open(sys.argv[1], encoding="utf-8") as stream:
    snapshot = json.load(stream)
now = datetime.now(UTC).replace(microsecond=0)
a_expires = datetime.fromisoformat(snapshot["capture_expires_at"].replace("Z", "+00:00"))
expires = min(now + timedelta(minutes=2), a_expires - timedelta(seconds=1))
if not now < expires:
    raise SystemExit("candidate A no longer has enough validity")
fmt = lambda value: value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
print(fmt(now), fmt(expires))
PY
)
export RELEASE_DIR="$EVIDENCE_ROOT/release-$(date -u '+%Y%m%dT%H%M%SZ')"

# This command shape is ADR-050 v2. In TWO_HUMAN omit the four
# authorization/package options below.
python scripts/deployment/platform-authority-lambda-invocation-materializer.py \
  materialize \
  --candidate-snapshot "$A_DIR/candidate-snapshot.json" \
  --collector-contract "$A_DIR/collector-contract.json" \
  --source-commit "$SOURCE_COMMIT" \
  --created-at "$RELEASE_CREATED" \
  --expires-at "$RELEASE_EXPIRES" \
  --output-dir "$RELEASE_DIR" \
  --authority-account-id "$AUTHORITY_ACCOUNT_ID" \
  --region "$AWS_REGION" \
  --function-name "$FUNCTION_NAME" \
  --authorization-mode SINGLE_OPERATOR_NONPROD_EXCEPTION \
  --single-operator-exception "$SINGLE_OPERATOR_EXCEPTION" \
  --broker-artifact-manifest "$BROKER_ARTIFACT_MANIFEST" \
  --expected-broker-artifact-manifest-digest \
    "$BROKER_ARTIFACT_MANIFEST_DIGEST"
```

## Phase 4 — Freeze and release-anchor verification

1. Recompute both canonical digests with the canonical verifier.
2. Verify the release anchor names the exact allowlist digest and complete
   source-set digests.
3. Verify the allowlist and release anchor are distinct record types and files.
4. Supply the release-anchor digest through a distinct reviewed input: an
   independent protected channel for `TWO_HUMAN`, or the exact owner-reviewed
   v2 release bound to ADR-050.
5. Freeze the records; never edit or replace them in place.
6. Record who materialized and who reviewed them.

With the current one-person roster, record:

```text
independent_approval_present = false
two_human_status = NOT_PROVEN
approval_authorized = false
```

The same operator may verify determinism, but that is not independent approval.

## Phase 5 — Fresh capture B

1. Obtain a new explicit read-only authorization window.
2. Use the separately pre-authenticated B profile and repeat STS principal
   validation immediately before B. Do not start an interactive SSO login
   inside the bounded release window. The machine proof normalizes session
   names and therefore proves only the same exact canonical role, not
   credential-session uniqueness.
3. Require the same frozen canonical collector role, including the actual
   Identity Center suffix binding.
4. Generate a new opaque B nonce; reject the A nonce or A snapshot digest.
5. Supply the frozen allowlist and the mode-appropriate reviewed release-anchor
   digest before any inventory read: independent in v1, exact owner-reviewed in
   v2.
6. Perform a complete new IAM/Lambda capture; do not reuse candidate A pages.
7. Validate the allowlist, capture B and GUG-218 receipt as one bundle at a
   trusted UTC instant.

The sequence must fit the exact bounded chronology:

```text
A_completed < release_created <= B_started <= B_decision
             < release_expires < A_expires
```

Operational feasibility is not established until a separately authorized
live rehearsal completes this sequence without relaxing the windows.

Only exact equality with all fourteen expected edges, zero foreign/mutation
edges, exact code/configuration and complete fresh evidence may produce
`REVIEW_SAFE_REPORT_ONLY`.

That status is not an approval. In v1 record the missing independent reviewer;
in v2 record the owner-reviewed exact digest and `NOT_PROVEN`. Keep deployment
and production blocked in both cases.

After the pre-authenticated B profile passes immediate STS revalidation, run B
before the release expires. The four v1 private inputs, plus the exception and
package manifest in v2, must be distinct regular owner-only files. The expected
release digest must come from the separately reviewed release record, not be
read back from either input by this invocation:

```bash
aws sts get-caller-identity \
  --profile "$AWS_PROFILE_B" \
  --region "$AWS_REGION" \
  --query '{Account:Account,Arn:Arn}' \
  --output json >/dev/null
# TWO_HUMAN obtains this value through an independently reviewed protected
# channel. ADR-050 uses the exact owner-reviewed v2 release and records
# `independent_approval_present=false` and `two_human_status=NOT_PROVEN`.
export RELEASE_DIGEST='sha256:<mode-appropriate-reviewed-64-hex>'
export B_RECEIPT="$EVIDENCE_ROOT/capture-b-$(date -u '+%Y%m%dT%H%M%SZ').json"

# This command shape is ADR-050 v2. In TWO_HUMAN omit the four
# authorization/package options below.
( set -e
  set -o noclobber
  umask 077
  python scripts/deployment/platform-authority-lambda-invocation-authority.py \
    aws-readonly \
    --allowlist "$RELEASE_DIR/allowlist.json" \
    --collector-contract "$RELEASE_DIR/collector-contract.json" \
    --release-manifest "$RELEASE_DIR/release-manifest.json" \
    --candidate-snapshot "$A_DIR/candidate-snapshot.json" \
    --expected-release-manifest-digest "$RELEASE_DIGEST" \
    --authorization-mode SINGLE_OPERATOR_NONPROD_EXCEPTION \
    --single-operator-exception "$SINGLE_OPERATOR_EXCEPTION" \
    --broker-artifact-manifest "$BROKER_ARTIFACT_MANIFEST" \
    --expected-broker-artifact-manifest-digest \
      "$BROKER_ARTIFACT_MANIFEST_DIGEST" \
    --profile "$AWS_PROFILE_B" \
    --ttl-minutes 5 \
    --authority-account-id "$AUTHORITY_ACCOUNT_ID" \
    --region "$AWS_REGION" \
    --function-name "$FUNCTION_NAME" \
    > "$B_RECEIPT"
  chmod 600 "$B_RECEIPT"
)
```

The wrapper retains raw B only in memory and writes the sanitized inventory
and receipt shown above. On any nonzero exit or ambiguous response, quarantine
the partial output and reconcile read-only; never overwrite or relabel it.

## Phase 6 — Evidence publication

Public evidence may include only:

- issue, branch, reviewed commit and PR;
- named local and CI gate status;
- sanitized capture timestamps or time-window status;
- bounded status and reason codes;
- expected/observed edge counts;
- canonical digests; and
- explicit authorization mode, `independent_approval_present = false`,
  `two_human_status = NOT_PROVEN` for ADR-050, and `Production: NO-GO`.

Never publish candidate A/B raw files, account IDs, ARNs, suffixes, policy
documents, assignment IDs, profile names, Function URLs, provider responses or
exact operational manifests.

## Stop conditions

Stop immediately for:

- any requested AWS mutation or Lambda invocation;
- missing or unapproved target/profile/Region;
- generic ReadOnly, administrator, root, IAM-user or foreign collector;
- managed policy, customer-managed reference, boundary or extra inline policy;
- unexpected or inferred Identity Center suffix;
- candidate A used as clean evaluation evidence;
- candidate A defining an allowed topology edge;
- allowlist and release anchor from the same file or same input channel;
- synthetic/placeholder/repository-local material entering `aws-readonly`;
- existing, symlinked, non-owner-only or repository-local output;
- incomplete pagination, access denied or ambiguous provider response;
- template, policy, observed code, configuration or principal digest mismatch;
- candidate B reusing A's nonce, pages or snapshot; session refresh is a
  separately recorded operational control;
- stale/future-dated evidence or untrusted clock;
- one operator represented as independent approval, or a v2 chain missing its
  exact owner-reviewed digests and `NOT_PROVEN` status; or
- any production or deployment-readiness claim.

## Failure and reconciliation

An ambiguous AWS result permits only read-only reconciliation in a new
authorized window. Do not retry the same capture, reuse its nonce or overwrite
its files.

If A or materialization fails, invalidate the candidate sequence and begin
again from a new A after resolving the cause. If B fails, retain the frozen
allowlist for forensic comparison only when its sources remain valid; a new B
still requires a refreshed session, nonce and authorization. Any source or collector
change requires a new A and new materialization.

## Rollback

This package creates no cloud state. Repository rollback is a reviewed revert.
Private artifacts are marked invalid and handled by the approved retention
procedure. Do not delete or alter Identity Center assignments, permission sets
or policies under this runbook; those require separately authorized rollback.

## Post-merge steps

1. Verify exact merged SHA and green required checks on `main`.
2. Record repository evidence in GUG-219 without live identifiers.
3. Preserve the consumed GUG-220 ledger and partial-state evidence.
4. Bootstrap/read back the exact GUG-221 authority and management broker
   stacks plus the invoke-only human permission set under separate authorization.
5. Repair and read back the exact collector contract through GUG-221.
6. Obtain a read-only window for A, materialize privately and freeze digests.
7. Record the absent independent reviewer for v1, or the exact owner-reviewed
   ADR-050 digests and `NOT_PROVEN` for v2.
8. Obtain a second read-only window and collect B.
9. Publish only the sanitized GUG-218 result.
10. Add a different human reviewer before `TWO_HUMAN` rollout approval; use only
    the owner checkpoint for ADR-050.
11. Complete preventive guardrail and non-production rollout gates before any
    production decision.

## Public closeout template

```text
Implemented: <exact commit and PR>
Locally validated: <named gates>
CI validated: <exact required checks or not established>
Candidate A: <not performed or sanitized status>
Allowlist/release anchor: <not materialized or private digest-bound status>
Candidate B: <not performed or sanitized report-only status>
AWS mutation: none
Authorization mode: <TWO_HUMAN or SINGLE_OPERATOR_NONPROD_EXCEPTION>
Independent approval present: false while one human is on roster
Two-human status: <NOT_PROVEN for ADR-050>
Owner-reviewed exact digest: <required for ADR-050>
Deployment authorized: no
Live validated: no
Production: NO-GO
```

See the [GUG-220 provisioning runbook](platform-authority-lambda-audit-permission-set.md)
for the mutation, ambiguity and exact-readback boundary.

Before accepting the private collector binding, confirm that the GUG-220
receipt derives from a non-expired intent whose validity never exceeded 15
minutes and whose live Identity Center Instance/Identity Store digests were
revalidated before effect. Reject pre-hardening intents, null permission-set or
role ARN digests, any false assignment/provisioning/role verification gate, and
policy changes without explicit target reprovisioning. Read the private input
through the descriptor-safe `O_NOFOLLOW`, current-owner and exact `0600`
procedure; a path-only check is not sufficient.

See the [GUG-221 repair runbook](platform-authority-lambda-audit-provisioning-repair.md)
for the exact partial-state gate, dedicated executor and no-retry repair.
