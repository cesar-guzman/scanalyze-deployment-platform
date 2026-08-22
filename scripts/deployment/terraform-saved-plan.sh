#!/usr/bin/env bash
# terraform-saved-plan.sh — GitHub-only exact saved-plan plan/apply runner.

set -euo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPO_ROOT="$(cd -P -- "${SCRIPT_DIR}/../.." && pwd -P)"

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
pass() { printf 'PASS: %s\n' "$*"; }

reject_ambient_overrides() {
  local variable_name
  while IFS= read -r variable_name; do
    case "$variable_name" in
      TF_*) die "Ambient Terraform environment variable is prohibited: ${variable_name}" ;;
    esac
  done < <(compgen -e)

  for variable_name in AWS_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE; do
    if [[ -n "${!variable_name:-}" ]]; then
      die "AWS profiles and shared configuration are prohibited in the live runner"
    fi
  done
}

require_live_ci_boundary() {
  [[ "${GITHUB_ACTIONS:-}" == "true" ]] \
    || die "Saved-plan execution is restricted to GitHub Actions"
  [[ "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" ]] \
    || die "Saved-plan execution requires workflow_dispatch"
  [[ "${GITHUB_REF:-}" == "refs/heads/main" ]] \
    || die "Saved-plan execution requires the protected main branch"
  [[ "${GITHUB_REF_PROTECTED:-}" == "true" ]] \
    || die "Saved-plan execution requires a protected ref"
  [[ "${SCANALYZE_LOGICAL_ENVIRONMENT:-}" == "dev" ]] \
    || die "Saved-plan execution is restricted to dev"
  [[ "${SCANALYZE_ALLOW_LIVE:-}" == "true" ]] \
    || die "Live execution was not enabled"
  [[ "${SCANALYZE_DRY_RUN:-}" == "false" ]] \
    || die "Live and dry-run execution cannot be combined"
  [[ "${SCANALYZE_EXPECTED_MAIN_SHA:-}" =~ ^[0-9a-f]{40}$ ]] \
    || die "The expected main SHA binding is invalid"
  [[ "${GITHUB_SHA:-}" == "${SCANALYZE_EXPECTED_MAIN_SHA}" ]] \
    || die "The workflow SHA is not the authorized main SHA"
  [[ "${GITHUB_WORKFLOW_REF:-}" == \
    "${GITHUB_REPOSITORY:-}/.github/workflows/nonprod-release.yml@refs/heads/main" ]] \
    || die "The workflow reference is not the canonical main workflow"
  [[ "${GITHUB_REPOSITORY_ID:-}" =~ ^[1-9][0-9]*$ ]] \
    || die "The repository numeric identity is unavailable"
  [[ "${GITHUB_REPOSITORY_OWNER_ID:-}" =~ ^[1-9][0-9]*$ ]] \
    || die "The repository owner numeric identity is unavailable"
  [[ "${SCANALYZE_EXPECTED_REPOSITORY_ID:-}" == "${GITHUB_REPOSITORY_ID}" ]] \
    || die "The repository numeric identity is not authorized"
  [[ "${SCANALYZE_EXPECTED_REPOSITORY_OWNER_ID:-}" == \
    "${GITHUB_REPOSITORY_OWNER_ID}" ]] \
    || die "The repository owner numeric identity is not authorized"
  [[ "${SCANALYZE_DEPLOYMENT_ID:-}" =~ ^dep_[0-9A-HJKMNP-TV-Z]{26}$ ]] \
    || die "The deployment binding is invalid"
  [[ "${SCANALYZE_GITHUB_ENVIRONMENT:-}" == \
    "scanalyze-${SCANALYZE_DEPLOYMENT_ID}-dev" ]] \
    || die "The protected Environment binding is not canonical"
  [[ "${SCANALYZE_OIDC_AUDIENCE:-}" == "sts.amazonaws.com" ]] \
    || die "The OIDC audience is not authorized"
  [[ "${SCANALYZE_ROLE_DURATION_SECONDS:-}" == "900" ]] \
    || die "The role duration is not the authorized minimum"
}

verify_terminal_identity() {
  local expected_account_id="$1"
  local expected_role_arn="$2"
  local identity

  [[ "$expected_account_id" =~ ^[0-9]{12}$ && "$expected_account_id" != "000000000000" ]] \
    || die "Expected destination account is invalid"
  [[ "$expected_role_arn" =~ ^arn:aws:iam::${expected_account_id}:role/[A-Za-z0-9+=,.@_-]+$ ]] \
    || die "Expected terminal role ARN is invalid"
  command -v aws >/dev/null 2>&1 \
    || die "AWS CLI is unavailable"
  identity="$(aws sts get-caller-identity --output json 2>/dev/null)" \
    || die "Unable to verify the terminal AWS identity"
  python3 - "$identity" "$expected_account_id" "$expected_role_arn" <<'PY' \
    || die "The active AWS identity is not the exact terminal role"
import json
import re
import sys

identity = json.loads(sys.argv[1])
account_id = sys.argv[2]
role_arn = sys.argv[3]
role_name = role_arn.rsplit("/", 1)[-1]
actual = identity.get("Arn")
if identity.get("Account") != account_id or not isinstance(actual, str):
    raise SystemExit(1)
pattern = rf"^arn:aws:sts::{re.escape(account_id)}:assumed-role/{re.escape(role_name)}/[^/]+$"
if re.fullmatch(pattern, actual) is None:
    raise SystemExit(1)
PY
}

require_private_regular_file() {
  local path="$1"
  local label="$2"
  python3 - "$path" <<'PY' \
    || die "${label} custody is invalid"
import os
import stat
import sys

path = os.path.abspath(sys.argv[1])
descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    metadata = os.fstat(descriptor)
finally:
    os.close(descriptor)
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != os.geteuid()
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or metadata.st_nlink != 1
):
    raise SystemExit(1)
PY
}

require_outside_repository() {
  local path="$1"
  local label="$2"
  python3 - "$path" "$REPO_ROOT" <<'PY' \
    || die "${label} must be outside the repository"
import os
import sys

path = os.path.realpath(sys.argv[1])
repo = os.path.realpath(sys.argv[2])
try:
    common = os.path.commonpath((path, repo))
except ValueError:
    raise SystemExit(1)
if common == repo:
    raise SystemExit(1)
PY
}

require_canonical_terminal_role() {
  local layer="$1"
  local operation="$2"
  local role_arn="$3"
  python3 - "$REPO_ROOT" "$layer" "$operation" "$role_arn" <<'PY' \
    || die "Expected terminal role is not canonical for the layer operation"
import sys

repo, layer, operation, role_arn = sys.argv[1:]
sys.path.insert(0, repo)
from tooling.nonprod_live_engine import require_terminal_role_for_layer

role_name = role_arn.rsplit("/", 1)[-1]
require_terminal_role_for_layer(layer=layer, operation=operation, role=role_name)
PY
}

ACTION="${1:-}"
shift || die "usage: terraform-saved-plan.sh <plan|apply> [options]"

case "$ACTION" in
  plan|apply) ;;
  *) die "Unknown action. Only protected plan or exact saved-plan apply is supported" ;;
esac

# This check deliberately precedes argument parsing and every subprocess. A
# caller cannot turn this file into a local apply escape hatch by supplying a
# valid-looking plan or Terraform option.
require_live_ci_boundary
reject_ambient_overrides

LAYER=""
PLAN_PATH=""
PLAN_RECORD=""
APPROVAL_RECORD=""
CONTEXT=""
APPLY_INTENT=""
APPROVED_LEDGER=""
APPLYING_LEDGER=""
PLAN_READBACK=""
STATE_READBACK=""
EXPECTED_ROLE_ARN=""
EXPECTED_SOURCE_SHA=""
ACCOUNT_ID=""
REGION=""
CUSTOMER_ID=""
DEPLOYMENT_ID=""
ENVIRONMENT=""
DOMAIN_NAME=""
RELEASE_VERSION=""
RELEASE_DIGEST=""
RESOLVED_INPUT=""
MANIFEST=""
TARGET_RECORD=""
TARGET_ANCHOR=""
ACCOUNT_READY_CONTRACT=""
EXECUTION_LOCK=""
EXECUTION_ID=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --layer)             [[ -n "${2:-}" ]] || die "--layer requires a value"; LAYER="$2"; shift 2 ;;
    --plan|--plan-out)   [[ -n "${2:-}" ]] || die "$1 requires a value"; PLAN_PATH="$2"; shift 2 ;;
    --plan-record)       [[ -n "${2:-}" ]] || die "--plan-record requires a value"; PLAN_RECORD="$2"; shift 2 ;;
    --approval-record)   [[ -n "${2:-}" ]] || die "--approval-record requires a value"; APPROVAL_RECORD="$2"; shift 2 ;;
    --context)           [[ -n "${2:-}" ]] || die "--context requires a value"; CONTEXT="$2"; shift 2 ;;
    --apply-intent)      [[ -n "${2:-}" ]] || die "--apply-intent requires a value"; APPLY_INTENT="$2"; shift 2 ;;
    --approved-ledger)   [[ -n "${2:-}" ]] || die "--approved-ledger requires a value"; APPROVED_LEDGER="$2"; shift 2 ;;
    --applying-ledger)   [[ -n "${2:-}" ]] || die "--applying-ledger requires a value"; APPLYING_LEDGER="$2"; shift 2 ;;
    --plan-readback)     [[ -n "${2:-}" ]] || die "--plan-readback requires a value"; PLAN_READBACK="$2"; shift 2 ;;
    --state-readback)    [[ -n "${2:-}" ]] || die "--state-readback requires a value"; STATE_READBACK="$2"; shift 2 ;;
    --expected-role|--expected-role-arn)
                          [[ -n "${2:-}" ]] || die "$1 requires a value"; EXPECTED_ROLE_ARN="$2"; shift 2 ;;
    --expected-source-sha)
                          [[ -n "${2:-}" ]] || die "--expected-source-sha requires a value"; EXPECTED_SOURCE_SHA="$2"; shift 2 ;;
    --customer-id)       [[ -n "${2:-}" ]] || die "--customer-id requires a value"; CUSTOMER_ID="$2"; shift 2 ;;
    --deployment-id)     [[ -n "${2:-}" ]] || die "--deployment-id requires a value"; DEPLOYMENT_ID="$2"; shift 2 ;;
    --account-id|--expected-account-id)
                          [[ -n "${2:-}" ]] || die "$1 requires a value"; ACCOUNT_ID="$2"; shift 2 ;;
    --region)            [[ -n "${2:-}" ]] || die "--region requires a value"; REGION="$2"; shift 2 ;;
    --environment)       [[ -n "${2:-}" ]] || die "--environment requires a value"; ENVIRONMENT="$2"; shift 2 ;;
    --domain-name)       [[ -n "${2:-}" ]] || die "--domain-name requires a value"; DOMAIN_NAME="$2"; shift 2 ;;
    --release-version)   [[ -n "${2:-}" ]] || die "--release-version requires a value"; RELEASE_VERSION="$2"; shift 2 ;;
    --release-digest)    [[ -n "${2:-}" ]] || die "--release-digest requires a value"; RELEASE_DIGEST="$2"; shift 2 ;;
    --resolved-input)    [[ -n "${2:-}" ]] || die "--resolved-input requires a value"; RESOLVED_INPUT="$2"; shift 2 ;;
    --manifest)          [[ -n "${2:-}" ]] || die "--manifest requires a value"; MANIFEST="$2"; shift 2 ;;
    --target-record)     [[ -n "${2:-}" ]] || die "--target-record requires a value"; TARGET_RECORD="$2"; shift 2 ;;
    --target-anchor)     [[ -n "${2:-}" ]] || die "--target-anchor requires a value"; TARGET_ANCHOR="$2"; shift 2 ;;
    --account-ready)     [[ -n "${2:-}" ]] || die "--account-ready requires a value"; ACCOUNT_READY_CONTRACT="$2"; shift 2 ;;
    --execution-lock)    [[ -n "${2:-}" ]] || die "--execution-lock requires a value"; EXECUTION_LOCK="$2"; shift 2 ;;
    --execution-id)      [[ -n "${2:-}" ]] || die "--execution-id requires a value"; EXECUTION_ID="$2"; shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$LAYER" ]] || die "--layer is required"
[[ "$LAYER" =~ ^[a-z][a-z0-9-]{1,63}$ ]] || die "--layer is invalid"
[[ -n "$PLAN_PATH" ]] || die "--plan or --plan-out is required"
[[ -n "$EXPECTED_ROLE_ARN" ]] || die "--expected-role-arn is required"
[[ -n "$EXPECTED_SOURCE_SHA" ]] || die "--expected-source-sha is required"
[[ -n "$ACCOUNT_ID" ]] || die "--account-id is required"
[[ -n "$REGION" ]] || die "--region is required"
[[ "$REGION" =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]] || die "--region is invalid"
[[ "$EXPECTED_SOURCE_SHA" == "${SCANALYZE_EXPECTED_MAIN_SHA}" ]] \
  || die "The command source SHA does not match the protected binding"
[[ "${AWS_REGION:-}" == "$REGION" && "${AWS_DEFAULT_REGION:-$REGION}" == "$REGION" ]] \
  || die "The AWS region environment is not exact"

require_canonical_terminal_role "$LAYER" "$ACTION" "$EXPECTED_ROLE_ARN"
verify_terminal_identity "$ACCOUNT_ID" "$EXPECTED_ROLE_ARN"

if [[ "$ACTION" == "plan" ]]; then
  [[ -n "$CUSTOMER_ID" ]] || die "--customer-id is required"
  [[ -n "$DEPLOYMENT_ID" ]] || die "--deployment-id is required"
  [[ -n "$MANIFEST" ]] || die "--manifest is required"
  [[ -n "$TARGET_RECORD" ]] || die "--target-record is required"
  [[ -n "$TARGET_ANCHOR" ]] || die "--target-anchor is required"
  [[ -n "$ACCOUNT_READY_CONTRACT" ]] || die "--account-ready is required"
  [[ "$DEPLOYMENT_ID" == "${SCANALYZE_DEPLOYMENT_ID}" ]] \
    || die "The command deployment does not match the protected binding"
  [[ "$ENVIRONMENT" == "dev" ]] || die "Only dev is supported"

  PLAN_PARENT="$(dirname -- "$PLAN_PATH")"
  [[ -d "$PLAN_PARENT" ]] || die "The saved-plan directory does not exist"
  require_outside_repository "$PLAN_PARENT" "Saved-plan directory"
  EXPECTED_PLAN_PATH="$(cd -P -- "$PLAN_PARENT" && pwd -P)/${LAYER}.tfplan"
  REQUESTED_PLAN_PATH="$(cd -P -- "$PLAN_PARENT" && pwd -P)/$(basename -- "$PLAN_PATH")"
  [[ "$REQUESTED_PLAN_PATH" == "$EXPECTED_PLAN_PATH" ]] \
    || die "--plan-out must use the canonical layer filename"

  plan_arguments=(
    plan
    --layer "$LAYER"
    --plan-dir "$PLAN_PARENT"
    --customer-id "$CUSTOMER_ID"
    --deployment-id "$DEPLOYMENT_ID"
    --account-id "$ACCOUNT_ID"
    --region "$REGION"
    --environment "$ENVIRONMENT"
    --manifest "$MANIFEST"
    --target-record "$TARGET_RECORD"
    --target-anchor "$TARGET_ANCHOR"
    --account-ready "$ACCOUNT_READY_CONTRACT"
  )
  [[ -z "$DOMAIN_NAME" ]] || plan_arguments+=(--domain-name "$DOMAIN_NAME")
  [[ -z "$RELEASE_VERSION" ]] || plan_arguments+=(--release-version "$RELEASE_VERSION")
  [[ -z "$RELEASE_DIGEST" ]] || plan_arguments+=(--release-digest "$RELEASE_DIGEST")
  [[ -z "$RESOLVED_INPUT" ]] || plan_arguments+=(--resolved-input "$RESOLVED_INPUT")
  [[ -z "$EXECUTION_LOCK" ]] || plan_arguments+=(--execution-lock "$EXECUTION_LOCK")
  [[ -z "$EXECUTION_ID" ]] || plan_arguments+=(--execution-id "$EXECUTION_ID")

  bash "${SCRIPT_DIR}/terraform-layer.sh" "${plan_arguments[@]}"
  require_private_regular_file "$EXPECTED_PLAN_PATH" "Saved plan"
  pass "Verified Terraform plan created for immutable storage"
  exit 0
fi

[[ "$LAYER" != "account-ready-gate" ]] \
  || die "The ACCOUNT_READY gate never permits apply"
[[ -n "$CONTEXT" ]] || die "--context is required"
[[ -n "$APPLY_INTENT" ]] || die "--apply-intent is required"
[[ -n "$APPROVED_LEDGER" ]] || die "--approved-ledger is required"
[[ -n "$APPLYING_LEDGER" ]] || die "--applying-ledger is required"
[[ -n "$PLAN_RECORD" ]] || die "--plan-record is required"
[[ -n "$APPROVAL_RECORD" ]] || die "--approval-record is required"
[[ -n "$PLAN_READBACK" ]] || die "--plan-readback is required"
[[ -n "$STATE_READBACK" ]] || die "--state-readback is required"
[[ -n "$MANIFEST" ]] || die "--manifest is required"
[[ -n "$TARGET_RECORD" ]] || die "--target-record is required"
[[ -n "$TARGET_ANCHOR" ]] || die "--target-anchor is required"
[[ -n "$ACCOUNT_READY_CONTRACT" ]] || die "--account-ready is required"
[[ -n "$EXECUTION_LOCK" ]] || die "--execution-lock is required"
[[ -n "$CUSTOMER_ID" ]] || die "--customer-id is required"
[[ -n "$DEPLOYMENT_ID" ]] || die "--deployment-id is required"
[[ -n "$EXECUTION_ID" ]] || die "--execution-id is required"

protected_files=(
  "$PLAN_PATH" "$CONTEXT" "$APPLY_INTENT" "$APPROVED_LEDGER"
  "$APPLYING_LEDGER" "$PLAN_RECORD" "$APPROVAL_RECORD" "$PLAN_READBACK"
  "$STATE_READBACK" "$MANIFEST" "$TARGET_RECORD" "$TARGET_ANCHOR"
  "$ACCOUNT_READY_CONTRACT" "$EXECUTION_LOCK"
)
for protected_file in "${protected_files[@]}"; do
  require_outside_repository "$protected_file" "Operational artifact"
  require_private_regular_file "$protected_file" "Operational artifact"
done

VALIDATED_BINDINGS="$(python3 - \
  "$REPO_ROOT" "$CONTEXT" "$APPLY_INTENT" "$PLAN_RECORD" "$APPROVAL_RECORD" \
  "$APPROVED_LEDGER" "$APPLYING_LEDGER" "$PLAN_READBACK" "$STATE_READBACK" \
  "$LAYER" "$CUSTOMER_ID" "$DEPLOYMENT_ID" "$EXECUTION_ID" "$ACCOUNT_ID" \
  "$REGION" "$GITHUB_REPOSITORY" "$GITHUB_REPOSITORY_ID" \
  "$GITHUB_REPOSITORY_OWNER_ID" "$GITHUB_RUN_ID" "${GITHUB_ACTOR_ID:-}" \
  "$GITHUB_SHA" "$SCANALYZE_GITHUB_ENVIRONMENT" <<'PY'
import sys
from datetime import UTC, datetime
from pathlib import Path

(
    repo,
    context_name,
    intent_name,
    record_name,
    approval_name,
    approved_ledger_name,
    applying_ledger_name,
    plan_readback_name,
    state_readback_name,
    layer,
    customer_id,
    deployment_id,
    execution_id,
    account_id,
    region,
    repository,
    repository_id,
    repository_owner_id,
    workflow_run_id,
    actor_id,
    github_sha,
    github_environment,
) = sys.argv[1:]
sys.path.insert(0, repo)
from tooling.authorize_deployment_backend import load_json_strict
from tooling.nonprod_live_orchestrator import validate_apply_intent

context = load_json_strict(Path(context_name))
intent = load_json_strict(Path(intent_name))
record = load_json_strict(Path(record_name))
approval = load_json_strict(Path(approval_name))
approved_ledger = load_json_strict(Path(approved_ledger_name))
applying_ledger = load_json_strict(Path(applying_ledger_name))
plan_readback = load_json_strict(Path(plan_readback_name))
state_readback = load_json_strict(Path(state_readback_name))

exact_workflow_ref = (
    f"{repository}/.github/workflows/nonprod-release.yml@refs/heads/main"
)
if (
    context.get("workflow_ref") != exact_workflow_ref
    or context.get("workflow_sha") != github_sha
    or context.get("repository_id") != int(repository_id)
    or context.get("repository_owner_id") != int(repository_owner_id)
    or context.get("workflow_run_id") != int(workflow_run_id)
    or not actor_id
    or context.get("initiator_user_id") != int(actor_id)
    or context.get("github_environment") != github_environment
):
    raise SystemExit(1)
if (
    context.get("layer") != layer
    or context.get("customer_id") != customer_id
    or context.get("deployment_id") != deployment_id
    or context.get("execution_id") != execution_id
    or context.get("destination_account_id") != account_id
    or context.get("region") != region
):
    raise SystemExit(1)

decision = validate_apply_intent(
    intent=intent,
    context=context,
    plan_record=record,
    approval_record=approval,
    approved_ledger=approved_ledger,
    applying_ledger=applying_ledger,
    plan_readback=plan_readback,
    state_readback=state_readback,
    now=datetime.now(UTC),
)
if decision.get("code") != "EXACT_SAVED_PLAN_APPLY_INTENT_VALIDATED":
    raise SystemExit(1)
print("\t".join((record["layer"], record["account_id"], record["region"])))
PY
)" || die "Exact saved-plan authorization revalidation failed"
[[ "$VALIDATED_BINDINGS" == "${LAYER}"$'\t'"${ACCOUNT_ID}"$'\t'"${REGION}" ]] \
  || die "Exact saved-plan bindings are not authorized"

TERRAFORM_BIN="$(command -v terraform)" || die "Terraform executable is unavailable"
ROOT_DIR="${REPO_ROOT}/roots/${LAYER}"
[[ -d "$ROOT_DIR" && ! -L "$ROOT_DIR" ]] || die "Terraform root is unavailable"

[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] \
  || die "The GitHub runner temporary directory is unavailable"
require_outside_repository "$RUNNER_TEMP" "Runner temporary directory"
CONTROL_DIR="$(mktemp -d "${RUNNER_TEMP}/scanalyze-saved-plan.XXXXXX")" \
  || die "Unable to create a private apply directory"
chmod 0700 "$CONTROL_DIR" || die "Unable to secure the private apply directory"
cleanup() {
  case "$CONTROL_DIR" in
    "${RUNNER_TEMP}"/scanalyze-saved-plan.*) rm -rf -- "$CONTROL_DIR" ;;
    *) return 1 ;;
  esac
}
trap cleanup EXIT INT TERM

CONTROLLED_PLAN="${CONTROL_DIR}/approved.tfplan"
python3 - "$REPO_ROOT" "$PLAN_PATH" "$PLAN_RECORD" "$CONTROLLED_PLAN" <<'PY' \
  || die "Saved-plan custody or digest validation failed"
import hashlib
import os
import stat
import sys
from pathlib import Path

repo, source_name, record_name, destination_name = sys.argv[1:]
sys.path.insert(0, repo)
from tooling.authorize_deployment_backend import load_json_strict
from tooling.nonprod_live_engine import validate_saved_plan_document

record = load_json_strict(Path(record_name))
validate_saved_plan_document(record)
source = os.open(source_name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
destination = -1
try:
    before = os.fstat(source)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
    ):
        raise ValueError("source custody")
    destination = os.open(
        destination_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o400,
    )
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(source, 1024 * 1024)
        if not chunk:
            break
        view = memoryview(chunk)
        while view:
            written = os.write(destination, view)
            view = view[written:]
        digest.update(chunk)
        size += len(chunk)
    os.fsync(destination)
    after = os.fstat(source)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
        item.st_ctime_ns, item.st_mode, item.st_nlink,
    )
    if identity(before) != identity(after):
        raise ValueError("source changed")
    if "sha256:" + digest.hexdigest() != record["plan_sha256"]:
        raise ValueError("digest mismatch")
    if size != record["plan_size_bytes"]:
        raise ValueError("size mismatch")
finally:
    if destination >= 0:
        os.close(destination)
    os.close(source)
PY

BACKEND_CONFIG="${CONTROL_DIR}/backend.hcl"
BACKEND_BINDING="${CONTROL_DIR}/backend-binding.json"
python3 "${REPO_ROOT}/tooling/authorize_deployment_backend.py" \
  --manifest "$MANIFEST" \
  --target "$TARGET_RECORD" \
  --target-anchor "$TARGET_ANCHOR" \
  --account-ready "$ACCOUNT_READY_CONTRACT" \
  --execution-lock "$EXECUTION_LOCK" \
  --layer-catalog "${REPO_ROOT}/deployment/layers.yaml" \
  --layer "$LAYER" \
  --backend-out "$BACKEND_CONFIG" \
  --binding-out "$BACKEND_BINDING" \
  --expected-customer-id "$CUSTOMER_ID" \
  --expected-deployment-id "$DEPLOYMENT_ID" \
  --expected-account-id "$ACCOUNT_ID" \
  --expected-region "$REGION" \
  --expected-execution-id "$EXECUTION_ID" \
  || die "Exact backend reauthorization failed"
require_private_regular_file "$BACKEND_CONFIG" "Backend configuration"
require_private_regular_file "$BACKEND_BINDING" "Backend binding"
python3 - "$REPO_ROOT" "$BACKEND_BINDING" "$PLAN_RECORD" <<'PY' \
  || die "Backend binding changed after the saved plan was created"
import sys
from pathlib import Path

repo, binding_name, record_name = sys.argv[1:]
sys.path.insert(0, repo)
from tooling.authorize_deployment_backend import load_json_strict

binding = load_json_strict(Path(binding_name))
record = load_json_strict(Path(record_name))
if binding.get("binding_digest") != record.get("backend_binding_digest"):
    raise SystemExit(1)
PY

mkdir -m 0700 "${CONTROL_DIR}/home" "${CONTROL_DIR}/tmp" "${CONTROL_DIR}/data"
printf '' > "${CONTROL_DIR}/terraform.rc"
chmod 0600 "${CONTROL_DIR}/terraform.rc"

terraform_environment=(
  "HOME=${CONTROL_DIR}/home"
  "PATH=${PATH:-/usr/bin:/bin}"
  "TMPDIR=${CONTROL_DIR}/tmp"
  "LC_ALL=C"
  "TF_IN_AUTOMATION=1"
  "TF_INPUT=0"
  "TF_CLI_CONFIG_FILE=${CONTROL_DIR}/terraform.rc"
  "TF_DATA_DIR=${CONTROL_DIR}/data"
  "AWS_REGION=${REGION}"
  "AWS_DEFAULT_REGION=${REGION}"
)
for variable_name in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AWS_ROLE_SESSION_NAME; do
  variable_value="${!variable_name:-}"
  [[ -z "$variable_value" ]] || terraform_environment+=("${variable_name}=${variable_value}")
done

env -i "${terraform_environment[@]}" \
  "$TERRAFORM_BIN" -chdir="$ROOT_DIR" init \
  -input=false \
  -no-color \
  -reconfigure \
  -backend-config="$BACKEND_CONFIG" \
  >/dev/null

python3 - "$REPO_ROOT" "$CONTROLLED_PLAN" "$PLAN_RECORD" <<'PY' \
  || die "Controlled saved-plan digest changed before apply"
import hashlib
import os
import sys
from pathlib import Path

repo, plan_name, record_name = sys.argv[1:]
sys.path.insert(0, repo)
from tooling.authorize_deployment_backend import load_json_strict

record = load_json_strict(Path(record_name))
descriptor = os.open(plan_name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
finally:
    os.close(descriptor)
if "sha256:" + digest.hexdigest() != record["plan_sha256"]:
    raise SystemExit(1)
if size != record["plan_size_bytes"]:
    raise SystemExit(1)
PY

# No plan, refresh, target, replacement, destroy, force-unlock, state operation,
# or retry exists in this runner. The one accepted mutation is this exact binary.
env -i "${terraform_environment[@]}" \
  "$TERRAFORM_BIN" -chdir="$ROOT_DIR" apply \
  -input=false \
  -auto-approve \
  -no-color \
  "$CONTROLLED_PLAN"
pass "Exact saved Terraform plan applied once"
