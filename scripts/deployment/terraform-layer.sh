#!/usr/bin/env bash
# terraform-layer.sh — fail-closed Terraform plan wrapper for verified contracts.

set -euo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPO_ROOT="$(cd -P -- "${SCRIPT_DIR}/../.." && pwd -P)"

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
info() { printf 'INFO: %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }

reject_ambient_terraform_environment() {
  local variable_name
  while IFS= read -r variable_name; do
    case "$variable_name" in
      TF_*)
        die "Ambient Terraform environment variable is prohibited: ${variable_name}"
        ;;
    esac
  done < <(compgen -e)
}

ACTION="${1:-}"
shift || die "usage: terraform-layer.sh plan [options]"

if [[ "$ACTION" == "apply" ]]; then
  die "Local Terraform apply is disabled by ADR-017. Only verified plans are supported."
fi
[[ "$ACTION" == "plan" ]] || die "Unknown action: ${ACTION}. Only local plan is supported."
reject_ambient_terraform_environment

LAYER=""
PLAN_DIR=""
CUSTOMER_ID=""
DEPLOYMENT_ID=""
ACCOUNT_ID=""
REGION=""
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
    --layer)           [[ -n "${2:-}" ]] || die "--layer requires a value"; LAYER="$2"; shift 2 ;;
    --plan-dir)        [[ -n "${2:-}" ]] || die "--plan-dir requires a value"; PLAN_DIR="$2"; shift 2 ;;
    --customer-id)     [[ -n "${2:-}" ]] || die "--customer-id requires a value"; CUSTOMER_ID="$2"; shift 2 ;;
    --deployment-id)   [[ -n "${2:-}" ]] || die "--deployment-id requires a value"; DEPLOYMENT_ID="$2"; shift 2 ;;
    --account-id)      [[ -n "${2:-}" ]] || die "--account-id requires a value"; ACCOUNT_ID="$2"; shift 2 ;;
    --region)          [[ -n "${2:-}" ]] || die "--region requires a value"; REGION="$2"; shift 2 ;;
    --environment)     [[ -n "${2:-}" ]] || die "--environment requires a value"; ENVIRONMENT="$2"; shift 2 ;;
    --domain-name)     [[ -n "${2:-}" ]] || die "--domain-name requires a value"; DOMAIN_NAME="$2"; shift 2 ;;
    --release-version) [[ -n "${2:-}" ]] || die "--release-version requires a value"; RELEASE_VERSION="$2"; shift 2 ;;
    --release-digest)  [[ -n "${2:-}" ]] || die "--release-digest requires a value"; RELEASE_DIGEST="$2"; shift 2 ;;
    --resolved-input)  [[ -n "${2:-}" ]] || die "--resolved-input requires a value"; RESOLVED_INPUT="$2"; shift 2 ;;
    --manifest)        [[ -n "${2:-}" ]] || die "--manifest requires a value"; MANIFEST="$2"; shift 2 ;;
    --target-record)   [[ -n "${2:-}" ]] || die "--target-record requires a value"; TARGET_RECORD="$2"; shift 2 ;;
    --target-anchor)   [[ -n "${2:-}" ]] || die "--target-anchor requires a value"; TARGET_ANCHOR="$2"; shift 2 ;;
    --account-ready)   [[ -n "${2:-}" ]] || die "--account-ready requires a value"; ACCOUNT_READY_CONTRACT="$2"; shift 2 ;;
    --execution-lock)  [[ -n "${2:-}" ]] || die "--execution-lock requires a value"; EXECUTION_LOCK="$2"; shift 2 ;;
    --execution-id)    [[ -n "${2:-}" ]] || die "--execution-id requires a value"; EXECUTION_ID="$2"; shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$LAYER" ]] || die "--layer is required"
[[ -n "$PLAN_DIR" ]] || die "--plan-dir is required"
[[ -n "$CUSTOMER_ID" ]] || die "--customer-id is required"
[[ -n "$DEPLOYMENT_ID" ]] || die "--deployment-id is required"
[[ -n "$ACCOUNT_ID" ]] || die "--account-id is required"
[[ -n "$REGION" ]] || die "--region is required"
[[ -n "$MANIFEST" ]] || die "--manifest is required"
[[ -n "$TARGET_RECORD" ]] || die "--target-record is required"
[[ -n "$TARGET_ANCHOR" ]] || die "--target-anchor is required"
[[ -n "$ACCOUNT_READY_CONTRACT" ]] || die "--account-ready is required"

BACKENDLESS_GATE=false
if [[ "$LAYER" == "account-ready-gate" ]]; then
  BACKENDLESS_GATE=true
else
  [[ -n "$RELEASE_VERSION" ]] || die "--release-version is required"
  [[ -n "$RELEASE_DIGEST" ]] || die "--release-digest is required"
  [[ -n "$RESOLVED_INPUT" ]] || die "--resolved-input is required"
  [[ -n "$EXECUTION_LOCK" ]] || die "--execution-lock is required"
  [[ -n "$EXECUTION_ID" ]] || die "--execution-id is required"
fi

ROOT_DIR="${REPO_ROOT}/roots/${LAYER}"
[[ -d "$ROOT_DIR" ]] || die "Layer root not found"
ROOT_REQUIRES_DOMAIN=false
if grep -q '^variable "domain_name"' "${ROOT_DIR}"/*.tf; then
  ROOT_REQUIRES_DOMAIN=true
  [[ -n "$DOMAIN_NAME" ]] || die "--domain-name is required for layer ${LAYER}"
fi
if grep -q '^variable "environment"' "${ROOT_DIR}"/*.tf && [[ -z "$ENVIRONMENT" ]]; then
  die "--environment is required for layer ${LAYER}"
fi

ABS_PLAN_DIR="$(cd -P -- "$PLAN_DIR" 2>/dev/null && pwd -P)" \
  || die "--plan-dir does not exist"
[[ "$ABS_PLAN_DIR" != "$REPO_ROOT" && "$ABS_PLAN_DIR" != "$REPO_ROOT/"* ]] \
  || die "--plan-dir must be outside the repository"

FINAL_PLAN_FILE="${ABS_PLAN_DIR}/${LAYER}.tfplan"
FINAL_PLAN_SUMMARY="${ABS_PLAN_DIR}/${LAYER}-plan-summary.txt"
CONTROL_DIR=""
MATERIALIZED_VARS=""
BACKEND_CONFIG=""
BACKEND_BINDING=""
PLAN_FILE=""
PLAN_SUMMARY=""
TERRAFORM_HOME=""
TERRAFORM_ROOT="$ROOT_DIR"

refuse_existing_artifact() {
  local destination="$1"
  local label="$2"
  if [[ -e "$destination" || -L "$destination" ]]; then
    die "${label} destination already exists"
  fi
}

publish_private_artifacts() {
  python3 - \
    "$PLAN_SUMMARY" "$FINAL_PLAN_SUMMARY" \
    "$PLAN_FILE" "$FINAL_PLAN_FILE" <<'PY'
import os
import stat
import sys

pairs = list(zip(sys.argv[1::2], sys.argv[2::2], strict=True))
identities = {}
created = []

try:
    for staged, destination in pairs:
        descriptor = os.open(
            staged,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError("staged artifact is not regular")
            os.fchmod(descriptor, 0o600)
            identities[destination] = (metadata.st_dev, metadata.st_ino)
        finally:
            os.close(descriptor)

    for staged, destination in pairs:
        os.link(staged, destination, follow_symlinks=False)
        created.append(destination)
except (OSError, TypeError, ValueError):
    for destination in created:
        try:
            metadata = os.stat(destination, follow_symlinks=False)
            if (metadata.st_dev, metadata.st_ino) == identities[destination]:
                os.unlink(destination)
        except OSError:
            pass
    print("DENY: private plan artifact publication failed", file=sys.stderr)
    raise SystemExit(1)
PY
}

refuse_existing_artifact "$FINAL_PLAN_FILE" "Terraform plan"
refuse_existing_artifact "$FINAL_PLAN_SUMMARY" "Terraform plan summary"

cleanup() {
  if [[ -n "$MATERIALIZED_VARS" || -n "$BACKEND_CONFIG" || -n "$BACKEND_BINDING" ]]; then
    rm -f -- "$MATERIALIZED_VARS" "$BACKEND_CONFIG" "$BACKEND_BINDING"
  fi
  if [[ -n "$TERRAFORM_HOME" && -d "$TERRAFORM_HOME" ]]; then
    rm -rf -- "$TERRAFORM_HOME"
  fi
  if [[ -n "$CONTROL_DIR" && -d "$CONTROL_DIR" ]]; then
    rmdir -- "$CONTROL_DIR" 2>/dev/null || true
  fi
}

PLAN_DIR_ID="$(python3 - "$ABS_PLAN_DIR" <<'PY'
import os
import stat
import sys
from pathlib import Path


def sanitized_exception(_exception_type, _exception, _traceback):
    print("plan directory custody validation failed", file=sys.stderr)


sys.excepthook = sanitized_exception

candidate = Path(sys.argv[1])
trusted_owners = {0, os.geteuid()}
for current in (candidate, *candidate.parents):
    metadata = current.lstat()
    sticky_root = (
        metadata.st_uid == 0
        and bool(metadata.st_mode & stat.S_ISVTX)
    )
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in trusted_owners
        or (
            metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            and not sticky_root
        )
    ):
        raise SystemExit("plan directory ancestry is not owner-controlled")

flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(candidate, flags)
try:
    metadata = os.fstat(descriptor)
    safe = (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0
    )
finally:
    os.close(descriptor)
if not safe:
    raise SystemExit("plan directory is not owner-controlled")
print(f"{metadata.st_dev}:{metadata.st_ino}")
PY
)" || die "--plan-dir must have owner-controlled ancestry"
[[ -n "$PLAN_DIR_ID" ]] \
  || die "Unable to bind plan directory identity"

require_plan_dir_identity() {
  python3 - "$ABS_PLAN_DIR" "$PLAN_DIR_ID" <<'PY'
import os
import stat
import sys


def sanitized_exception(_exception_type, _exception, _traceback):
    print("plan directory identity validation failed", file=sys.stderr)


sys.excepthook = sanitized_exception

flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(sys.argv[1], flags)
try:
    metadata = os.fstat(descriptor)
finally:
    os.close(descriptor)
identity = f"{metadata.st_dev}:{metadata.st_ino}"
if (
    identity != sys.argv[2]
    or not stat.S_ISDIR(metadata.st_mode)
    or metadata.st_uid != os.geteuid()
    or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
):
    raise SystemExit("plan directory identity changed")
PY
}

if ! require_plan_dir_identity; then
  die "--plan-dir must be an owner-controlled directory"
fi

CONTROL_DIR="$(mktemp -d "${ABS_PLAN_DIR}/.${LAYER}.control.XXXXXX")" \
  || die "Unable to create private plan control directory"
trap cleanup EXIT INT TERM
chmod 0700 "$CONTROL_DIR" \
  || die "Unable to secure private plan control directory"
require_plan_dir_identity \
  || die "Plan directory identity changed during control setup"
MATERIALIZED_VARS="${CONTROL_DIR}/materialized.auto.tfvars.json"
BACKEND_CONFIG="${CONTROL_DIR}/backend.hcl"
BACKEND_BINDING="${CONTROL_DIR}/backend-binding.json"

terraform_variables=()
if [[ "$BACKENDLESS_GATE" == true ]]; then
  python3 "${REPO_ROOT}/tooling/authorize_deployment_backend.py" \
    --backendless-gate \
    --manifest "$MANIFEST" \
    --target "$TARGET_RECORD" \
    --target-anchor "$TARGET_ANCHOR" \
    --account-ready "$ACCOUNT_READY_CONTRACT" \
    --layer "$LAYER" \
    --gate-vars-out "$MATERIALIZED_VARS" \
    --expected-customer-id "$CUSTOMER_ID" \
    --expected-deployment-id "$DEPLOYMENT_ID" \
    --expected-account-id "$ACCOUNT_ID" \
    --expected-region "$REGION" \
    --expected-environment "$ENVIRONMENT" \
    || die "Verified ACCOUNT_READY v2 gate binding is required"
  terraform_variables=("-var-file=${MATERIALIZED_VARS}")
else
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
    || die "Authorized registry-backed backend binding is required"
  require_plan_dir_identity \
    || die "Plan directory identity changed after backend authorization"

  AUTHORIZED_BINDINGS="$(python3 - \
    "$BACKEND_BINDING" "$BACKEND_CONFIG" "$REPO_ROOT" \
    "$CUSTOMER_ID" "$DEPLOYMENT_ID" "$ACCOUNT_ID" "$REGION" \
    "$LAYER" "$EXECUTION_ID" "$ROOT_REQUIRES_DOMAIN" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path


def sanitized_exception(_exception_type, _exception, _traceback):
    print("backend binding revalidation failed", file=sys.stderr)


sys.excepthook = sanitized_exception

import jsonschema  # noqa: E402

(
    binding_name,
    backend_name,
    repo_root,
    customer_id,
    deployment_id,
    account_id,
    region,
    layer,
    execution_id,
    root_requires_domain,
) = sys.argv[1:]


def reject_duplicate_keys(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON key")
        document[key] = value
    return document


def read_private_regular(path, *, json_document=False):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise ValueError("authorization artifact custody is invalid")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            if json_document:
                return json.load(handle, object_pairs_hook=reject_duplicate_keys)
            return handle.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


binding = read_private_regular(binding_name, json_document=True)
if not isinstance(binding, dict):
    raise ValueError("backend binding must be an object")
schema_version = binding.get("schema_version")
if schema_version not in {"1", "2"}:
    raise ValueError("backend binding schema is unsupported")
schema_path = Path(repo_root) / "schemas" / f"terraform-backend-binding.v{schema_version}.schema.json"
schema = json.loads(schema_path.read_text(encoding="utf-8"))
jsonschema.Draft202012Validator(
    schema,
    format_checker=jsonschema.FormatChecker(),
).validate(binding)

digest_body = {key: value for key, value in binding.items() if key != "binding_digest"}
canonical = json.dumps(
    digest_body,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
).encode("ascii")
expected_binding_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
if binding.get("binding_digest") != expected_binding_digest:
    raise ValueError("backend binding digest mismatch")

expected_tuple = {
    "customer_id": customer_id,
    "deployment_id": deployment_id,
    "account_id": account_id,
    "region": region,
    "layer": layer,
    "execution_id": execution_id,
}
if any(binding.get(key) != value for key, value in expected_tuple.items()):
    raise ValueError("backend binding request tuple mismatch")
backend = binding.get("backend")
if not isinstance(backend, dict) or (
    backend.get("region") != region
    or backend.get("allowed_account_ids") != [account_id]
):
    raise ValueError("backend binding authority mismatch")

backend_content = read_private_regular(backend_name)
expected_backend_lines = [
    f'bucket = {json.dumps(backend["bucket"])}',
    f'key = {json.dumps(backend["key"])}',
    f'region = {json.dumps(backend["region"])}',
    "encrypt = true",
    f'kms_key_id = {json.dumps(backend["kms_key_id"])}',
    "use_lockfile = true",
    f'allowed_account_ids = [{json.dumps(backend["allowed_account_ids"][0])}]',
    "",
]
if backend_content != "\n".join(expected_backend_lines):
    raise ValueError("backend configuration does not match its binding")

environment = binding.get("environment")
account_ready_digest = binding.get("account_ready_digest")
if not isinstance(environment, str) or "|" in environment or "\n" in environment:
    raise ValueError("authorized environment binding is unavailable")
if (
    not isinstance(account_ready_digest, str)
    or re.fullmatch(r"sha256:[a-f0-9]{64}", account_ready_digest) is None
):
    raise ValueError("authorized ACCOUNT_READY digest binding is unavailable")

domain_name = ""
if root_requires_domain == "true":
    runtime_origin = binding.get("runtime_origin")
    domain_name = (
        runtime_origin.get("domain_name")
        if isinstance(runtime_origin, dict)
        else None
    )
    if (
        schema_version != "2"
        or not isinstance(domain_name, str)
        or re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
            domain_name,
        )
        is None
    ):
        raise ValueError("authorized runtime-origin domain is unavailable")

print("|".join((environment, account_ready_digest, domain_name)))
PY
  )" || die "Unable to revalidate authorized backend binding"
  IFS='|' read -r \
    AUTHORIZED_ENVIRONMENT AUTHORIZED_ACCOUNT_READY_DIGEST AUTHORIZED_DOMAIN_NAME \
    <<< "$AUTHORIZED_BINDINGS"
  [[ -z "$ENVIRONMENT" || "$ENVIRONMENT" == "$AUTHORIZED_ENVIRONMENT" ]] \
    || die "--environment conflicts with the authorized deployment target"
  ENVIRONMENT="$AUTHORIZED_ENVIRONMENT"

  if [[ "$ROOT_REQUIRES_DOMAIN" == true ]]; then
    [[ "$DOMAIN_NAME" == "$AUTHORIZED_DOMAIN_NAME" ]] \
      || die "--domain-name conflicts with the authorized deployment target"
    DOMAIN_NAME="$AUTHORIZED_DOMAIN_NAME"
  fi

  CALLER_ACCOUNT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)" \
    || die "Unable to verify AWS caller identity"
  [[ "$CALLER_ACCOUNT" == "$ACCOUNT_ID" ]] \
    || die "Caller account does not match the expected account"
  pass "Account binding verified"

  export AWS_REGION="$REGION"
  export AWS_DEFAULT_REGION="$REGION"

  python3 "${SCRIPT_DIR}/validate-contract-resolution.py" \
    --resolution "$RESOLVED_INPUT" \
    --layer "$LAYER" \
    --customer-id "$CUSTOMER_ID" \
    --deployment-id "$DEPLOYMENT_ID" \
    --account-id "$ACCOUNT_ID" \
    --region "$REGION" \
    --release-version "$RELEASE_VERSION" \
    --release-digest "$RELEASE_DIGEST" \
    --expected-account-ready-digest "$AUTHORIZED_ACCOUNT_READY_DIGEST" \
    --materialize-out "$MATERIALIZED_VARS" \
    || die "Verified contract resolution is required before Terraform plan"

  terraform_variables=(
    "-var-file=${MATERIALIZED_VARS}"
    "-var=deployment_id=${DEPLOYMENT_ID}"
    "-var=account_id=${ACCOUNT_ID}"
    "-var=region=${REGION}"
  )
  if grep -q '^variable "customer_id"' "${ROOT_DIR}"/*.tf; then
    terraform_variables+=("-var=customer_id=${CUSTOMER_ID}")
  fi
  if grep -q '^variable "environment"' "${ROOT_DIR}"/*.tf; then
    terraform_variables+=("-var=environment=${ENVIRONMENT}")
  fi
  if [[ "$ROOT_REQUIRES_DOMAIN" == true ]]; then
    terraform_variables+=("-var=domain_name=${DOMAIN_NAME}")
  fi
  if grep -q '^variable "release_version"' "${ROOT_DIR}"/*.tf; then
    terraform_variables+=("-var=release_version=${RELEASE_VERSION}")
  fi
  if grep -q '^variable "release_manifest_digest"' "${ROOT_DIR}"/*.tf; then
    terraform_variables+=("-var=release_manifest_digest=${RELEASE_DIGEST}")
  fi
fi

require_plan_dir_identity \
  || die "Plan directory identity changed before Terraform setup"
TERRAFORM_BIN="$(command -v terraform)" \
  || die "Terraform executable is not available"
TERRAFORM_HOME="$(mktemp -d "${ABS_PLAN_DIR}/.${LAYER}.terraform-home.XXXXXX")" \
  || die "Unable to create controlled Terraform environment"
chmod 0700 "$TERRAFORM_HOME"
mkdir -m 0700 "$TERRAFORM_HOME/tmp"
mkdir -m 0700 "$TERRAFORM_HOME/artifacts"
mkdir -m 0700 "$TERRAFORM_HOME/data"
if [[ "$BACKENDLESS_GATE" == true ]]; then
  mkdir -m 0700 "$TERRAFORM_HOME/provider-mirror"
  python3 - \
    "$TERRAFORM_HOME/provider-mirror" \
    "$TERRAFORM_HOME/terraform.rc" <<'PY'
import json
import sys
from pathlib import Path

mirror_path, configuration_path = sys.argv[1:]
Path(configuration_path).write_text(
    "provider_installation {\n"
    "  filesystem_mirror {\n"
    f"    path = {json.dumps(mirror_path)}\n"
    "  }\n"
    "}\n",
    encoding="utf-8",
)
PY
else
  printf '' > "${TERRAFORM_HOME}/terraform.rc"
fi
chmod 0600 "${TERRAFORM_HOME}/terraform.rc"
PLAN_FILE="${TERRAFORM_HOME}/artifacts/${LAYER}.tfplan"
PLAN_SUMMARY="${TERRAFORM_HOME}/artifacts/${LAYER}-plan-summary.txt"
: > "$PLAN_FILE"
chmod 0600 "$PLAN_FILE"
: > "$PLAN_SUMMARY"
chmod 0600 "$PLAN_SUMMARY"

if [[ "$BACKENDLESS_GATE" == true ]]; then
  TERRAFORM_ROOT="${TERRAFORM_HOME}/root"
  mkdir -m 0700 "$TERRAFORM_ROOT"
  gate_configuration_found=false
  for configuration_file in "$ROOT_DIR"/*.tf; do
    [[ -f "$configuration_file" && ! -L "$configuration_file" ]] \
      || die "ACCOUNT_READY gate configuration must contain only regular Terraform files"
    cp -- "$configuration_file" "$TERRAFORM_ROOT/"
    chmod 0600 "${TERRAFORM_ROOT}/$(basename -- "$configuration_file")"
    gate_configuration_found=true
  done
  [[ "$gate_configuration_found" == true ]] \
    || die "ACCOUNT_READY gate configuration is unavailable"
fi

terraform_environment=(
  "HOME=${TERRAFORM_HOME}"
  "PATH=${PATH:-/usr/bin:/bin}"
  "TMPDIR=${TERRAFORM_HOME}/tmp"
  "LC_ALL=C"
  "TF_IN_AUTOMATION=1"
  "TF_INPUT=0"
  "TF_CLI_CONFIG_FILE=${TERRAFORM_HOME}/terraform.rc"
  "AWS_REGION=${REGION}"
  "AWS_DEFAULT_REGION=${REGION}"
)
preserved_aws_environment=(
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
  AWS_SESSION_TOKEN
  AWS_WEB_IDENTITY_TOKEN_FILE
  AWS_ROLE_ARN
  AWS_ROLE_SESSION_NAME
  AWS_PROFILE
  AWS_CONFIG_FILE
  AWS_SHARED_CREDENTIALS_FILE
  AWS_SDK_LOAD_CONFIG
  AWS_EC2_METADATA_DISABLED
)
if [[ "$BACKENDLESS_GATE" == true ]]; then
  terraform_environment+=(
    "AWS_EC2_METADATA_DISABLED=true"
    "CHECKPOINT_DISABLE=1"
    "TF_DATA_DIR=${TERRAFORM_HOME}/data"
  )
else
  for variable_name in "${preserved_aws_environment[@]}"; do
    variable_value="${!variable_name:-}"
    if [[ -n "$variable_value" ]]; then
      terraform_environment+=("${variable_name}=${variable_value}")
    fi
  done
fi

require_plan_dir_identity \
  || die "Plan directory identity changed before Terraform init"
if [[ "$BACKENDLESS_GATE" == true ]]; then
  info "Initializing verified ACCOUNT_READY gate without a backend..."
  env -i "${terraform_environment[@]}" "$TERRAFORM_BIN" -chdir="$TERRAFORM_ROOT" init \
    -backend=false \
    -input=false \
    -no-color \
    >/dev/null
else
  info "Initializing verified registry-backed layer plan..."
  env -i "${terraform_environment[@]}" "$TERRAFORM_BIN" -chdir="$TERRAFORM_ROOT" init \
    -input=false \
    -no-color \
    -reconfigure \
    -backend-config="$BACKEND_CONFIG" \
    >/dev/null
fi

require_plan_dir_identity \
  || die "Plan directory identity changed before Terraform plan"
info "Planning verified layer..."
if [[ "$BACKENDLESS_GATE" == true ]]; then
  env -i "${terraform_environment[@]}" "$TERRAFORM_BIN" -chdir="$TERRAFORM_ROOT" plan \
    -input=false \
    -no-color \
    -refresh=false \
    -lock=false \
    -state="${TERRAFORM_HOME}/gate-empty.tfstate" \
    -out="$PLAN_FILE" \
    "${terraform_variables[@]}" \
    2>&1 | tee "$PLAN_SUMMARY"
else
  env -i "${terraform_environment[@]}" "$TERRAFORM_BIN" -chdir="$TERRAFORM_ROOT" plan \
    -input=false \
    -no-color \
    -out="$PLAN_FILE" \
    "${terraform_variables[@]}" \
    2>&1 | tee "$PLAN_SUMMARY"
fi

require_plan_dir_identity \
  || die "Plan directory identity changed before artifact publication"
if grep -qE '(destroy|replace)' "$PLAN_SUMMARY" 2>/dev/null; then
  warn "Destructive changes detected; reviewed approval remains mandatory."
fi

publish_private_artifacts \
  || die "Unable to publish private Terraform plan artifacts"

pass "Verified plan saved outside the repository"
