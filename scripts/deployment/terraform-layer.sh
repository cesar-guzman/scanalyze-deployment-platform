#!/usr/bin/env bash
# terraform-layer.sh — fail-closed Terraform plan wrapper for verified contracts.

set -euo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
info() { printf 'INFO: %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }

ACTION="${1:-}"
shift || die "usage: terraform-layer.sh plan [options]"

if [[ "$ACTION" == "apply" ]]; then
  die "Local Terraform apply is disabled by ADR-017. Only verified plans are supported."
fi
[[ "$ACTION" == "plan" ]] || die "Unknown action: ${ACTION}. Only local plan is supported."

LAYER=""
PLAN_DIR=""
CUSTOMER_ID=""
DEPLOYMENT_ID=""
ACCOUNT_ID=""
REGION=""
RELEASE_VERSION=""
RELEASE_DIGEST=""
RESOLVED_INPUT=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --layer)           [[ -n "${2:-}" ]] || die "--layer requires a value"; LAYER="$2"; shift 2 ;;
    --plan-dir)        [[ -n "${2:-}" ]] || die "--plan-dir requires a value"; PLAN_DIR="$2"; shift 2 ;;
    --customer-id)     [[ -n "${2:-}" ]] || die "--customer-id requires a value"; CUSTOMER_ID="$2"; shift 2 ;;
    --deployment-id)   [[ -n "${2:-}" ]] || die "--deployment-id requires a value"; DEPLOYMENT_ID="$2"; shift 2 ;;
    --account-id)      [[ -n "${2:-}" ]] || die "--account-id requires a value"; ACCOUNT_ID="$2"; shift 2 ;;
    --region)          [[ -n "${2:-}" ]] || die "--region requires a value"; REGION="$2"; shift 2 ;;
    --release-version) [[ -n "${2:-}" ]] || die "--release-version requires a value"; RELEASE_VERSION="$2"; shift 2 ;;
    --release-digest)  [[ -n "${2:-}" ]] || die "--release-digest requires a value"; RELEASE_DIGEST="$2"; shift 2 ;;
    --resolved-input)  [[ -n "${2:-}" ]] || die "--resolved-input requires a value"; RESOLVED_INPUT="$2"; shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$LAYER" ]] || die "--layer is required"
[[ -n "$PLAN_DIR" ]] || die "--plan-dir is required"
[[ -n "$CUSTOMER_ID" ]] || die "--customer-id is required"
[[ -n "$DEPLOYMENT_ID" ]] || die "--deployment-id is required"
[[ -n "$ACCOUNT_ID" ]] || die "--account-id is required"
[[ -n "$REGION" ]] || die "--region is required"
[[ -n "$RELEASE_VERSION" ]] || die "--release-version is required"
[[ -n "$RELEASE_DIGEST" ]] || die "--release-digest is required"
[[ -n "$RESOLVED_INPUT" ]] || die "--resolved-input is required"

ROOT_DIR="${REPO_ROOT}/roots/${LAYER}"
[[ -d "$ROOT_DIR" ]] || die "Layer root not found"

ABS_PLAN_DIR="$(cd "$PLAN_DIR" && pwd)" || die "--plan-dir does not exist"
[[ "$ABS_PLAN_DIR" != "$REPO_ROOT" && "$ABS_PLAN_DIR" != "$REPO_ROOT/"* ]] \
  || die "--plan-dir must be outside the repository"

CALLER_ACCOUNT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)" \
  || die "Unable to verify AWS caller identity"
[[ "$CALLER_ACCOUNT" == "$ACCOUNT_ID" ]] \
  || die "Caller account does not match the expected account"
pass "Account binding verified"

export AWS_REGION="$REGION"
export AWS_DEFAULT_REGION="$REGION"

MATERIALIZED_VARS="${ABS_PLAN_DIR}/.${LAYER}.$$.auto.tfvars.json"
PLAN_FILE="${ABS_PLAN_DIR}/${LAYER}.tfplan"
PLAN_SUMMARY="${ABS_PLAN_DIR}/${LAYER}-plan-summary.txt"
cleanup() {
  rm -f -- "$MATERIALIZED_VARS"
}
trap cleanup EXIT INT TERM

python3 "${SCRIPT_DIR}/validate-contract-resolution.py" \
  --resolution "$RESOLVED_INPUT" \
  --layer "$LAYER" \
  --customer-id "$CUSTOMER_ID" \
  --deployment-id "$DEPLOYMENT_ID" \
  --account-id "$ACCOUNT_ID" \
  --region "$REGION" \
  --release-version "$RELEASE_VERSION" \
  --release-digest "$RELEASE_DIGEST" \
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
if grep -q '^variable "release_version"' "${ROOT_DIR}"/*.tf; then
  terraform_variables+=("-var=release_version=${RELEASE_VERSION}")
fi
if grep -q '^variable "release_manifest_digest"' "${ROOT_DIR}"/*.tf; then
  terraform_variables+=("-var=release_manifest_digest=${RELEASE_DIGEST}")
fi

info "Initializing verified layer plan..."
terraform -chdir="$ROOT_DIR" init -input=false -no-color -backend=false >/dev/null

info "Planning verified layer..."
terraform -chdir="$ROOT_DIR" plan \
  -input=false \
  -no-color \
  -out="$PLAN_FILE" \
  "${terraform_variables[@]}" \
  2>&1 | tee "$PLAN_SUMMARY"

if grep -qE '(destroy|replace)' "$PLAN_SUMMARY" 2>/dev/null; then
  warn "Destructive changes detected; reviewed approval remains mandatory."
fi

pass "Verified plan saved outside the repository"
