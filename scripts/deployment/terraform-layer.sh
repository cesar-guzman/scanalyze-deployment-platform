#!/usr/bin/env bash
# terraform-layer.sh — Safe Terraform wrapper with account binding
#
# Usage:
#   terraform-layer.sh plan --layer <name> --plan-dir <path> --account-id <id> --region <region> --deployment-id <id>
#   terraform-layer.sh apply --layer <name> --plan-dir <path> --account-id <id> --region <region> --deployment-id <id>

set -euo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
info() { printf 'INFO: %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }

ACTION="${1:-}"
shift || die "usage: terraform-layer.sh <plan|apply> [options]"

LAYER=""
PLAN_DIR=""
ACCOUNT_ID=""
REGION=""
DEPLOYMENT_ID=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --layer)          LAYER="$2"; shift 2 ;;
    --plan-dir)       PLAN_DIR="$2"; shift 2 ;;
    --account-id)     ACCOUNT_ID="$2"; shift 2 ;;
    --region)         REGION="$2"; shift 2 ;;
    --deployment-id)  DEPLOYMENT_ID="$2"; shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$LAYER" ]] || die "--layer is required"
[[ -n "$PLAN_DIR" ]] || die "--plan-dir is required"
[[ -n "$ACCOUNT_ID" ]] || die "--account-id is required"
[[ -n "$REGION" ]] || die "--region is required"
[[ -n "$DEPLOYMENT_ID" ]] || die "--deployment-id is required"

ROOT_DIR="${REPO_ROOT}/roots/${LAYER}"
[[ -d "$ROOT_DIR" ]] || die "Layer root not found: ${ROOT_DIR}"

# Verify plan-dir is outside repo
ABS_PLAN_DIR="$(cd "$PLAN_DIR" && pwd)"
[[ "$ABS_PLAN_DIR" != "$REPO_ROOT"* ]] || die "--plan-dir must be outside the repository"

# Verify account binding
CALLER_ACCOUNT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)" \
  || die "Unable to verify AWS caller identity"
[[ "$CALLER_ACCOUNT" == "$ACCOUNT_ID" ]] \
  || die "Caller account ($CALLER_ACCOUNT) does not match expected ($ACCOUNT_ID)"

pass "Account binding verified: ${ACCOUNT_ID}"

export AWS_REGION="$REGION"
export AWS_DEFAULT_REGION="$REGION"

PLAN_FILE="${ABS_PLAN_DIR}/${LAYER}.tfplan"

case "$ACTION" in
  plan)
    info "Initializing roots/${LAYER}..."
    terraform -chdir="$ROOT_DIR" init -input=false -no-color -backend=false 2>&1 | tail -1

    info "Planning roots/${LAYER}..."
    terraform -chdir="$ROOT_DIR" plan \
      -input=false \
      -no-color \
      -out="$PLAN_FILE" \
      -var="deployment_id=${DEPLOYMENT_ID}" \
      -var="account_id=${ACCOUNT_ID}" \
      -var="region=${REGION}" \
      2>&1 | tee "${ABS_PLAN_DIR}/${LAYER}-plan-summary.txt"

    # Check for destructive changes
    if grep -qE '(destroy|replace)' "${ABS_PLAN_DIR}/${LAYER}-plan-summary.txt" 2>/dev/null; then
      warn "DESTRUCTIVE CHANGES detected in ${LAYER} plan. Review before apply."
    fi

    pass "Plan saved to: ${PLAN_FILE}"
    ;;

  apply)
    [[ -f "$PLAN_FILE" ]] || die "No saved plan found: ${PLAN_FILE}. Run plan first."

    if [[ "${SCANALYZE_ALLOW_LIVE:-}" != "1" ]]; then
      die "Apply requires SCANALYZE_ALLOW_LIVE=1"
    fi

    info "Applying saved plan for roots/${LAYER}..."
    terraform -chdir="$ROOT_DIR" apply \
      -input=false \
      -no-color \
      "$PLAN_FILE"

    pass "Layer ${LAYER} applied successfully"
    ;;

  *)
    die "Unknown action: ${ACTION}. Use 'plan' or 'apply'."
    ;;
esac
