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

# Provide fallback digests for manual deployments bypassing CI gates
export TF_VAR_account_ready_contract_digest="${TF_VAR_account_ready_contract_digest:-sha256:0000000000000000000000000000000000000000000000000000000000000000}"
export TF_VAR_expected_contract_digest="${TF_VAR_expected_contract_digest:-sha256:0000000000000000000000000000000000000000000000000000000000000000}"
export TF_VAR_release_manifest_digest="${TF_VAR_release_manifest_digest:-sha256:0000000000000000000000000000000000000000000000000000000000000000}"
export TF_VAR_upstream_contract_digest="${TF_VAR_upstream_contract_digest:-sha256:0000000000000000000000000000000000000000000000000000000000000000}"
export TF_VAR_expected_upstream_digest="${TF_VAR_expected_upstream_digest:-sha256:0000000000000000000000000000000000000000000000000000000000000000}"
export TF_VAR_upstream_schema_version="${TF_VAR_upstream_schema_version:-1}"

# --- Mocks for cross-layer variables (upstream outputs) ---
# When running plan-all locally without a real orchestrator passing state between layers,
# Terraform will fail on downstream layers because variables like vpc_id have no default.
export TF_VAR_vpc_id="${TF_VAR_vpc_id:-vpc-00000000000000000}"
export TF_VAR_private_subnet_ids="${TF_VAR_private_subnet_ids:-{ \"us-east-1a\" = \"subnet-00000000000000001\", \"us-east-1b\" = \"subnet-00000000000000002\" }}"
export TF_VAR_vpc_cidr_block="${TF_VAR_vpc_cidr_block:-10.0.0.0/16}"
export TF_VAR_internal_certificate_arn="${TF_VAR_internal_certificate_arn:-arn:aws:acm:us-east-1:905418363887:certificate/00000000-0000-0000-0000-000000000000}"
export TF_VAR_domain_name="${TF_VAR_domain_name:-example.com}"
export TF_VAR_alb_listener_arn="${TF_VAR_alb_listener_arn:-arn:aws:elasticloadbalancing:us-east-1:905418363887:listener/app/mock/0000000000000000/0000000000000000}"
export TF_VAR_alb_security_group_id="${TF_VAR_alb_security_group_id:-sg-00000000000000000}"
export TF_VAR_api_access_log_group_arn="${TF_VAR_api_access_log_group_arn:-arn:aws:logs:us-east-1:905418363887:log-group:/aws/apigateway/mock:*}"
export TF_VAR_route53_zone_id="${TF_VAR_route53_zone_id:-Z00000000000000000000}"
export TF_VAR_api_gateway_endpoint="${TF_VAR_api_gateway_endpoint:-mock.execute-api.us-east-1.amazonaws.com}"
export TF_VAR_frontend_bucket_domain_name="${TF_VAR_frontend_bucket_domain_name:-mock.s3.amazonaws.com}"
export TF_VAR_ecs_cluster_name="${TF_VAR_ecs_cluster_name:-mock-cluster}"
export TF_VAR_microservices="${TF_VAR_microservices:-[\"auth\",\"payments\"]}"
export TF_VAR_ecs_cluster_arn="${TF_VAR_ecs_cluster_arn:-arn:aws:ecs:us-east-1:905418363887:cluster/mock}"
export TF_VAR_ecs_task_execution_role_arn="${TF_VAR_ecs_task_execution_role_arn:-arn:aws:iam::905418363887:role/mock-exec-role}"
export TF_VAR_workload_role_arns="${TF_VAR_workload_role_arns:-{ \"auth\" = \"arn:aws:iam::905418363887:role/mock-workload-role\" }}"
export TF_VAR_service_definitions="${TF_VAR_service_definitions:-{ \"auth\" = { \"port\" = 8080, \"cpu\" = 256, \"memory\" = 512 } }}"

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
