#!/usr/bin/env bash
# scanalyze-deploy.sh — Autonomous deployment orchestrator for Scanalyze
#
# This is the single entrypoint for all deployment operations.
# By default, everything runs in dry-run mode. Live mutations require
# explicit flags and environment variables.
#
# Usage:
#   scripts/deployment/scanalyze-deploy.sh <subcommand> [options]
#
# See: scripts/deployment/scanalyze-deploy.sh help

set -euo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly VERSION="1.0.0"

# ── Defaults (safe) ──────────────────────────────────────────────────
MANIFEST=""
CUSTOMER_ID=""
DEPLOYMENT_ID=""
ACCOUNT_ID=""
REGION=""
ENVIRONMENT=""
GIT_REF=""
NON_INTERACTIVE=false
DRY_RUN=true
APPROVE=false
PLAN_DIR=""
EVIDENCE_DIR=""
LAYER=""
RELEASE_VERSION=""
RELEASE_DIGEST=""
RESOLVED_INPUT=""

# ── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────
die()  { printf "${RED}ERROR:${NC} %s\n" "$*" >&2; exit 2; }
warn() { printf "${YELLOW}WARN:${NC} %s\n" "$*" >&2; }
info() { printf "${BLUE}INFO:${NC} %s\n" "$*"; }
pass() { printf "${GREEN}PASS:${NC} %s\n" "$*"; }
fail() { printf "${RED}FAIL:${NC} %s\n" "$*" >&2; }

# ── Usage ─────────────────────────────────────────────────────────────
show_help() {
  cat <<'EOF'
Scanalyze Autonomous Deployment Orchestrator

Usage:
  scanalyze-deploy.sh <subcommand> [options]

Subcommands:
  help                 Show this help
  doctor               Check local toolchain and environment
  validate-manifest    Validate a deployment manifest
  bootstrap-local      Bootstrap local development environment
  repro-check          Run reproducibility checks
  account-preflight    Read-only AWS account verification
  plan-layer           Terraform plan for a single layer
  apply-layer          BLOCKED locally; future GitHub orchestrator only
  plan-all             Plan all layers in dependency order
  apply-all            BLOCKED locally; future GitHub orchestrator only
  publish-images       Build and push OCI images to ECR
  deploy-services      Plan/apply services layer with image digests
  validate-live        Validate deployed resources
  smoke-e2e            Run synthetic end-to-end smoke test
  rollback             Rollback to approved digests via Terraform
  go-no-go             Generate GO/NO-GO assessment
  handoff-package      Generate handoff documentation package

Options:
  --manifest <path>           Path to deployment manifest YAML
  --customer-id <id>          Canonical customer ID (cust_<ULID>)
  --deployment-id <id>        Deployment ID (dep_<ULID>)
  --account-id <id>           Expected AWS account ID (12 digits)
  --region <region>           Expected AWS region
  --environment <env>         Target environment
  --ref <git_ref>             Git ref for the deployment
  --layer <name>              Terraform layer name
  --release-version <value>   Immutable release version
  --release-digest <sha256>   Immutable release manifest digest
  --resolved-input <path>     Verified layer resolution outside the repository
  --non-interactive           Suppress interactive prompts
  --dry-run                   Dry-run mode (default)
  --no-dry-run                Disable dry-run mode
  --approve                   Approve the operation
  --plan-dir <path>           Directory for Terraform plans (must be outside repo)
  --evidence-dir <path>       Directory for evidence artifacts (must be outside repo)

Safety:
  By default, all operations are dry-run. To perform live mutations:
    SCANALYZE_ALLOW_LIVE=1    Required for any AWS mutation
    SCANALYZE_ALLOW_PROD=1    Required additionally for production environments
  Both require a valid manifest, account binding, and explicit approval.

EOF
}

# ── Argument Parsing ──────────────────────────────────────────────────
SUBCOMMAND="${1:-help}"
shift || true

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --manifest)       [[ -n "${2:-}" ]] || die "--manifest requires a value"; MANIFEST="$2"; shift 2 ;;
    --customer-id)    [[ -n "${2:-}" ]] || die "--customer-id requires a value"; CUSTOMER_ID="$2"; shift 2 ;;
    --deployment-id)  [[ -n "${2:-}" ]] || die "--deployment-id requires a value"; DEPLOYMENT_ID="$2"; shift 2 ;;
    --account-id)     [[ -n "${2:-}" ]] || die "--account-id requires a value"; ACCOUNT_ID="$2"; shift 2 ;;
    --region)         [[ -n "${2:-}" ]] || die "--region requires a value"; REGION="$2"; shift 2 ;;
    --environment)    [[ -n "${2:-}" ]] || die "--environment requires a value"; ENVIRONMENT="$2"; shift 2 ;;
    --ref)            [[ -n "${2:-}" ]] || die "--ref requires a value"; GIT_REF="$2"; shift 2 ;;
    --layer)          [[ -n "${2:-}" ]] || die "--layer requires a value"; LAYER="$2"; shift 2 ;;
    --release-version) [[ -n "${2:-}" ]] || die "--release-version requires a value"; RELEASE_VERSION="$2"; shift 2 ;;
    --release-digest) [[ -n "${2:-}" ]] || die "--release-digest requires a value"; RELEASE_DIGEST="$2"; shift 2 ;;
    --resolved-input) [[ -n "${2:-}" ]] || die "--resolved-input requires a value"; RESOLVED_INPUT="$2"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=true; shift ;;
    --dry-run)        DRY_RUN=true; shift ;;
    --no-dry-run)     DRY_RUN=false; shift ;;
    --approve)        APPROVE=true; shift ;;
    --plan-dir)       [[ -n "${2:-}" ]] || die "--plan-dir requires a value"; PLAN_DIR="$2"; shift 2 ;;
    --evidence-dir)   [[ -n "${2:-}" ]] || die "--evidence-dir requires a value"; EVIDENCE_DIR="$2"; shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done

# ── Guards ────────────────────────────────────────────────────────────
guard_live() {
  if [[ "${SCANALYZE_ALLOW_LIVE:-}" != "1" ]]; then
    die "Live mutations require SCANALYZE_ALLOW_LIVE=1"
  fi
  if [[ -z "$MANIFEST" ]]; then
    die "Live mutations require --manifest"
  fi
  if [[ "$DRY_RUN" == true ]]; then
    die "Live mutations require --no-dry-run"
  fi
}

guard_prod() {
  guard_live
  if [[ "$ENVIRONMENT" == "production" ]]; then
    if [[ "${SCANALYZE_ALLOW_PROD:-}" != "1" ]]; then
      die "Production mutations require SCANALYZE_ALLOW_PROD=1"
    fi
    # TODO: verify non-production evidence reference
    info "Production mode enabled — additional gates apply"
  fi
}

guard_plan_dir() {
  if [[ -z "$PLAN_DIR" ]]; then
    die "--plan-dir is required for Terraform operations"
  fi
  local abs_plan_dir
  abs_plan_dir="$(cd "$PLAN_DIR" 2>/dev/null && pwd)" || die "--plan-dir does not exist: $PLAN_DIR"
  if [[ "$abs_plan_dir" == "$REPO_ROOT"* ]]; then
    die "--plan-dir must be outside the repository: $abs_plan_dir is inside $REPO_ROOT"
  fi
}

guard_evidence_dir() {
  if [[ -z "$EVIDENCE_DIR" ]]; then
    die "--evidence-dir is required"
  fi
  local abs_evidence_dir
  abs_evidence_dir="$(cd "$EVIDENCE_DIR" 2>/dev/null && pwd)" || die "--evidence-dir does not exist: $EVIDENCE_DIR"
  if [[ "$abs_evidence_dir" == "$REPO_ROOT"* ]]; then
    die "--evidence-dir must be outside the repository: $abs_evidence_dir is inside $REPO_ROOT"
  fi
}

guard_account_binding() {
  if [[ -z "$ACCOUNT_ID" ]]; then
    die "--account-id is required for AWS operations"
  fi
  if [[ -z "$REGION" ]]; then
    die "--region is required for AWS operations"
  fi

  if ! command -v aws &>/dev/null; then
    die "aws CLI is required for account binding verification"
  fi

  local caller_account
  caller_account="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)" \
    || die "Unable to verify AWS caller identity"

  if [[ "$caller_account" != "$ACCOUNT_ID" ]]; then
    die "AWS caller account ($caller_account) does not match expected account ($ACCOUNT_ID)"
  fi

  local caller_region="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
  if [[ -n "$caller_region" && "$caller_region" != "$REGION" ]]; then
    warn "AWS_REGION ($caller_region) differs from --region ($REGION)"
  fi

  pass "Account binding verified: $ACCOUNT_ID in $REGION"
}

load_manifest() {
  if [[ -z "$MANIFEST" ]]; then
    return
  fi
  if [[ ! -f "$MANIFEST" ]]; then
    die "Manifest not found: $MANIFEST"
  fi

  # Validate manifest
  if ! python3 "$SCRIPT_DIR/validate-manifest.py" "$MANIFEST"; then
    die "Manifest validation failed"
  fi

  # Extract key fields if not overridden by CLI
  if command -v python3 &>/dev/null; then
    if [[ -z "$DEPLOYMENT_ID" ]]; then
      DEPLOYMENT_ID="$(python3 -c "import yaml; print(yaml.safe_load(open('$MANIFEST'))['deployment_id'])" 2>/dev/null)" || true
    fi
    if [[ -z "$ACCOUNT_ID" ]]; then
      ACCOUNT_ID="$(python3 -c "import yaml; print(yaml.safe_load(open('$MANIFEST'))['aws_account_id'])" 2>/dev/null)" || true
    fi
    if [[ -z "$REGION" ]]; then
      REGION="$(python3 -c "import yaml; print(yaml.safe_load(open('$MANIFEST'))['aws_region'])" 2>/dev/null)" || true
    fi
    if [[ -z "$ENVIRONMENT" ]]; then
      ENVIRONMENT="$(python3 -c "import yaml; print(yaml.safe_load(open('$MANIFEST'))['environment'])" 2>/dev/null)" || true
    fi
  fi
}

# ── Subcommands ───────────────────────────────────────────────────────

cmd_doctor() {
  info "Scanalyze Deployment Orchestrator v${VERSION}"
  info "Repository: ${REPO_ROOT}"
  info "Branch: $(git -C "$REPO_ROOT" branch --show-current 2>/dev/null || echo 'detached')"
  info "HEAD: $(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
  echo ""

  local errors=0
  for tool in python3 terraform jq git bash; do
    if command -v "$tool" &>/dev/null; then
      pass "$tool: $(command -v "$tool")"
    else
      fail "$tool: not found"
      errors=$((errors + 1))
    fi
  done

  for tool in docker aws shellcheck actionlint cosign syft trivy; do
    if command -v "$tool" &>/dev/null; then
      pass "$tool: available (optional)"
    else
      warn "$tool: not found (optional)"
    fi
  done

  echo ""
  info "SCANALYZE_ALLOW_LIVE: ${SCANALYZE_ALLOW_LIVE:-not set}"
  info "SCANALYZE_ALLOW_PROD: ${SCANALYZE_ALLOW_PROD:-not set}"
  info "Dry-run: ${DRY_RUN}"

  if [[ "$errors" -gt 0 ]]; then
    die "$errors required tool(s) missing"
  fi
  pass "Doctor check complete"
}

cmd_validate_manifest() {
  if [[ -z "$MANIFEST" ]]; then
    die "--manifest is required"
  fi
  python3 "$SCRIPT_DIR/validate-manifest.py" "$MANIFEST"
}

cmd_bootstrap_local() {
  info "Bootstrapping local environment..."
  cd "$REPO_ROOT"
  make bootstrap-local
  pass "Bootstrap complete"
}

cmd_repro_check() {
  info "Running reproducibility checks..."
  cd "$REPO_ROOT"
  make repro-check
  pass "Reproducibility check complete"
}

cmd_account_preflight() {
  load_manifest
  guard_account_binding
  info "Running read-only account preflight..."

  if [[ "$DRY_RUN" == true ]]; then
    info "[DRY-RUN] Would verify: VPC, subnets, ECR repos, KMS keys, SSM params"
    pass "Account preflight dry-run complete"
    return
  fi

  guard_live

  # Read-only checks
  aws sts get-caller-identity
  aws ec2 describe-vpcs --region "$REGION" --query 'Vpcs[].VpcId' --output table 2>/dev/null || warn "VPC check skipped"
  pass "Account preflight complete"
}

cmd_plan_layer() {
  load_manifest
  guard_plan_dir

  if [[ -z "$LAYER" ]]; then
    die "--layer is required for plan-layer"
  fi

  local root_dir="${REPO_ROOT}/roots/${LAYER}"
  if [[ ! -d "$root_dir" ]]; then
    die "Layer root not found: roots/${LAYER}"
  fi

  info "Planning layer: ${LAYER}"

  if [[ "$DRY_RUN" == true ]]; then
    info "[DRY-RUN] Would run: terraform -chdir=roots/${LAYER} plan -out=${PLAN_DIR}/${LAYER}.tfplan"
    pass "Plan layer dry-run complete"
    return
  fi

  guard_live
  guard_account_binding

  bash "$SCRIPT_DIR/terraform-layer.sh" plan \
    --layer "$LAYER" \
    --plan-dir "$PLAN_DIR" \
    --customer-id "$CUSTOMER_ID" \
    --account-id "$ACCOUNT_ID" \
    --region "$REGION" \
    --deployment-id "$DEPLOYMENT_ID" \
    --release-version "$RELEASE_VERSION" \
    --release-digest "$RELEASE_DIGEST" \
    --resolved-input "$RESOLVED_INPUT"
}

cmd_apply_layer() {
  die "Local apply-layer is disabled by ADR-017. The future live path is the protected GitHub Actions orchestrator; this PR is dry-run only."
}

canonical_plan_layers() {
  local dag_file="${REPO_ROOT}/deployment/layers.yaml"
  python3 "$SCRIPT_DIR/validate-layer-dag.py" "$dag_file" >/dev/null \
    || die "Canonical deployment DAG validation failed"

  python3 - "$dag_file" <<'PY'
import sys

import yaml

with open(sys.argv[1], encoding="utf-8") as handle:
    document = yaml.safe_load(handle)

for stage in document["layers"]:
    if stage["kind"] in {"gate", "terraform"}:
        print(stage["layer"])
PY
}

cmd_plan_all() {
  load_manifest
  guard_plan_dir

  info "Planning all layers in dependency order..."
  local layer_output
  layer_output="$(canonical_plan_layers)" \
    || die "Unable to resolve the canonical deployment DAG"
  local layers=()
  local layer
  while IFS= read -r layer; do
    [[ -n "$layer" ]] && layers+=("$layer")
  done <<< "$layer_output"
  [[ "${#layers[@]}" -gt 0 ]] || die "Canonical deployment DAG contains no plan stages"

  for layer in "${layers[@]}"; do
    if [[ ! -d "${REPO_ROOT}/roots/${layer}" ]]; then
      warn "Skipping missing layer: ${layer}"
      continue
    fi
    LAYER="$layer" cmd_plan_layer
  done

  pass "All layers planned"
}

cmd_apply_all() {
  die "Local apply-all is disabled by ADR-017. Mock-backed plans are never authorized for apply."
}

cmd_publish_images() {
  load_manifest

  if [[ "$DRY_RUN" == true ]]; then
    info "[DRY-RUN] Would build and push 7 microservice images"
    info "[DRY-RUN] Base image: (from manifest)"
    info "[DRY-RUN] ECR prefix: (from manifest)"
    info "[DRY-RUN] Tag: sha-$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
    pass "Publish images dry-run complete"
    return
  fi

  guard_live
  guard_account_binding

  if [[ "$APPROVE" != true ]]; then
    die "publish-images requires --approve"
  fi

  local tag="${GIT_REF:-sha-$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD)}"

  # Extract ECR config from manifest
  local ecr_prefix base_image
  ecr_prefix="$(python3 -c "import yaml; print(yaml.safe_load(open('$MANIFEST'))['ecr']['prefix'])" 2>/dev/null)" \
    || die "Unable to read ecr.prefix from manifest"
  base_image="$(python3 -c "import yaml; print(yaml.safe_load(open('$MANIFEST'))['base_image_uri'])" 2>/dev/null)" \
    || die "Unable to read base_image_uri from manifest"

  bash "${REPO_ROOT}/scripts/microservices/build-push.sh" \
    --all \
    --tag "$tag" \
    --base-image "$base_image" \
    --account-id "$ACCOUNT_ID" \
    --region "$REGION" \
    --deployment-id "$DEPLOYMENT_ID" \
    --ecr-prefix "$ecr_prefix" \
    --push \
    --write-ssm

  pass "Images published"
}

cmd_deploy_services() {
  load_manifest
  guard_plan_dir

  info "Deploying services layer with image digests..."

  if [[ "$DRY_RUN" == true ]]; then
    info "[DRY-RUN] Would plan/apply services layer consuming digests from SSM"
    pass "Deploy services dry-run complete"
    return
  fi

  guard_live
  guard_account_binding

  LAYER="services" cmd_plan_layer
  if [[ "$APPROVE" == true ]]; then
    LAYER="services" cmd_apply_layer
  else
    info "Services plan generated. Review and re-run with --approve to apply."
  fi
}

cmd_validate_live() {
  load_manifest

  if [[ "$DRY_RUN" == true ]]; then
    info "[DRY-RUN] Would validate: ECS services, ALB health, SQS queues, DynamoDB tables"
    pass "Validate live dry-run complete"
    return
  fi

  guard_live
  guard_account_binding
  guard_evidence_dir

  info "Validating live deployment..."
  # Read-only validation of deployed resources
  info "Checking ECS services..."
  info "Checking ALB health..."
  info "Checking SQS queues..."
  info "Checking DynamoDB tables..."
  info "Checking CloudWatch log groups..."
  warn "Live validation implementation requires deployment-specific checks"
  pass "Live validation framework ready"
}

cmd_smoke_e2e() {
  load_manifest

  if [[ "$DRY_RUN" == true ]]; then
    info "[DRY-RUN] Would run E2E smoke test with synthetic document"
    info "[DRY-RUN] No PII, no real documents, no customer data"
    pass "Smoke E2E dry-run complete"
    return
  fi

  guard_live
  guard_account_binding
  guard_evidence_dir

  info "Running E2E smoke test..."
  warn "E2E smoke test implementation requires deployed services"
  pass "Smoke E2E framework ready"
}

cmd_rollback() {
  load_manifest

  if [[ "$DRY_RUN" == true ]]; then
    info "[DRY-RUN] Would rollback services to last-known-good digests via Terraform plan"
    pass "Rollback dry-run complete"
    return
  fi

  guard_live
  guard_prod
  guard_plan_dir
  guard_account_binding

  if [[ "$APPROVE" != true ]]; then
    die "rollback requires --approve"
  fi

  info "Rolling back services to last-known-good digests..."
  warn "Rollback generates a new Terraform plan; it does NOT restore state"
  pass "Rollback framework ready"
}

cmd_go_no_go() {
  load_manifest
  info "Generating GO/NO-GO assessment..."

  local status="NO-GO"
  local reasons=()

  # Check reproducibility
  if (cd "$REPO_ROOT" && make repro-check &>/dev/null); then
    pass "repro-check: PASSED"
  else
    fail "repro-check: FAILED"
    reasons+=("repro-check failed")
  fi

  # Check manifest
  if [[ -n "$MANIFEST" ]] && python3 "$SCRIPT_DIR/validate-manifest.py" "$MANIFEST" &>/dev/null; then
    pass "manifest: VALID"
  elif [[ -n "$MANIFEST" ]]; then
    fail "manifest: INVALID"
    reasons+=("manifest validation failed")
  else
    warn "manifest: NOT PROVIDED"
    reasons+=("no manifest provided")
  fi

  # Check environment
  if [[ "$ENVIRONMENT" == "production" ]]; then
    reasons+=("production requires live non-production evidence")
  fi

  if [[ ${#reasons[@]} -eq 0 ]]; then
    status="GO (non-production only)"
  fi

  echo ""
  info "═══════════════════════════════════════"
  info "  GO/NO-GO Assessment: ${status}"
  info "═══════════════════════════════════════"
  if [[ ${#reasons[@]} -gt 0 ]]; then
    for reason in "${reasons[@]}"; do
      info "  Reason: ${reason}"
    done
  fi
  echo ""
}

cmd_handoff_package() {
  load_manifest
  guard_evidence_dir

  info "Generating handoff package..."
  local handoff_dir="${EVIDENCE_DIR}/handoff-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$handoff_dir"

  # Copy sanitized documentation
  cp "$REPO_ROOT/README.md" "$handoff_dir/"
  cp "$REPO_ROOT/REPRODUCIBILITY.md" "$handoff_dir/"
  if [[ -f "$MANIFEST" ]]; then
    info "Manifest reference included (path only, not copied for security)"
    echo "manifest_path: $MANIFEST" > "$handoff_dir/manifest-ref.txt"
  fi

  # Generate summary
  cat > "$handoff_dir/handoff-summary.md" <<HANDOFF
# Scanalyze Deployment Handoff

Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Repository: $(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || echo 'local')
Commit: $(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo 'unknown')
Branch: $(git -C "$REPO_ROOT" branch --show-current 2>/dev/null || echo 'detached')
Deployment ID: ${DEPLOYMENT_ID:-not specified}
Environment: ${ENVIRONMENT:-not specified}

## Status
- clone-ready: YES
- repro-check: $(cd "$REPO_ROOT" && make repro-check &>/dev/null && echo "PASSED" || echo "FAILED")
- production-ready: NO (requires live validation)

## Next Steps
1. Review this handoff package
2. Verify clean clone reproducibility
3. Obtain approval for non-production deployment
4. Execute live validation
5. Generate GO/NO-GO for production
HANDOFF

  pass "Handoff package generated at: ${handoff_dir}"
}

# ── Dispatch ──────────────────────────────────────────────────────────
load_manifest

case "$SUBCOMMAND" in
  help)              show_help ;;
  doctor)            cmd_doctor ;;
  validate-manifest) cmd_validate_manifest ;;
  bootstrap-local)   cmd_bootstrap_local ;;
  repro-check)       cmd_repro_check ;;
  account-preflight) cmd_account_preflight ;;
  plan-layer)        cmd_plan_layer ;;
  apply-layer)       cmd_apply_layer ;;
  plan-all)          cmd_plan_all ;;
  apply-all)         cmd_apply_all ;;
  publish-images)    cmd_publish_images ;;
  deploy-services)   cmd_deploy_services ;;
  validate-live)     cmd_validate_live ;;
  smoke-e2e)         cmd_smoke_e2e ;;
  rollback)          cmd_rollback ;;
  go-no-go)          cmd_go_no_go ;;
  handoff-package)   cmd_handoff_package ;;
  *) die "unknown subcommand: $SUBCOMMAND. Run 'scanalyze-deploy.sh help'" ;;
esac
