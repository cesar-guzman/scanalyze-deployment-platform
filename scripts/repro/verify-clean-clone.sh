#!/usr/bin/env bash
# verify-clean-clone.sh — Verify Scanalyze reproducibility from a clean clone
#
# Usage:
#   scripts/repro/verify-clean-clone.sh --ref HEAD
#   scripts/repro/verify-clean-clone.sh --ref v1.0.0
#   scripts/repro/verify-clean-clone.sh --ref feat/monorepo-microservices
#
# This script clones the repository into a temporary directory and runs
# bootstrap + validation to prove reproducibility. It never touches AWS.

set -euo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

REF="HEAD"
REMOTE=""
KEEP_CLONE=false

usage() {
  cat <<'EOF'
Verify Scanalyze reproducibility from a clean git clone.

Usage:
  verify-clean-clone.sh [--ref <ref>] [--remote <url>] [--keep]

Options:
  --ref <ref>       Git ref to check out (default: HEAD)
  --remote <url>    Remote URL to clone (default: origin from current repo)
  --keep            Keep the temporary clone directory after verification
  -h, --help        Show this help

The script:
  1. Clones the repository into a temporary directory
  2. Checks out the specified ref
  3. Runs make bootstrap-local
  4. Runs make repro-check
  5. Verifies 7 services exist
  6. Verifies schemas exist
  7. Verifies no forbidden artifacts
  8. Cleans up the temporary directory (unless --keep)

Exit codes:
  0  All checks passed
  1  One or more checks failed
  2  Usage error
EOF
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
log() { printf '[clone-check] %s\n' "$*"; }

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --ref)    [[ -n "${2:-}" ]] || die "--ref requires a value"; REF="$2"; shift 2 ;;
    --remote) [[ -n "${2:-}" ]] || die "--remote requires a value"; REMOTE="$2"; shift 2 ;;
    --keep)   KEEP_CLONE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

# Resolve remote
if [[ -z "$REMOTE" ]]; then
  REMOTE="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null)" \
    || die "unable to resolve origin remote; pass --remote explicitly"
fi

# Resolve ref to a commit SHA if it is HEAD
RESOLVED_REF="$REF"
if [[ "$REF" == "HEAD" ]]; then
  RESOLVED_REF="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)" \
    || die "unable to resolve HEAD"
fi

# Create temporary directory
CLONE_DIR="$(mktemp -d)"
if [[ "$KEEP_CLONE" == false ]]; then
  trap 'rm -rf "$CLONE_DIR"' EXIT HUP INT TERM
fi

log "Cloning ${REMOTE} into ${CLONE_DIR}"
git clone --quiet "$REMOTE" "$CLONE_DIR/repo" 2>/dev/null \
  || git clone --quiet "$REPO_ROOT" "$CLONE_DIR/repo"

cd "$CLONE_DIR/repo"

log "Checking out ref: ${RESOLVED_REF}"
git checkout --quiet "$RESOLVED_REF" 2>/dev/null \
  || git checkout --quiet "$REF" 2>/dev/null \
  || die "unable to check out ref: $REF"

ERRORS=0

# --- Check 1: Seven services exist ---
log "Checking 7 microservices..."
SERVICES=(ingest-api ocr-worker postprocess-worker classifier-worker bank-worker personal-worker gov-worker)
for svc in "${SERVICES[@]}"; do
  svc_dir="backend/workers/scanalyze-${svc}"
  if [[ ! -d "$svc_dir" ]]; then
    log "FAIL: missing service directory: ${svc_dir}"
    ERRORS=$((ERRORS + 1))
  elif [[ ! -f "${svc_dir}/Dockerfile" ]]; then
    log "FAIL: missing Dockerfile: ${svc_dir}/Dockerfile"
    ERRORS=$((ERRORS + 1))
  else
    log "  OK: ${svc}"
  fi
done

# --- Check 2: Key files exist ---
log "Checking key files..."
KEY_FILES=(
  "Makefile"
  "README.md"
  "REPRODUCIBILITY.md"
  ".gitignore"
  "pyproject.toml"
  "schemas/deployment-manifest.schema.json"
  "examples/deployments/synthetic-nonprod.yaml"
  "scripts/deployment/scanalyze-deploy.sh"
  "scripts/deployment/validate-manifest.py"
  "scripts/repro/verify-clean-clone.sh"
  "playbooks/enterprise-client-deployment.md"
)
for f in "${KEY_FILES[@]}"; do
  if [[ ! -f "$f" ]]; then
    log "FAIL: missing file: ${f}"
    ERRORS=$((ERRORS + 1))
  fi
done

# --- Check 3: No forbidden artifacts ---
log "Checking for forbidden artifacts..."
FORBIDDEN_PATTERNS=(
  "*.tfstate"
  "*.tfstate.*"
  "*.tfplan"
  ".env"
  "*.pem"
  "*.key"
  "~\$*.docx"
)
for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
  found=$(find . -name "$pattern" -not -path '*/.git/*' -not -path '*/.venv/*' -not -path '*/.work/*' 2>/dev/null | head -1)
  if [[ -n "$found" ]]; then
    log "FAIL: forbidden artifact found: ${found}"
    ERRORS=$((ERRORS + 1))
  fi
done

# --- Check 4: Bootstrap local ---
log "Running bootstrap-local..."
if make bootstrap-local 2>&1; then
  log "  bootstrap-local: PASSED"
else
  log "FAIL: bootstrap-local failed"
  ERRORS=$((ERRORS + 1))
fi

# --- Check 5: Repro check ---
log "Running repro-check..."
if make repro-check 2>&1; then
  log "  repro-check: PASSED"
else
  log "FAIL: repro-check failed"
  ERRORS=$((ERRORS + 1))
fi

# --- Summary ---
echo ""
if [[ "$ERRORS" -gt 0 ]]; then
  log "FAILED: ${ERRORS} error(s) in clean clone verification"
  if [[ "$KEEP_CLONE" == true ]]; then
    log "Clone preserved at: ${CLONE_DIR}/repo"
  fi
  exit 1
else
  log "PASSED: Clean clone verification complete"
  log "  Remote:  ${REMOTE}"
  log "  Ref:     ${REF}"
  log "  Commit:  $(git rev-parse --short HEAD)"
  if [[ "$KEEP_CLONE" == true ]]; then
    log "Clone preserved at: ${CLONE_DIR}/repo"
  fi
  exit 0
fi
