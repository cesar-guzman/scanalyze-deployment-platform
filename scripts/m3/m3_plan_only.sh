#!/usr/bin/env bash
# ============================================================================
# M3 Plan-Only Wrapper — Fail-Closed Speculative Plan
# ============================================================================
#
# This script runs a single speculative terraform plan for one root.
# It enforces ALL M3 safety constraints and refuses to execute if any
# constraint is violated.
#
# Usage:
#   M3_APPROVED_ROOT=global \
#   M3_APPROVED_ACCOUNT_ID=000000000000 \
#   M3_APPROVED_MODE=speculative-plan \
#     ./scripts/m3/m3_plan_only.sh
#
# Required environment variables:
#   M3_APPROVED_ROOT       — root name (must be in APPROVED_ROOTS list)
#   M3_APPROVED_ACCOUNT_ID — approved sandbox account ID
#   M3_APPROVED_MODE       — must be "speculative-plan"
#
# Optional:
#   M3_TFVARS_FILE         — path to tfvars (default: environments/m3-sandbox.synthetic.tfvars.example)
#
# Exit codes:
#   0 — plan completed successfully
#   1 — safety constraint violated (fail-closed)
#   2 — terraform plan failed (declaration error)
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# --- Approved roots (M3 scope) ---
APPROVED_ROOTS=(
  account-ready-gate
  global
  network
  platform
  data-foundation
  cicd
  identity-control-plane
  services
  edge-identity
  edge
  addons
)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

fail() {
  echo -e "${RED}FAIL: $1${NC}" >&2
  exit 1
}

warn() {
  echo -e "${YELLOW}WARN: $1${NC}" >&2
}

pass() {
  echo -e "${GREEN}PASS: $1${NC}"
}

# ============================================================================
# GATE 1: Required environment variables
# ============================================================================

echo "=== M3 Plan-Only Wrapper ==="
echo ""

[ -z "${M3_APPROVED_ROOT:-}" ] && fail "M3_APPROVED_ROOT not set. Set to approved root name."
[ -z "${M3_APPROVED_ACCOUNT_ID:-}" ] && fail "M3_APPROVED_ACCOUNT_ID not set. Set to approved sandbox account ID."
[ -z "${M3_APPROVED_MODE:-}" ] && fail "M3_APPROVED_MODE not set. Must be 'speculative-plan'."

[ "$M3_APPROVED_MODE" != "speculative-plan" ] && fail "M3_APPROVED_MODE must be 'speculative-plan', got '$M3_APPROVED_MODE'."

pass "Required environment variables set"

# ============================================================================
# GATE 2: Root is in approved list
# ============================================================================

ROOT_APPROVED=false
for r in "${APPROVED_ROOTS[@]}"; do
  if [ "$r" = "$M3_APPROVED_ROOT" ]; then
    ROOT_APPROVED=true
    break
  fi
done

[ "$ROOT_APPROVED" = false ] && fail "Root '$M3_APPROVED_ROOT' is not in approved roots list."
pass "Root '$M3_APPROVED_ROOT' is approved"

ROOT_DIR="$REPO_ROOT/roots/$M3_APPROVED_ROOT"
[ ! -d "$ROOT_DIR" ] && fail "Root directory does not exist: $ROOT_DIR"

# ============================================================================
# GATE 3: tfvars file validation
# ============================================================================

TFVARS_FILE="${M3_TFVARS_FILE:-$REPO_ROOT/environments/m3-sandbox.synthetic.tfvars.example}"

[ ! -f "$TFVARS_FILE" ] && fail "tfvars file not found: $TFVARS_FILE"

# Reject non-synthetic tfvars (must contain 'synthetic' in name or path)
if [[ "$TFVARS_FILE" != *synthetic* ]] && [[ "$TFVARS_FILE" != *example* ]]; then
  fail "tfvars file must contain 'synthetic' or 'example' in name. Got: $TFVARS_FILE"
fi

# Reject .auto.tfvars
if [[ "$TFVARS_FILE" == *.auto.tfvars* ]]; then
  fail ".auto.tfvars files are not allowed for M3 speculative plan."
fi

pass "tfvars file validated: $(basename "$TFVARS_FILE")"

# ============================================================================
# GATE 4: No static long-lived AWS credentials
# ============================================================================

if [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -z "${AWS_SESSION_TOKEN:-}" ]; then
  fail "Static long-lived AWS_ACCESS_KEY_ID detected without session token. Use SSO/STS sessions only."
fi

pass "No static long-lived credentials detected"

# ============================================================================
# GATE 5: Block forbidden terraform commands via process check
# ============================================================================

# This wrapper ONLY runs 'terraform plan'. Verify no other terraform
# processes are running with write commands.
FORBIDDEN_COMMANDS=(
  "terraform apply"
  "terraform destroy"
  "terraform import"
  "terraform state"
)

for cmd in "${FORBIDDEN_COMMANDS[@]}"; do
  if pgrep -f "$cmd" > /dev/null 2>&1; then
    fail "Forbidden terraform command detected running: '$cmd'"
  fi
done

pass "No forbidden terraform commands running"

# ============================================================================
# GATE 6: Verify no remote backend configured
# ============================================================================

if [ -f "$ROOT_DIR/backend.tf" ]; then
  fail "backend.tf exists in $ROOT_DIR — remote backend not allowed for M3."
fi

# Check for backend blocks in all .tf files
if grep -rl 'backend "s3"' "$ROOT_DIR"/*.tf 2>/dev/null | grep -v 'backend.example' | grep -v '#' > /dev/null 2>&1; then
  fail "Active S3 backend configuration found in $ROOT_DIR. Only backend.example.hcl is allowed."
fi

pass "No remote backend configured"

# ============================================================================
# GATE 7: Construct plan command (speculative, no -out)
# ============================================================================

# Compute relative path from root dir to tfvars
TFVARS_RELPATH="$(python3 -c "import os; print(os.path.relpath('$TFVARS_FILE', '$ROOT_DIR'))")"

PLAN_CMD=(
  terraform
  -chdir="$ROOT_DIR"
  plan
  -no-color
  -input=false
  -refresh=false
  -var-file="$TFVARS_RELPATH"
)

# ============================================================================
# GATE 8: Verify plan command does NOT contain forbidden flags
# ============================================================================

PLAN_CMD_STR="${PLAN_CMD[*]}"

FORBIDDEN_FLAGS=(
  "-out"
  "-out="
  "-destroy"
  "-target"
  "-target="
  "-replace"
  "-replace="
  "-generate-config-out"
  "-refresh-only"
)

for flag in "${FORBIDDEN_FLAGS[@]}"; do
  if [[ "$PLAN_CMD_STR" == *"$flag"* ]]; then
    fail "Forbidden flag detected in plan command: '$flag'"
  fi
done

pass "Plan command has no forbidden flags"

# ============================================================================
# GATE 9: Create ephemeral work directory
# ============================================================================

WORK_DIR="$REPO_ROOT/.work/m3/plans"
mkdir -p "$WORK_DIR"

# Verify .work is gitignored
if ! grep -q '^\.work/' "$REPO_ROOT/.gitignore" 2>/dev/null; then
  fail ".work/ is not in .gitignore. Add it before running M3."
fi

pass ".work/ directory ready and gitignored"

# ============================================================================
# EXECUTE: Speculative plan
# ============================================================================

echo ""
echo "=== Executing Speculative Plan ==="
echo "  Root:      $M3_APPROVED_ROOT"
echo "  Account:   $M3_APPROVED_ACCOUNT_ID"
echo "  Mode:      $M3_APPROVED_MODE"
echo "  tfvars:    $(basename "$TFVARS_FILE")"
echo "  Refresh:   false"
echo "  Backend:   none (backend=false)"
echo "  -out:      NOT USED (speculative)"
echo ""

RAW_OUTPUT="$WORK_DIR/${M3_APPROVED_ROOT}-plan-raw.txt"

echo "Running: ${PLAN_CMD[*]}"
echo ""

# Init first (backend=false)
terraform -chdir="$ROOT_DIR" init -backend=false -input=false -no-color 2>&1 | tail -3

echo ""

# Execute plan, capture output
if "${PLAN_CMD[@]}" 2>&1 | tee "$RAW_OUTPUT"; then
  PLAN_EXIT=0
  pass "Plan completed for $M3_APPROVED_ROOT"
else
  PLAN_EXIT=$?
  warn "Plan exited with code $PLAN_EXIT for $M3_APPROVED_ROOT"
fi

# ============================================================================
# POST: Generate plan digest
# ============================================================================

if [ -f "$RAW_OUTPUT" ]; then
  DIGEST=$(shasum -a 256 "$RAW_OUTPUT" | cut -d' ' -f1)
  echo ""
  echo "=== Plan Artifact ==="
  echo "  Raw output: $RAW_OUTPUT (EPHEMERAL — do not commit)"
  echo "  Digest:     sha256:$DIGEST"
  echo "  Size:       $(wc -c < "$RAW_OUTPUT" | tr -d ' ') bytes"
  echo ""
  echo "Next step: run tooling/sanitize_plan_summary.py to produce committable summary."
fi

echo ""
echo "=== M3 Plan-Only Wrapper Complete ==="
echo "  Root:   $M3_APPROVED_ROOT"
echo "  Status: $([ $PLAN_EXIT -eq 0 ] && echo 'PLAN_SUCCEEDED' || echo 'PLAN_FAILED')"
echo "  Mode:   speculative (no -out, no state writes, no apply intent)"

exit $PLAN_EXIT
