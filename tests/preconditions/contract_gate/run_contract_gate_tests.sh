#!/usr/bin/env bash
# Contract fail-closed HCL harness test runner
# Tests that invalid contract scenarios fail terraform plan via preconditions
#
# Usage: ./run_contract_gate_tests.sh
# Requires: terraform >= 1.5.0

set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "$0")" && pwd)"
FIXTURES_DIR="${HARNESS_DIR}/fixtures"
PASS=0
FAIL=0
ERRORS=""

# Check terraform availability
if ! command -v terraform &>/dev/null; then
    echo "BLOCKED_TOOLING: terraform not found"
    exit 2
fi

TF_VERSION=$(terraform version -json 2>/dev/null | jq -r '.terraform_version' 2>/dev/null || terraform version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
echo "=== Contract Gate HCL Harness ==="
echo "Terraform version: ${TF_VERSION}"
echo "Harness: ${HARNESS_DIR}"
echo ""

# Initialize once
cd "${HARNESS_DIR}"
terraform init -backend=false -input=false >/dev/null 2>&1

# Test function
run_test() {
    local fixture_name="$1"
    local expect_pass="$2"  # "pass" or "fail"
    local fixture_file="${FIXTURES_DIR}/${fixture_name}.tfvars"

    if [[ ! -f "${fixture_file}" ]]; then
        echo "  SKIP: ${fixture_name} — fixture not found"
        return
    fi

    local plan_output
    local plan_exit
    plan_output=$(terraform plan -var-file="${fixture_file}" -input=false -no-color 2>&1) || true
    plan_exit=$?

    # Check if precondition error occurred
    if echo "${plan_output}" | grep -q "FAIL_CLOSED"; then
        plan_exit=1
    fi

    if [[ "${expect_pass}" == "pass" ]]; then
        if [[ ${plan_exit} -eq 0 ]] && ! echo "${plan_output}" | grep -q "FAIL_CLOSED"; then
            echo "  PASS: ${fixture_name} → plan succeeded (expected)"
            PASS=$((PASS + 1))
        else
            echo "  FAIL: ${fixture_name} → plan failed (expected pass)"
            ERRORS="${ERRORS}\n  ${fixture_name}: expected pass but got fail"
            FAIL=$((FAIL + 1))
        fi
    else
        if echo "${plan_output}" | grep -q "FAIL_CLOSED"; then
            echo "  EXPECTED FAIL: ${fixture_name} → precondition blocked (correct)"
            PASS=$((PASS + 1))
        else
            echo "  FAIL: ${fixture_name} → plan did not fail (expected precondition failure)"
            ERRORS="${ERRORS}\n  ${fixture_name}: expected fail but got pass"
            FAIL=$((FAIL + 1))
        fi
    fi
}

echo "=== Running contract gate tests ==="
echo ""

# Valid scenario should pass
run_test "valid" "pass"

# All invalid scenarios should fail
run_test "wrong-deployment-id" "fail"
run_test "wrong-account-id" "fail"
run_test "wrong-region" "fail"
run_test "unsupported-schema" "fail"
run_test "tampered-digest" "fail"
run_test "replay-old-release" "fail"

echo ""
echo "=== Results ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"

if [[ ${FAIL} -gt 0 ]]; then
    echo -e "\nErrors:${ERRORS}"
    exit 1
fi

echo ""
echo "All contract gate tests passed."
exit 0
