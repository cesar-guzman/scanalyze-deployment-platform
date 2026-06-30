#!/bin/bash
# Layer Contract Matrix — Test Runner
#
# Generates tfvars from scenarios.yaml and runs terraform plan
# against the data-driven harness for each layer pair × scenario.
#
# Usage: ./run_matrix.sh [--layer-pair global_to_network] [--scenario valid]
#
# Prerequisites:
# - terraform available locally
# - No AWS provider required (pure local validation)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
ERRORS=0
TOTAL=0

# Known valid baseline values
VALID_DEPLOYMENT_ID="dep_01J5A7B2C3D4E5F6G7H8J9K0M1"
VALID_ACCOUNT_ID="123456789012"
VALID_REGION="us-east-1"
VALID_RELEASE="v2.1.0"
VALID_RELEASE_DIGEST="sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
VALID_CONTRACT_DIGEST="sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
VALID_SERIAL="5"

# Layer pairs: producer|consumer|scope
LAYER_PAIRS=(
  "global|network|regional"
  "network|platform|regional"
  "platform|data-foundation|regional"
  "data-foundation|services|regional"
  "services|edge-identity|regional"
  "edge-identity|edge|global"
  "edge|addons|regional"
)

run_scenario() {
  local producer="$1"
  local consumer="$2"
  local scope="$3"
  local scenario="$4"
  local expect="$5"

  TOTAL=$((TOTAL + 1))
  local fixture_dir="fixtures/${producer}_to_${consumer}"
  mkdir -p "$fixture_dir"

  # Start with valid baseline
  local dep_id="$VALID_DEPLOYMENT_ID"
  local acct_id="$VALID_ACCOUNT_ID"
  local region="$VALID_REGION"
  local release="$VALID_RELEASE"
  local rel_digest="$VALID_RELEASE_DIGEST"
  local expected_rel_digest="$VALID_RELEASE_DIGEST"
  local contract_digest="$VALID_CONTRACT_DIGEST"
  local expected_digest="$VALID_CONTRACT_DIGEST"
  local schema_ver="1"
  local serial="$VALID_SERIAL"
  local min_serial="1"
  local prod_release="$VALID_RELEASE"
  local state_key=""
  local contract_raw=''
  local allowed_keys='[]'

  # Set state key based on scope
  if [ "$scope" = "global" ]; then
    state_key="${VALID_DEPLOYMENT_ID}/${consumer}/terraform.tfstate"
  else
    state_key="${VALID_DEPLOYMENT_ID}/${VALID_REGION}/${consumer}/terraform.tfstate"
  fi

  # Apply scenario mutations
  case "$scenario" in
    valid) ;;
    wrong-deployment-id) dep_id="dep_WRONGWRONGWRONGWRONGWRONG" ;;
    wrong-account-id) acct_id="WRONG_ACCT" ;;
    wrong-region) region="eu-west-1" ;;
    wrong-producer-layer) producer="FAKE_LAYER" ;;
    wrong-schema-version) schema_ver="99" ;;
    tampered-digest) contract_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000" ;;
    stale-contract-version) serial="0"; min_serial="1" ;;
    stale-producer-release) prod_release="v0.0.0-stale" ;;
    stale-release-manifest-digest)
      rel_digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      ;;
    missing-expected-release-digest)
      expected_rel_digest=""
      ;;
    consumer-bypass-attempt) contract_digest="" ;;
    unknown-critical-field)
      contract_raw='{"deployment_id":"test","account_id":"123456789012","UNKNOWN_FIELD":"bad"}'
      allowed_keys='["deployment_id", "account_id"]'
      ;;
    unknown-non-allowlisted-field)
      contract_raw='{"deployment_id":"test","sneaky_extension":"not_allowed"}'
      allowed_keys='["deployment_id", "account_id"]'
      ;;
    allowed-extension-field)
      contract_raw='{"deployment_id":"test","account_id":"123456789012","approved_extension":"ok"}'
      allowed_keys='["deployment_id", "account_id", "approved_extension"]'
      ;;
    state-path-global-with-region)
      state_key="${VALID_DEPLOYMENT_ID}/${VALID_REGION}/${consumer}/terraform.tfstate"
      scope="global"
      ;;
    state-path-regional-without-region)
      state_key="${VALID_DEPLOYMENT_ID}/${consumer}/terraform.tfstate"
      scope="regional"
      ;;
    *) echo "  UNKNOWN scenario: $scenario"; ERRORS=$((ERRORS + 1)); return ;;
  esac

  # Write tfvars
  local tfvars="$fixture_dir/${scenario}.tfvars"
  cat > "$tfvars" << EOF
producer_layer                    = "${producer}"
consumer_layer                    = "${consumer}"
deployment_id                     = "${dep_id}"
account_id                        = "${acct_id}"
region                            = "${region}"
release_version                   = "${release}"
release_manifest_digest           = "${rel_digest}"
expected_release_manifest_digest  = "${expected_rel_digest}"
upstream_contract_digest          = "${contract_digest}"
expected_upstream_digest          = "${expected_digest}"
upstream_schema_version           = "${schema_ver}"
contract_serial                   = "${serial}"
expected_minimum_serial           = "${min_serial}"
producer_release_version          = "${prod_release}"
state_scope                       = "${scope}"
state_key                         = "${state_key}"
EOF
  # Append JSON fields with proper quoting (heredoc can't escape inner double-quotes)
  if [ -n "$contract_raw" ]; then
    printf 'contract_raw_json                 = "%s"\n' "$(echo "$contract_raw" | sed 's/"/\\"/g')" >> "$tfvars"
  else
    printf 'contract_raw_json                 = ""\n' >> "$tfvars"
  fi
  printf 'allowed_contract_keys             = %s\n' "$allowed_keys" >> "$tfvars"

  # Run terraform plan
  local result
  if terraform plan -var-file="$tfvars" -input=false -no-color 2>&1 | tail -5 > /tmp/tf_matrix_out 2>&1; then
    result="pass"
  else
    result="fail"
  fi

  # Check expectation
  if [ "$result" = "$expect" ]; then
    if [ "$expect" = "pass" ]; then
      echo "  PASS: ${producer}→${consumer} / ${scenario} (plan succeeded)"
      PASS=$((PASS + 1))
    else
      echo "  EXPECTED FAIL: ${producer}→${consumer} / ${scenario} (precondition blocked)"
      PASS=$((PASS + 1))
    fi
  else
    echo "  ✗ UNEXPECTED: ${producer}→${consumer} / ${scenario} (expected=$expect, got=$result)"
    FAIL=$((FAIL + 1))
  fi
}

echo "=== Layer Contract Matrix Test Suite ==="
echo ""

# Initialize terraform
terraform init -input=false -no-color -backend=false > /dev/null 2>&1

for pair in "${LAYER_PAIRS[@]}"; do
  IFS='|' read -r producer consumer scope <<< "$pair"
  echo "--- ${producer} → ${consumer} (${scope}) ---"

  # Valid scenario
  run_scenario "$producer" "$consumer" "$scope" "valid" "pass"

  # Negative scenarios
  run_scenario "$producer" "$consumer" "$scope" "wrong-deployment-id" "fail"
  run_scenario "$producer" "$consumer" "$scope" "wrong-account-id" "fail"
  run_scenario "$producer" "$consumer" "$scope" "wrong-producer-layer" "fail"
  run_scenario "$producer" "$consumer" "$scope" "wrong-schema-version" "fail"
  run_scenario "$producer" "$consumer" "$scope" "tampered-digest" "fail"
  run_scenario "$producer" "$consumer" "$scope" "stale-contract-version" "fail"
  run_scenario "$producer" "$consumer" "$scope" "stale-producer-release" "fail"
  run_scenario "$producer" "$consumer" "$scope" "consumer-bypass-attempt" "fail"

  # Regional-only scenarios
  if [ "$scope" = "regional" ]; then
    run_scenario "$producer" "$consumer" "$scope" "wrong-region" "fail"
  fi

  # Release freshness scenarios
  run_scenario "$producer" "$consumer" "$scope" "stale-release-manifest-digest" "fail"
  run_scenario "$producer" "$consumer" "$scope" "missing-expected-release-digest" "fail"

  echo ""
done

# State path scope tests
echo "--- State Path Scope Tests ---"

# Global layers with region (should fail)
run_scenario "account-ready" "global" "global" "state-path-global-with-region" "fail"
run_scenario "edge-identity" "edge" "global" "state-path-global-with-region" "fail"

# Regional layers without region (should fail)
run_scenario "global" "network" "regional" "state-path-regional-without-region" "fail"
run_scenario "network" "platform" "regional" "state-path-regional-without-region" "fail"

# Unknown critical field tests
echo ""
echo "--- Unknown Critical Field Tests ---"

# Unknown field in contract → FAIL
run_scenario "global" "network" "regional" "unknown-critical-field" "fail"

# Non-allowlisted extension → FAIL
run_scenario "global" "network" "regional" "unknown-non-allowlisted-field" "fail"

# Explicitly allowed extension → PASS
run_scenario "global" "network" "regional" "allowed-extension-field" "pass"

echo ""
echo "=== Results ==="
echo "  Total:    $TOTAL"
echo "  Pass:     $PASS"
echo "  Fail:     $FAIL"
echo "  Errors:   $ERRORS"

if [ "$FAIL" -gt 0 ] || [ "$ERRORS" -gt 0 ]; then
  echo "FAIL: Some scenarios did not match expectations"
  exit 1
fi

echo "ALL SCENARIOS PASSED"
