#!/usr/bin/env bash
set -euo pipefail

# This script generates a local deployment manifest for development/testing
# using an explicitly selected non-production AWS profile. The output is always
# outside the repository and created with owner-only permissions.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TEMPLATE_FILE="${REPO_ROOT}/examples/deployments/dev-template.yaml.tpl"
if [[ ! -f "$TEMPLATE_FILE" ]]; then
  echo "ERROR: Template not found at $TEMPLATE_FILE" >&2
  exit 1
fi

usage() {
  cat >&2 <<'EOF'
Usage: generate-dev-manifest.sh <customer-id> \
  --deployment-id <registry-assigned-dep_ULID> \
  --github-environment <deployment-scoped-environment> \
  --output <path-outside-repository>

Required operational inputs:
  --deployment-id       Immutable deployment ID allocated by the approved registry
  --github-environment  Pre-created, protected Environment for this deployment/stage

Required environment:
  AWS_PROFILE  Explicit approved non-production profile
  AWS_REGION   Explicit approved AWS region
EOF
}

[[ "$#" -ge 1 ]] || { usage; exit 2; }

CUSTOMER_ID="$1"
shift
OUTPUT_FILE=""
DEPLOYMENT_ID=""
GITHUB_ENVIRONMENT=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --deployment-id)
      [[ -n "${2:-}" ]] || { echo "ERROR: --deployment-id requires a value" >&2; exit 2; }
      DEPLOYMENT_ID="$2"
      shift 2
      ;;
    --github-environment)
      [[ -n "${2:-}" ]] || { echo "ERROR: --github-environment requires a value" >&2; exit 2; }
      GITHUB_ENVIRONMENT="$2"
      shift 2
      ;;
    --output)
      [[ -n "${2:-}" ]] || { echo "ERROR: --output requires a path" >&2; exit 2; }
      OUTPUT_FILE="$2"
      shift 2
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

[[ "$CUSTOMER_ID" =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ ]] || {
  echo "ERROR: customer-id must be 3-63 lowercase letters, digits, or hyphens" >&2
  exit 2
}
[[ -n "$OUTPUT_FILE" ]] || {
  echo "ERROR: --output is required; real manifests must be outside the repository" >&2
  exit 2
}
[[ -n "$DEPLOYMENT_ID" ]] || {
  echo "ERROR: --deployment-id is required and must come from the approved registry" >&2
  exit 2
}
[[ "$DEPLOYMENT_ID" =~ ^dep_[0-9A-HJKMNP-TV-Z]{26}$ ]] || {
  echo "ERROR: --deployment-id must be a dep_<ULID> allocated by the approved registry" >&2
  exit 2
}
[[ -n "$GITHUB_ENVIRONMENT" ]] || {
  echo "ERROR: --github-environment is required and must name the protected deployment Environment" >&2
  exit 2
}
[[ "$GITHUB_ENVIRONMENT" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$ ]] || {
  echo "ERROR: --github-environment has an invalid format" >&2
  exit 2
}
[[ "$GITHUB_ENVIRONMENT" == *"$DEPLOYMENT_ID"* ]] || {
  echo "ERROR: --github-environment must be deployment-scoped and include the exact --deployment-id" >&2
  exit 2
}
[[ -n "${AWS_PROFILE:-}" ]] || {
  echo "ERROR: AWS_PROFILE must name the approved non-production profile" >&2
  exit 2
}
[[ -n "${AWS_REGION:-}" ]] || {
  echo "ERROR: AWS_REGION must name the approved region" >&2
  exit 2
}

REGION="$AWS_REGION"
[[ "$REGION" =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]] || {
  echo "ERROR: AWS_REGION has an invalid format" >&2
  exit 2
}

OUTPUT_DIR="$(dirname "$OUTPUT_FILE")"
[[ -d "$OUTPUT_DIR" ]] || {
  echo "ERROR: output directory does not exist: $OUTPUT_DIR" >&2
  exit 2
}
ABS_OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
ABS_OUTPUT_FILE="${ABS_OUTPUT_DIR}/$(basename "$OUTPUT_FILE")"

case "${ABS_OUTPUT_FILE}" in
  "${REPO_ROOT}"|"${REPO_ROOT}"/*)
    echo "ERROR: --output must be outside the repository" >&2
    exit 2
    ;;
esac

echo "Fetching caller identity from AWS..."
ACCOUNT_ID="$(aws --profile "$AWS_PROFILE" --region "$REGION" sts get-caller-identity --query Account --output text 2>/dev/null)" || {
  echo "ERROR: Unable to get AWS Account ID. Are you authenticated?" >&2
  exit 1
}
[[ "$ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || {
  echo "ERROR: AWS caller identity returned an invalid account binding" >&2
  exit 1
}

DEPLOYMENT_ULID="${DEPLOYMENT_ID#dep_}"
LOWER_ULID="$(echo "$DEPLOYMENT_ULID" | tr '[:upper:]' '[:lower:]')"

# Replace variables
umask 077
TEMP_OUTPUT="$(mktemp "${ABS_OUTPUT_DIR}/.scanalyze-manifest.XXXXXX")"
trap 'rm -f "$TEMP_OUTPUT"' EXIT HUP INT TERM

sed -e "s/__ACCOUNT_ID__/${ACCOUNT_ID}/g" \
    -e "s/__REGION__/${REGION}/g" \
    -e "s/__CUSTOMER_ID__/${CUSTOMER_ID}/g" \
    -e "s/__DEPLOYMENT_ID__/${DEPLOYMENT_ID}/g" \
    -e "s/__GITHUB_ENVIRONMENT__/${GITHUB_ENVIRONMENT}/g" \
    -e "s/__LOWER_ULID__/${LOWER_ULID}/g" \
    "$TEMPLATE_FILE" > "$TEMP_OUTPUT"

chmod 600 "$TEMP_OUTPUT"
mv "$TEMP_OUTPUT" "$ABS_OUTPUT_FILE"
trap - EXIT HUP INT TERM

echo "PASS: generated a private non-production manifest outside the repository:"
echo "   $ABS_OUTPUT_FILE"
echo ""
echo "Validate it locally without committing it:"
echo "   python scripts/deployment/validate-manifest.py \"$ABS_OUTPUT_FILE\""
