#!/usr/bin/env bash
set -euo pipefail

# This script generates a local deployment manifest for development/testing
# using the active AWS credentials.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TEMPLATE_FILE="${REPO_ROOT}/examples/deployments/dev-template.yaml.tpl"
if [[ ! -f "$TEMPLATE_FILE" ]]; then
  echo "ERROR: Template not found at $TEMPLATE_FILE" >&2
  exit 1
fi

CUSTOMER_ID="${1:-my-dev-env}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"

echo "Fetching caller identity from AWS..."
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)" || {
  echo "ERROR: Unable to get AWS Account ID. Are you authenticated?" >&2
  exit 1
}

CLEAN_CUSTOMER_ID="$(echo "$CUSTOMER_ID" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9' | cut -c 1-14)"

# Generate a 26-character Crockford Base32 string for the deployment_id validation
VALID_CHARS="0123456789ABCDEFGHJKMNPQRSTVWXYZ"
RANDOM_ULID="$(openssl rand -base64 64 | env LC_CTYPE=C tr -dc "$VALID_CHARS" | head -c 26)"
LOWER_ULID="$(echo "$RANDOM_ULID" | tr '[:upper:]' '[:lower:]')"

OUTPUT_FILE="${REPO_ROOT}/examples/deployments/${CUSTOMER_ID}.generated.yaml"

# Replace variables
sed -e "s/__ACCOUNT_ID__/${ACCOUNT_ID}/g" \
    -e "s/__REGION__/${REGION}/g" \
    -e "s/__CUSTOMER_ID__/${CUSTOMER_ID}/g" \
    -e "s/__CLEAN_CUSTOMER_ID__/${CLEAN_CUSTOMER_ID}/g" \
    -e "s/__RANDOM_ULID__/${RANDOM_ULID}/g" \
    -e "s/__LOWER_ULID__/${LOWER_ULID}/g" \
    "$TEMPLATE_FILE" > "$OUTPUT_FILE"

echo "✅ Generated manifest for account $ACCOUNT_ID at:"
echo "   $OUTPUT_FILE"
echo ""
echo "You can now run deployments using this manifest:"
echo "   ./scripts/deployment/scanalyze-deploy.sh account-preflight --manifest $OUTPUT_FILE --no-dry-run"
