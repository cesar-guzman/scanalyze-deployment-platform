#!/usr/bin/env bash
# Owner-run publication of the seven service images for one direct-path
# deployment (GUG-543).
#
# 1. Prepares the hermetic OCR and classifier wheelhouses.
# 2. Runs scripts/microservices/build-push.sh --all --push --write-ssm. That
#    script enforces immutable ECR tags, a digest-pinned base image from the
#    target account, a clean worktree and the caller account.
# 3. Reads every pushed digest back from ECR and writes a release-images JSON
#    file. scripts/deployment/render-direct-service-definitions.py turns it
#    into the services layer's service_definitions.
#
# This mutates AWS (ECR pushes and SSM release metadata). Run it from your own
# shell, with your own credentials, after reviewing the --dry-run output.
set -euo pipefail
IFS=$'\n\t'

readonly SERVICES=(
  "ingest-api"
  "ocr-worker"
  "postprocess-worker"
  "classifier-worker"
  "bank-worker"
  "personal-worker"
  "gov-worker"
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

ACCOUNT_ID=""
REGION=""
DEPLOYMENT_ID=""
BASE_IMAGE=""
TAG=""
OUTPUT=""
DRY_RUN=false

usage() {
  cat <<'USAGE'
Publish the seven Scanalyze service images for one direct-path deployment.

Usage:
  publish-direct-release.sh --account-id <id> --region <region> \
    --deployment-id <dep_ULID> --base-image <account-ECR-ref@sha256:...> \
    --tag <immutable-tag> --output <release-images.json> [--dry-run]

The ECR repositories <dep-ulid>/scanalyze/<service> must exist with immutable
tags, and the base image must already be in the same account's ECR, pinned by
digest. See docs/operations/direct-path-publish.md.
USAGE
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 2
}

log() {
  printf '==> %s\n' "$*" >&2
}

require_value() {
  [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || die "$1 requires a value"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --account-id) require_value "$@"; ACCOUNT_ID="$2"; shift 2 ;;
    --region) require_value "$@"; REGION="$2"; shift 2 ;;
    --deployment-id) require_value "$@"; DEPLOYMENT_ID="$2"; shift 2 ;;
    --base-image) require_value "$@"; BASE_IMAGE="$2"; shift 2 ;;
    --tag) require_value "$@"; TAG="$2"; shift 2 ;;
    --output) require_value "$@"; OUTPUT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || die "--account-id must contain exactly 12 digits"
[[ "$ACCOUNT_ID" != "000000000000" ]] || die "synthetic account IDs cannot be published to"
[[ "$REGION" =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]] || die "invalid --region"
[[ "$DEPLOYMENT_ID" =~ ^dep_[0-9A-HJKMNP-TV-Z]{26}$ ]] || die "--deployment-id must match dep_<ULID>"
[[ "$TAG" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || die "invalid --tag"
[[ "$(printf '%s' "$TAG" | tr '[:upper:]' '[:lower:]')" != "latest" ]] || die "the latest tag is forbidden"

readonly REGISTRY="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
[[ "$BASE_IMAGE" == "${REGISTRY}/"* ]] || die "--base-image must come from ${REGISTRY}"
[[ "$BASE_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] || die "--base-image must be pinned by @sha256 digest"

[[ -n "$OUTPUT" ]] || die "--output is required"
[[ ! -e "$OUTPUT" ]] || die "--output already exists; refusing to overwrite ${OUTPUT}"
[[ -d "$(dirname "$OUTPUT")" ]] || die "--output directory does not exist"

SANITIZED_DEPLOYMENT_ID="$(printf '%s' "$DEPLOYMENT_ID" | tr '[:upper:]_' '[:lower:]-')"
readonly ECR_PREFIX="${SANITIZED_DEPLOYMENT_ID}/scanalyze"

run() {
  if [[ "$DRY_RUN" == true ]]; then
    printf '[dry-run]'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

if [[ "$DRY_RUN" != true ]]; then
  command -v aws >/dev/null 2>&1 || die "aws CLI is required"
  command -v docker >/dev/null 2>&1 || die "docker is required"
  command -v python3 >/dev/null 2>&1 || die "python3 is required"
fi

log "Preparing the hermetic OCR and classifier wheelhouses"
run "${REPO_ROOT}/scripts/microservices/prepare-ocr-wheelhouse.sh"
run "${REPO_ROOT}/scripts/microservices/prepare-classifier-wheelhouse.sh"

log "Building and pushing ${#SERVICES[@]} images to ${REGISTRY}/${ECR_PREFIX} with tag ${TAG}"
run "${REPO_ROOT}/scripts/microservices/build-push.sh" \
  --all \
  --tag "$TAG" \
  --base-image "$BASE_IMAGE" \
  --account-id "$ACCOUNT_ID" \
  --region "$REGION" \
  --deployment-id "$DEPLOYMENT_ID" \
  --ecr-prefix "$ECR_PREFIX" \
  --push \
  --write-ssm

if [[ "$DRY_RUN" == true ]]; then
  for service in "${SERVICES[@]}"; do
    run aws ecr describe-images --region "$REGION" --repository-name "${ECR_PREFIX}/${service}" \
      --image-ids "imageTag=${TAG}" --query 'imageDetails[0].imageDigest' --output text
  done
  log "Dry run: would write ${OUTPUT}"
  exit 0
fi

digest_lines=()
for service in "${SERVICES[@]}"; do
  digest="$(aws ecr describe-images --region "$REGION" --repository-name "${ECR_PREFIX}/${service}" \
    --image-ids "imageTag=${TAG}" --query 'imageDetails[0].imageDigest' --output text)"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "ECR returned no valid digest for ${service}"
  digest_lines+=("${service}=${digest}")
done

REVISION="$(git -C "$REPO_ROOT" rev-parse HEAD)"
python3 - "$OUTPUT" "$ACCOUNT_ID" "$REGION" "$DEPLOYMENT_ID" "$TAG" "$REVISION" "${digest_lines[@]}" <<'PY'
import json
import os
import sys

output, account_id, region, deployment_id, tag, revision, *pairs = sys.argv[1:]
document = {
    "schema_version": "scanalyze.direct-release-images.v1",
    "account_id": account_id,
    "region": region,
    "deployment_id": deployment_id,
    "tag": tag,
    "revision": revision,
    "images": dict(pair.split("=", 1) for pair in pairs),
}
descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

log "Wrote ${OUTPUT}"
log "Next: scripts/deployment/render-direct-service-definitions.py --release-images ${OUTPUT} --out <services.auto.tfvars.json>"
