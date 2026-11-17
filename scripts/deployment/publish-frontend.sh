#!/usr/bin/env bash
# Owner-run build and upload of the frontend SPA for one direct-path
# deployment (GUG-543).
#
# The build is environment-agnostic: the edge layer writes the runtime
# configuration (<deployment>/config.json) into the same bucket, so this upload
# never deletes objects and never touches config.json files.
#
# This mutates AWS (S3 uploads and an optional CloudFront invalidation). Run it
# from your own shell, with your own credentials, after reviewing --dry-run.
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly FRONTEND_DIR="${REPO_ROOT}/frontend/scanalyze-frontend-ui"

ACCOUNT_ID=""
BUCKET=""
DISTRIBUTION_ID=""
DRY_RUN=false

usage() {
  cat <<'USAGE'
Build the Scanalyze frontend and upload it to the deployment's frontend bucket.

Usage:
  publish-frontend.sh --account-id <id> --bucket scanalyze-<id>-frontend \
    [--distribution-id <cloudfront-id>] [--dry-run]
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
    --bucket) require_value "$@"; BUCKET="$2"; shift 2 ;;
    --distribution-id) require_value "$@"; DISTRIBUTION_ID="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || die "--account-id must contain exactly 12 digits"
[[ "$ACCOUNT_ID" != "000000000000" ]] || die "synthetic account IDs cannot be published to"
# modules/edge/runtime_config.tf serves the SPA from exactly this bucket.
[[ "$BUCKET" == "scanalyze-${ACCOUNT_ID}-frontend" ]] || die "--bucket must be scanalyze-${ACCOUNT_ID}-frontend"
[[ -z "$DISTRIBUTION_ID" || "$DISTRIBUTION_ID" =~ ^[A-Z0-9]{8,20}$ ]] || die "invalid --distribution-id"
[[ -f "${FRONTEND_DIR}/package-lock.json" ]] || die "frontend lockfile is missing"

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
  command -v npm >/dev/null 2>&1 || die "npm is required"
  command -v aws >/dev/null 2>&1 || die "aws CLI is required"
  caller_account="$(aws sts get-caller-identity --query Account --output text)"
  [[ "$caller_account" == "$ACCOUNT_ID" ]] || die "AWS caller account does not match --account-id"
fi

log "Building the frontend from the lockfile"
run npm --prefix "$FRONTEND_DIR" ci
run npm --prefix "$FRONTEND_DIR" run build

log "Uploading dist/ to s3://${BUCKET}/ (no deletes; config.json stays owned by the edge layer)"
run aws s3 sync "${FRONTEND_DIR}/dist/" "s3://${BUCKET}/" --exclude "*config.json" --only-show-errors

if [[ -n "$DISTRIBUTION_ID" ]]; then
  log "Invalidating CloudFront distribution ${DISTRIBUTION_ID}"
  run aws cloudfront create-invalidation --distribution-id "$DISTRIBUTION_ID" --paths "/*"
fi

log "Frontend published to s3://${BUCKET}/"
