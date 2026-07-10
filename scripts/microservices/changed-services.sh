#!/usr/bin/env bash
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

usage() {
  cat <<'USAGE'
Usage:
  changed-services.sh --all
  changed-services.sh --service <service>
  changed-services.sh --diff <base-revision> <head-revision>
  changed-services.sh --service-diff <base-revision> <head-revision>

Prints a compact JSON array of canonical service IDs.
USAGE
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 2
}

is_allowed_service() {
  local candidate="$1"
  local service
  for service in "${SERVICES[@]}"; do
    [[ "$candidate" == "$service" ]] && return 0
  done
  return 1
}

emit_json() {
  local first=true
  local value
  printf '['
  for value in "$@"; do
    if [[ "$first" == true ]]; then
      first=false
    else
      printf ','
    fi
    printf '"%s"' "$value"
  done
  printf ']\n'
}

[[ "$#" -gt 0 ]] || die "a selection mode is required"

case "$1" in
  --all)
    [[ "$#" -eq 1 ]] || die "--all does not accept additional arguments"
    emit_json "${SERVICES[@]}"
    ;;
  --service)
    [[ "$#" -eq 2 ]] || die "--service requires exactly one value"
    service="${2#scanalyze-}"
    is_allowed_service "$service" || die "unsupported service: ${service}"
    emit_json "$service"
    ;;
  --diff)
    [[ "$#" -eq 3 ]] || die "--diff requires base and head revisions"
    base_revision="$2"
    head_revision="$3"
    git -C "$REPO_ROOT" cat-file -e "${base_revision}^{commit}" 2>/dev/null ||
      die "base revision is not available"
    git -C "$REPO_ROOT" cat-file -e "${head_revision}^{commit}" 2>/dev/null ||
      die "head revision is not available"

    changed_files="$(git -C "$REPO_ROOT" diff --name-only --no-renames "$base_revision" "$head_revision")"
    if [[ -z "$changed_files" ]]; then
      emit_json
      exit 0
    fi

    if printf '%s\n' "$changed_files" |
      grep -Eq '^(scripts/microservices/|\.github/workflows/microservices-build\.yml$|tooling/check_microservices\.py$)'; then
      emit_json "${SERVICES[@]}"
      exit 0
    fi

    selected=()
    for service in "${SERVICES[@]}"; do
      if printf '%s\n' "$changed_files" |
        grep -q "^backend/workers/scanalyze-${service}/"; then
        selected+=("$service")
      fi
    done
    emit_json "${selected[@]}"
    ;;
  --service-diff)
    [[ "$#" -eq 3 ]] || die "--service-diff requires base and head revisions"
    base_revision="$2"
    head_revision="$3"
    git -C "$REPO_ROOT" cat-file -e "${base_revision}^{commit}" 2>/dev/null ||
      die "base revision is not available"
    git -C "$REPO_ROOT" cat-file -e "${head_revision}^{commit}" 2>/dev/null ||
      die "head revision is not available"

    changed_files="$(git -C "$REPO_ROOT" diff --name-only --no-renames "$base_revision" "$head_revision")"
    selected=()
    for service in "${SERVICES[@]}"; do
      if printf '%s\n' "$changed_files" |
        grep -q "^backend/workers/scanalyze-${service}/"; then
        selected+=("$service")
      fi
    done
    emit_json "${selected[@]}"
    ;;
  -h|--help)
    usage
    ;;
  *)
    die "unknown selection mode: $1"
    ;;
esac
