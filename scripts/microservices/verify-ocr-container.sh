#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SMOKE_SCRIPT="${REPO_ROOT}/backend/workers/scanalyze-ocr-worker/tests/container_smoke.py"

IMAGE=""
REVISION=""
IMAGE_SEEN=false
REVISION_SEEN=false

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 2
}

require_value() {
  local option="$1"
  local value="${2:-}"
  [[ -n "$value" && "$value" != --* ]] || die "${option} requires a value"
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --image)
      [[ "$IMAGE_SEEN" == false ]] || die "--image may be specified only once"
      require_value "$1" "${2:-}"
      IMAGE="$2"
      IMAGE_SEEN=true
      shift 2
      ;;
    --revision)
      [[ "$REVISION_SEEN" == false ]] || die "--revision may be specified only once"
      require_value "$1" "${2:-}"
      REVISION="$2"
      REVISION_SEEN=true
      shift 2
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ "$IMAGE_SEEN" == true ]] || die "--image is required"
[[ "$REVISION_SEEN" == true ]] || die "--revision is required"
[[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] || die "revision must be a full lowercase Git SHA"
expected_image="scanalyze-ci/ocr-worker:sha-${REVISION:0:12}"
[[ "$IMAGE" == "$expected_image" ]] ||
  die "image must be the exact hermetic OCR tag ${expected_image}"
[[ -f "$SMOKE_SCRIPT" ]] || die "missing container smoke script"
command -v docker >/dev/null 2>&1 || die "docker is required"

docker image inspect "$IMAGE" >/dev/null 2>&1 ||
  die "image is not present locally; verifier will not pull it"

[[ "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE")" == "linux/amd64" ]] ||
  die "image platform must be linux/amd64"
[[ "$(docker image inspect --format '{{.Config.User}}' "$IMAGE")" == "app" ]] ||
  die "image runtime user must be app"
[[ "$(docker image inspect --format '{{json .Config.Entrypoint}}' "$IMAGE")" == '["python","-m","src.ocr_worker.main"]' ]] ||
  die "image ENTRYPOINT does not match the OCR worker contract"
[[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE")" == "$REVISION" ]] ||
  die "OCI revision label does not match the reviewed Git SHA"

run_args=(
  run
  --rm
  --platform linux/amd64
  --network none
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges:true
  --tmpfs /tmp:rw,noexec,nosuid,size=16m
  --env SCANALYZE_ENV=ci
  --env SCANALYZE_TENANT=platform
  --env SCANALYZE_DEPLOYMENT_CUSTOMER_ID=cust_01ARZ3NDEKTSV4RRFFQ69G5FAW
  --env SCANALYZE_DEPLOYMENT_ID=dep_01ARZ3NDEKTSV4RRFFQ69G5FAV
  --env SCANALYZE_PARAM_ROOT=/scanalyze/ci/tenants
  --env AWS_EC2_METADATA_DISABLED=true
  --env AWS_REGION=us-east-1
  --env AWS_DEFAULT_REGION=us-east-1
  --env AWS_CONFIG_FILE=/dev/null
  --env AWS_SHARED_CREDENTIALS_FILE=/dev/null
  --env BOTO_CONFIG=/dev/null
)

runtime_output="$(
  docker "${run_args[@]}" \
    --entrypoint python \
    "$IMAGE" \
    -c 'import importlib.metadata as metadata
import sys

def require_equal(actual, expected, label):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected {expected!r}, got {actual!r}")

require_equal(sys.version_info[:3], (3, 11, 14), "Python version")
require_equal(metadata.version("boto3"), "1.34.0", "boto3 version")
require_equal(metadata.version("pydantic"), "2.5.3", "pydantic version")
import src.ocr_worker.main
print("OCR_CONTAINER_IMPORT_OK")' \
    2>&1
)" || die "container runtime/import verification failed"
[[ "$runtime_output" == *"OCR_CONTAINER_IMPORT_OK"* ]] ||
  die "container import marker was not emitted"

assert_startup_fails_closed() {
  local mode="$1"
  local output
  local status
  local mode_args=()
  if [[ "$mode" != "<unset>" ]]; then
    mode_args=(--env "WORKER_MODE=${mode}")
  fi

  set +e
  output="$(docker "${run_args[@]}" "${mode_args[@]}" "$IMAGE" 2>&1)"
  status=$?
  set -e

  [[ "$status" -eq 1 ]] ||
    die "WORKER_MODE ${mode} must fail with exit code 1, got ${status}"
  [[ "$output" == *'Invalid WORKER_MODE. Must be INGEST or OCR_POLL.'* ]] ||
    die "WORKER_MODE ${mode} did not emit the safe fail-closed diagnostic"
}

assert_startup_fails_closed "<unset>"
assert_startup_fails_closed "INVALID"

smoke_output="$(
  docker "${run_args[@]}" \
    --env PYTHONOPTIMIZE=1 \
    --interactive \
    --entrypoint python \
    "$IMAGE" - < "$SMOKE_SCRIPT" 2>&1
)" || die "causal container smoke failed"
[[ "$smoke_output" == *"OCR_CONTAINER_SMOKE_OK"* ]] ||
  die "causal container smoke marker was not emitted"

for sentinel in \
  SYNTHETIC_RAW_DOCUMENT_CONTENT \
  SYNTHETIC_PII_ISH_CONTENT \
  SYNTHETIC_EXCEPTION_CONTENT \
  '<SENTINEL_CORR>' \
  '<SENTINEL_TRACE>'
do
  [[ "$smoke_output" != *"$sentinel"* ]] ||
    die "container output leaked a synthetic sentinel"
done

printf 'PASS: hermetic OCR image imports, fails closed, processes the synthetic fixture, and redacts sentinels.\n'
