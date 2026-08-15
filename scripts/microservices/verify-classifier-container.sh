#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SMOKE_SCRIPT="${REPO_ROOT}/backend/workers/scanalyze-classifier-worker/tests/container_smoke.py"
EXPECTED_SOURCE="https://github.com/cesar-guzman/scanalyze-deployment-platform"

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
[[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] ||
  die "revision must be a full lowercase Git SHA"
expected_image="scanalyze-ci/classifier-worker:sha-${REVISION:0:12}"
[[ "$IMAGE" == "$expected_image" ]] ||
  die "image must be the exact hermetic classifier tag ${expected_image}"
[[ -f "$SMOKE_SCRIPT" ]] || die "missing classifier container smoke script"
command -v docker >/dev/null 2>&1 || die "docker is required"

docker image inspect "$IMAGE" >/dev/null 2>&1 ||
  die "image is not present locally; verifier will not pull it"
[[ "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE")" == "linux/amd64" ]] ||
  die "image platform must be linux/amd64"
[[ "$(docker image inspect --format '{{.Config.User}}' "$IMAGE")" == "app" ]] ||
  die "image runtime user must be app"
[[ "$(docker image inspect --format '{{json .Config.Entrypoint}}' "$IMAGE")" == '["python","-m","classifier_worker.main"]' ]] ||
  die "image ENTRYPOINT does not match the classifier worker contract"
[[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$IMAGE")" == "$EXPECTED_SOURCE" ]] ||
  die "OCI source label does not match the canonical repository"
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
  --pids-limit 128
  --memory 512m
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
import os
import sys

def require_equal(actual, expected, label):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected {expected!r}, got {actual!r}")

require_equal(sys.version_info[:3], (3, 11, 14), "Python version")
require_equal(metadata.version("boto3"), "1.43.72", "boto3 version")
require_equal(metadata.version("pydantic"), "2.13.4", "pydantic version")
require_equal(metadata.version("structlog"), "26.1.0", "structlog version")
require_equal(set(os.listdir("/sys/class/net")), {"lo"}, "network interfaces")
for name in (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
):
    if name in os.environ:
        raise SystemExit(f"credential environment is present: {name}")
if os.path.exists("/var/run/docker.sock"):
    raise SystemExit("Docker socket is visible inside the container")
import classifier_worker.main
import classifier_worker.classifier
import classifier_worker.contracts
print("CLASSIFIER_CONTAINER_IMPORT_OK")' \
    2>&1
)" || die "container runtime/import verification failed"
[[ "$runtime_output" == *"CLASSIFIER_CONTAINER_IMPORT_OK"* ]] ||
  die "container import marker was not emitted"

set +e
startup_output="$(
  docker "${run_args[@]}" \
    --env SCANALYZE_DEPLOYMENT_ID=SYNTHETIC_PROVIDER_PAYLOAD_DO_NOT_LOG \
    "$IMAGE" 2>&1
)"
startup_status=$?
set -e
[[ "$startup_status" -eq 1 ]] ||
  die "controlled invalid startup must fail with exit code 1, got ${startup_status}"
[[ "$startup_output" == *"SCANALYZE_DEPLOYMENT_ID is invalid"* ]] ||
  die "real entrypoint did not emit the safe fail-closed diagnostic"

smoke_output="$(
  docker "${run_args[@]}" \
    --env PYTHONOPTIMIZE=1 \
    --interactive \
    --entrypoint python \
    "$IMAGE" - < "$SMOKE_SCRIPT" 2>&1
)" || die "causal classifier container smoke failed"
[[ "$smoke_output" == *"CLASSIFIER_CONTAINER_SMOKE_OK"* ]] ||
  die "causal classifier smoke marker was not emitted"

combined_output="${runtime_output}${startup_output}${smoke_output}"
for sentinel in \
  SYNTHETIC_DOCUMENT_CONTENT_DO_NOT_LOG \
  SYNTHETIC_TOKEN_DO_NOT_LOG \
  SYNTHETIC_CREDENTIAL_DO_NOT_LOG \
  000011112222 \
  SYNTHETIC_PROVIDER_PAYLOAD_DO_NOT_LOG
do
  [[ "$combined_output" != *"$sentinel"* ]] ||
    die "container output leaked a synthetic sentinel"
done

printf 'PASS: hermetic classifier image imports, fails closed before providers, preserves the event contract, and redacts sentinels.\n'
