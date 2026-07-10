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

SELECTED_SERVICE=""
SELECT_ALL=false
TAG=""
BASE_IMAGE=""
ACCOUNT_ID=""
AWS_REGION_VALUE=""
DEPLOYMENT_ID=""
ECR_PREFIX=""
PUSH_IMAGES=false
WRITE_SSM=false
RECONCILE_DIGEST=""

SERVICE_SEEN=false
ALL_SEEN=false
TAG_SEEN=false
BASE_IMAGE_SEEN=false
ACCOUNT_ID_SEEN=false
REGION_SEEN=false
DEPLOYMENT_ID_SEEN=false
ECR_PREFIX_SEEN=false
PUSH_MODE_SEEN=false
SSM_MODE_SEEN=false
RECONCILE_SEEN=false

usage() {
  cat <<'USAGE'
Build Scanalyze microservice images from the monorepo.

Usage:
  build-push.sh (--service <service> | --all) --tag <tag> [--base-image <image>] [options]

Required:
  --service <service>       One of the seven Scanalyze service IDs
  --all                     Build all seven services (mutually exclusive with --service)
  --tag <tag>               Immutable image tag; "latest" is rejected
  --base-image <image>      Explicit Docker base image (required for builds)

Required only with --push:
  --account-id <id>         Expected 12-digit AWS account ID
  --region <region>         Explicit AWS region
  --deployment-id <id>     Deployment ID in dep_<ULID> format
  --ecr-prefix <prefix>     Full ECR prefix, for example dep-.../scanalyze

Modes (safe defaults shown):
  --push | --no-push                 Default: --no-push
  --write-ssm | --no-write-ssm       Default: --no-write-ssm
  --reconcile-existing <sha256:...>   Service-only recovery for an existing tag

Publishing requires a digest-pinned base image in the target account ECR.
SSM writes require --push and occur only after ECR returns a valid digest.
Reconciliation requires --service, --push, --write-ssm, and an exact digest;
it verifies the immutable ECR tag and writes metadata without rebuilding.
USAGE
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 2
}

log() {
  printf '%s\n' "$*"
}

write_release_metadata() {
  local service="$1"
  local digest="$2"
  local namespace="/${DEPLOYMENT_ID}/cicd/images/${service}"

  aws ssm put-parameter \
    --name "${namespace}/image_tag" \
    --value "$TAG" \
    --type String \
    --overwrite >/dev/null
  aws ssm put-parameter \
    --name "${namespace}/image_digest" \
    --value "$digest" \
    --type String \
    --overwrite >/dev/null
  log "Updated release metadata for ${service} under ${namespace}."
}

require_value() {
  local option="$1"
  local value="${2:-}"
  [[ -n "$value" && "$value" != --* ]] || die "${option} requires a value"
}

is_allowed_service() {
  local candidate="$1"
  local service
  for service in "${SERVICES[@]}"; do
    if [[ "$candidate" == "$service" ]]; then
      return 0
    fi
  done
  return 1
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --service)
      [[ "$SERVICE_SEEN" == false ]] || die "--service may be specified only once"
      [[ "$ALL_SEEN" == false ]] || die "--service and --all are mutually exclusive"
      require_value "$1" "${2:-}"
      SELECTED_SERVICE="${2#scanalyze-}"
      SERVICE_SEEN=true
      shift 2
      ;;
    --all)
      [[ "$ALL_SEEN" == false ]] || die "--all may be specified only once"
      [[ "$SERVICE_SEEN" == false ]] || die "--service and --all are mutually exclusive"
      SELECT_ALL=true
      ALL_SEEN=true
      shift
      ;;
    --tag)
      [[ "$TAG_SEEN" == false ]] || die "--tag may be specified only once"
      require_value "$1" "${2:-}"
      TAG="$2"
      TAG_SEEN=true
      shift 2
      ;;
    --base-image)
      [[ "$BASE_IMAGE_SEEN" == false ]] || die "--base-image may be specified only once"
      require_value "$1" "${2:-}"
      BASE_IMAGE="$2"
      BASE_IMAGE_SEEN=true
      shift 2
      ;;
    --account-id)
      [[ "$ACCOUNT_ID_SEEN" == false ]] || die "--account-id may be specified only once"
      require_value "$1" "${2:-}"
      ACCOUNT_ID="$2"
      ACCOUNT_ID_SEEN=true
      shift 2
      ;;
    --region)
      [[ "$REGION_SEEN" == false ]] || die "--region may be specified only once"
      require_value "$1" "${2:-}"
      AWS_REGION_VALUE="$2"
      REGION_SEEN=true
      shift 2
      ;;
    --deployment-id)
      [[ "$DEPLOYMENT_ID_SEEN" == false ]] || die "--deployment-id may be specified only once"
      require_value "$1" "${2:-}"
      DEPLOYMENT_ID="$2"
      DEPLOYMENT_ID_SEEN=true
      shift 2
      ;;
    --ecr-prefix)
      [[ "$ECR_PREFIX_SEEN" == false ]] || die "--ecr-prefix may be specified only once"
      require_value "$1" "${2:-}"
      ECR_PREFIX="$2"
      ECR_PREFIX_SEEN=true
      shift 2
      ;;
    --push)
      [[ "$PUSH_MODE_SEEN" == false ]] || die "choose exactly one push mode"
      PUSH_IMAGES=true
      PUSH_MODE_SEEN=true
      shift
      ;;
    --no-push)
      [[ "$PUSH_MODE_SEEN" == false ]] || die "choose exactly one push mode"
      PUSH_IMAGES=false
      PUSH_MODE_SEEN=true
      shift
      ;;
    --write-ssm)
      [[ "$SSM_MODE_SEEN" == false ]] || die "choose exactly one SSM mode"
      WRITE_SSM=true
      SSM_MODE_SEEN=true
      shift
      ;;
    --no-write-ssm)
      [[ "$SSM_MODE_SEEN" == false ]] || die "choose exactly one SSM mode"
      WRITE_SSM=false
      SSM_MODE_SEEN=true
      shift
      ;;
    --reconcile-existing)
      [[ "$RECONCILE_SEEN" == false ]] || die "--reconcile-existing may be specified only once"
      require_value "$1" "${2:-}"
      RECONCILE_DIGEST="$2"
      RECONCILE_SEEN=true
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ "$SERVICE_SEEN" == true || "$ALL_SEEN" == true ]] || die "choose --service or --all"
[[ "$TAG_SEEN" == true ]] || die "--tag is required"
if [[ "$RECONCILE_SEEN" == false ]]; then
  [[ "$BASE_IMAGE_SEEN" == true ]] || die "--base-image is required for builds"
fi

if [[ "$SERVICE_SEEN" == true ]]; then
  is_allowed_service "$SELECTED_SERVICE" || die "unsupported service: ${SELECTED_SERVICE}"
  SERVICES_TO_BUILD=("$SELECTED_SERVICE")
else
  SERVICES_TO_BUILD=("${SERVICES[@]}")
fi

[[ "$TAG" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || die "invalid OCI/ECR tag"
[[ "$(printf '%s' "$TAG" | tr '[:upper:]' '[:lower:]')" != "latest" ]] || die "the latest tag is forbidden"
if [[ "$BASE_IMAGE_SEEN" == true ]]; then
  [[ "$BASE_IMAGE" != *[[:space:]]* ]] || die "base image must not contain whitespace"
  [[ "$BASE_IMAGE" != *":latest" ]] || die "a latest base image is forbidden"
fi

if [[ -n "$ACCOUNT_ID" ]]; then
  [[ "$ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || die "account ID must contain exactly 12 digits"
fi
if [[ -n "$AWS_REGION_VALUE" ]]; then
  [[ "$AWS_REGION_VALUE" =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]] || die "invalid AWS region"
fi
if [[ -n "$DEPLOYMENT_ID" ]]; then
  [[ "$DEPLOYMENT_ID" =~ ^dep_[0-9A-HJKMNP-TV-Z]{26}$ ]] || die "deployment ID must match dep_<ULID>"
fi
if [[ -n "$ECR_PREFIX" ]]; then
  [[ "$ECR_PREFIX" =~ ^[a-z0-9]+([._/-][a-z0-9]+)*$ ]] || die "invalid ECR prefix"
fi

if [[ "$WRITE_SSM" == true && "$PUSH_IMAGES" != true ]]; then
  die "--write-ssm requires --push"
fi

if [[ "$RECONCILE_SEEN" == true ]]; then
  [[ "$SERVICE_SEEN" == true ]] || die "--reconcile-existing requires exactly one --service"
  [[ "$PUSH_IMAGES" == true ]] || die "--reconcile-existing requires --push authorization"
  [[ "$WRITE_SSM" == true ]] || die "--reconcile-existing requires --write-ssm"
  [[ "$RECONCILE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "invalid reconciliation digest"
  [[ "$BASE_IMAGE_SEEN" == false ]] || die "--base-image is not used with --reconcile-existing"
fi

if [[ "$PUSH_IMAGES" == true ]]; then
  [[ -n "$ACCOUNT_ID" ]] || die "--account-id is required with --push"
  [[ "$ACCOUNT_ID" != "000000000000" ]] || die "synthetic account IDs cannot be used with --push"
  [[ -n "$AWS_REGION_VALUE" ]] || die "--region is required with --push"
  [[ -n "$DEPLOYMENT_ID" ]] || die "--deployment-id is required with --push"
  [[ -n "$ECR_PREFIX" ]] || die "--ecr-prefix is required with --push"
  SANITIZED_DEPLOYMENT_ID="$(printf '%s' "$DEPLOYMENT_ID" | tr '[:upper:]_' '[:lower:]-')"
  [[ "$ECR_PREFIX" == "${SANITIZED_DEPLOYMENT_ID}/"* ]] || die "ECR prefix must belong to --deployment-id"
  if [[ "$RECONCILE_SEEN" == false ]]; then
    [[ "$BASE_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] || die "published base images must be digest-pinned"
  fi
fi

if [[ "$RECONCILE_SEEN" == false ]]; then
  command -v docker >/dev/null 2>&1 || die "docker is required"
fi

SOURCE_URL="local"
if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
  SOURCE_URL="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}"
fi

HEAD_REVISION="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)" || die "repository HEAD is unavailable"
REVISION="${GITHUB_SHA:-$HEAD_REVISION}"
git -C "$REPO_ROOT" cat-file -e "${REVISION}^{commit}" 2>/dev/null || die "source revision is not a Git commit"
REVISION="$(git -C "$REPO_ROOT" rev-parse "${REVISION}^{commit}")"
CREATED="$(git -C "$REPO_ROOT" show -s --format=%cI "$REVISION")"

REGISTRY=""
if [[ "$PUSH_IMAGES" == true ]]; then
  command -v aws >/dev/null 2>&1 || die "aws CLI is required with --push"
  REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION_VALUE}.amazonaws.com"
  if [[ "$RECONCILE_SEEN" == false ]]; then
    [[ "$BASE_IMAGE" == "${REGISTRY}/"* ]] || die "published base image must come from the target account ECR"
  fi

  export AWS_REGION="$AWS_REGION_VALUE"
  export AWS_DEFAULT_REGION="$AWS_REGION_VALUE"

  CALLER_ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
  [[ "$CALLER_ACCOUNT" == "$ACCOUNT_ID" ]] || die "AWS caller account does not match --account-id"

  [[ "$REVISION" == "$HEAD_REVISION" ]] || die "publish revision must match the checked-out HEAD"
  WORKTREE_STATUS="$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal)"
  [[ -z "$WORKTREE_STATUS" ]] || die "publishing requires a clean Git worktree"

  for service in "${SERVICES_TO_BUILD[@]}"; do
    repository_name="${ECR_PREFIX}/${service}"
    repository_mutability="$(aws ecr describe-repositories \
      --repository-names "$repository_name" \
      --query 'repositories[0].imageTagMutability' \
      --output text)" || die "unable to inspect ECR repository ${repository_name}"
    [[ "$repository_mutability" == "IMMUTABLE" ]] || die "ECR repository ${repository_name} must enforce immutable tags"

    if ! existing_count="$(aws ecr batch-get-image \
      --repository-name "$repository_name" \
      --image-ids "imageTag=${TAG}" \
      --query 'length(images)' \
      --output text)"; then
      die "unable to verify whether tag ${TAG} already exists for ${service}"
    fi
    if [[ "$RECONCILE_SEEN" == true ]]; then
      [[ "$existing_count" == "1" ]] || die "reconciliation tag ${TAG} does not exist exactly once for ${service}"
      existing_digest="$(aws ecr describe-images \
        --repository-name "$repository_name" \
        --image-ids "imageTag=${TAG}" \
        --query 'imageDetails[0].imageDigest' \
        --output text)" || die "unable to read existing digest for ${service}"
      [[ "$existing_digest" == "$RECONCILE_DIGEST" ]] || die "existing ECR digest does not match --reconcile-existing"
    else
      [[ "$existing_count" == "0" ]] || die "immutable tag ${TAG} already exists for ${service}"
    fi
  done

  log "Authenticated AWS caller for account ${ACCOUNT_ID} in ${AWS_REGION_VALUE}."
  if [[ "$RECONCILE_SEEN" == false ]]; then
    aws ecr get-login-password --region "$AWS_REGION_VALUE" |
      docker login --username AWS --password-stdin "$REGISTRY" >/dev/null
  fi
fi

if [[ "$RECONCILE_SEEN" == true ]]; then
  write_release_metadata "$SELECTED_SERVICE" "$RECONCILE_DIGEST"
  log "Reconciled existing immutable image metadata; no image was built or pushed."
  exit 0
fi

for service in "${SERVICES_TO_BUILD[@]}"; do
  context="${REPO_ROOT}/backend/workers/scanalyze-${service}"
  [[ -d "$context" ]] || die "missing build context: ${context}"
  [[ -f "${context}/Dockerfile" ]] || die "missing Dockerfile for ${service}"

  if [[ "$PUSH_IMAGES" == true ]]; then
    image_uri="${REGISTRY}/${ECR_PREFIX}/${service}:${TAG}"
  else
    image_uri="scanalyze-ci/${service}:${TAG}"
  fi

  log "Building ${service} as ${image_uri}"
  docker build \
    --platform linux/amd64 \
    --build-arg "BASE_IMAGE=${BASE_IMAGE}" \
    --label "org.opencontainers.image.source=${SOURCE_URL}" \
    --label "org.opencontainers.image.revision=${REVISION}" \
    --label "org.opencontainers.image.created=${CREATED}" \
    --tag "$image_uri" \
    "$context"

  if [[ "$PUSH_IMAGES" != true ]]; then
    log "Validated ${service} locally; no image was pushed."
    continue
  fi

  repository_name="${ECR_PREFIX}/${service}"
  log "Pushing ${service} with immutable tag ${TAG}"
  docker push "$image_uri"

  digest=""
  attempt=1
  while [[ "$attempt" -le 5 ]]; do
    digest="$(aws ecr describe-images \
      --repository-name "$repository_name" \
      --image-ids "imageTag=${TAG}" \
      --query 'imageDetails[0].imageDigest' \
      --output text 2>/dev/null || true)"
    if [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
      break
    fi
    sleep 2
    attempt=$((attempt + 1))
  done
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "ECR did not return a valid digest for ${service}"

  log "Verified ${service} digest ${digest}"

  if [[ "$WRITE_SSM" == true ]]; then
    write_release_metadata "$service" "$digest"
  fi
done

log "Completed ${#SERVICES_TO_BUILD[@]} service build(s)."
