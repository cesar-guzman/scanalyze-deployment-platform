#!/usr/bin/env bash
# Exercise the complete deployment DAG without credentials, provider plans, or AWS.

set -euo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly MANIFEST="${REPO_ROOT}/examples/deployments/synthetic-nonprod.yaml"
readonly VENV_BIN="${REPO_ROOT}/.venv/bin"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ -x "${VENV_BIN}/python3" ]] \
  || die "local virtual environment is missing; run make bootstrap-local first"
export PATH="${VENV_BIN}:${PATH}"

TMP_BASE="${TMPDIR:-/tmp}"
[[ -d "$TMP_BASE" ]] || die "temporary directory base does not exist: $TMP_BASE"
TMP_BASE="$(cd "$TMP_BASE" && pwd -P)"
case "$TMP_BASE" in
  "$REPO_ROOT"|"$REPO_ROOT"/*)
    die "temporary plan directory must be outside the repository"
    ;;
esac

PLAN_DIR="$(mktemp -d "${TMP_BASE%/}/scanalyze-release-dry-run.XXXXXX")" \
  || die "unable to create temporary plan directory"
trap 'rm -rf "$PLAN_DIR"' EXIT HUP INT TERM

# Keep this proof incapable of inheriting credentials or live-enablement flags.
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE
unset AWS_WEB_IDENTITY_TOKEN_FILE SCANALYZE_ALLOW_LIVE SCANALYZE_ALLOW_PROD

printf '[release-dry-run] Exercising all canonical layers with a temporary plan directory\n'
bash "${REPO_ROOT}/scripts/deployment/scanalyze-deploy.sh" plan-all \
  --manifest "$MANIFEST" \
  --plan-dir "$PLAN_DIR" \
  --dry-run
printf '[release-dry-run] Complete; temporary plan directory removed on exit\n'
