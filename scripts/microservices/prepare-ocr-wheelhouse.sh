#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SERVICE_DIR="${REPO_ROOT}/backend/workers/scanalyze-ocr-worker"
LOCK_FILE="${SERVICE_DIR}/requirements.lock"
WHEELHOUSE_DIR="${SERVICE_DIR}/.wheelhouse"
MARKER_FILE="${WHEELHOUSE_DIR}/.gug291-wheelhouse"
OCR_PYTHON_BIN="${OCR_PYTHON_BIN:-python3.11}"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 2
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  else
    die "sha256sum or shasum is required"
  fi
}

command -v "$OCR_PYTHON_BIN" >/dev/null 2>&1 || die "Python 3.11.14 is required"
[[ "$($OCR_PYTHON_BIN --version 2>&1)" == "Python 3.11.14" ]] ||
  die "wheelhouse preparation requires Python 3.11.14"
[[ -f "$LOCK_FILE" ]] || die "missing lock file: ${LOCK_FILE}"

lock_digest="$(sha256_file "$LOCK_FILE")"
expected_marker="$(printf 'lock_sha256=%s\ntarget=linux/amd64\npython=3.11.14' "$lock_digest")"
temporary_dir="$(mktemp -d "${SERVICE_DIR}/.wheelhouse.tmp.XXXXXX")"

cleanup() {
  if [[ -n "${temporary_dir:-}" && -d "$temporary_dir" ]]; then
    find "$temporary_dir" -depth -delete
  fi
}
trap cleanup EXIT HUP INT TERM

PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 \
  "$OCR_PYTHON_BIN" -m pip download \
    --dest "$temporary_dir" \
    --require-hashes \
    --only-binary=:all: \
    --platform manylinux2014_x86_64 \
    --python-version 3.11 \
    --implementation cp \
    --abi cp311 \
    --requirement "$LOCK_FILE"

wheel_count="$(find "$temporary_dir" -maxdepth 1 -type f -name '*.whl' | wc -l | tr -d ' ')"
[[ "$wheel_count" == "11" ]] || die "expected 11 locked wheels, found ${wheel_count}"
if find "$temporary_dir" -maxdepth 1 -type l | grep -q .; then
  die "wheelhouse must not contain symbolic links"
fi

printf '%s\n' "$expected_marker" > "${temporary_dir}/.gug291-wheelhouse"

if [[ -e "$WHEELHOUSE_DIR" ]]; then
  [[ -d "$WHEELHOUSE_DIR" && -f "$MARKER_FILE" ]] ||
    die "refusing to replace an unrecognized wheelhouse path"
  [[ "$(wc -l < "$MARKER_FILE" | tr -d ' ')" == "3" ]] ||
    die "refusing to replace a wheelhouse with an invalid marker"
  grep -Eq '^lock_sha256=[0-9a-f]{64}$' "$MARKER_FILE" ||
    die "refusing to replace a wheelhouse with an invalid lock marker"
  grep -qx 'target=linux/amd64' "$MARKER_FILE" ||
    die "refusing to replace a wheelhouse for another target"
  grep -qx 'python=3.11.14' "$MARKER_FILE" ||
    die "refusing to replace a wheelhouse for another Python runtime"
  find "$WHEELHOUSE_DIR" -depth -delete
fi

mv "$temporary_dir" "$WHEELHOUSE_DIR"
temporary_dir=""
printf 'Prepared %s verified wheels for linux/amd64 CPython 3.11.14.\n' "$wheel_count"
