#!/usr/bin/env bash
# Sign an immutable image and persist its verification bundle.
set -euo pipefail
IFS=$'\n\t'

readonly IMAGE="${1:-}"
readonly FLAG="${2:-}"
readonly BUNDLE="${3:-}"

if [[ ! "$IMAGE" =~ @sha256:[0-9a-f]{64}$ || "$FLAG" != "--bundle" || -z "$BUNDLE" ]]; then
  echo "Usage: sign-image.sh <image@sha256:digest> --bundle <bundle-file>" >&2
  exit 2
fi
if ! command -v cosign >/dev/null 2>&1; then
  echo "ERROR: required signer cosign is unavailable" >&2
  exit 3
fi

cosign sign --yes --bundle "$BUNDLE" "$IMAGE"
[[ -s "$BUNDLE" ]] || { echo "ERROR: cosign produced no signature bundle" >&2; exit 4; }
echo "PASSED: immutable image signature bundle generated"
