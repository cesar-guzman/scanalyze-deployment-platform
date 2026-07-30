#!/usr/bin/env bash
# Scan an immutable Scanalyze image and fail on HIGH or CRITICAL findings.
set -euo pipefail
IFS=$'\n\t'

readonly IMAGE="${1:-}"
readonly OUTPUT="${2:-}"

if [[ ! "$IMAGE" =~ @sha256:[0-9a-f]{64}$ || -z "$OUTPUT" ]]; then
  echo "Usage: scan-image.sh <image@sha256:digest> <output-file>" >&2
  exit 2
fi
if ! command -v trivy >/dev/null 2>&1; then
  echo "ERROR: required vulnerability scanner trivy is unavailable" >&2
  exit 3
fi

trivy image \
  --exit-code 1 \
  --severity HIGH,CRITICAL \
  --format json \
  --output "$OUTPUT" \
  "$IMAGE"
[[ -s "$OUTPUT" ]] || { echo "ERROR: trivy produced no scan evidence" >&2; exit 4; }
echo "PASSED: vulnerability evidence generated with no blocking findings"
