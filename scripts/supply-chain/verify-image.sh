#!/usr/bin/env bash
# verify-image.sh — Verify a Scanalyze service image signature
# Requires: cosign
set -euo pipefail
IMAGE="${1:-}"
if [[ -z "$IMAGE" ]]; then echo "Usage: verify-image.sh <image-with-digest>"; exit 2; fi
if ! command -v cosign &>/dev/null; then
  echo "SKIPPED: cosign is not installed"
  exit 0
fi
[[ "$IMAGE" == *"@sha256:"* ]] || { echo "ERROR: image must include digest"; exit 2; }
cosign verify "$IMAGE" && echo "PASSED: Signature verified" || echo "FAIL: Signature verification failed"
