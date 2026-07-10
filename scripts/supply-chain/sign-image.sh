#!/usr/bin/env bash
# sign-image.sh — Sign a Scanalyze service image with cosign
# Requires: cosign (https://github.com/sigstore/cosign)
set -euo pipefail
IMAGE="${1:-}"
if [[ -z "$IMAGE" ]]; then echo "Usage: sign-image.sh <image-with-digest>"; exit 2; fi
if ! command -v cosign &>/dev/null; then
  echo "SKIPPED: cosign is not installed"
  echo "  Install: https://github.com/sigstore/cosign#installation"
  exit 0
fi
[[ "$IMAGE" == *"@sha256:"* ]] || { echo "ERROR: image must include digest (@sha256:...)"; exit 2; }
cosign sign --yes "$IMAGE"
echo "PASSED: Image signed: $IMAGE"
