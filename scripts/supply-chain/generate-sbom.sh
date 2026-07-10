#!/usr/bin/env bash
# generate-sbom.sh — Generate SBOM for a Scanalyze service image
# Requires: syft (https://github.com/anchore/syft)
# If syft is not installed, reports SKIPPED with reason.
set -euo pipefail

IMAGE="${1:-}"
OUTPUT="${2:-}"

if [[ -z "$IMAGE" ]]; then
  echo "Usage: generate-sbom.sh <image> [output-file]"
  echo "  If syft is not installed, reports SKIPPED."
  exit 2
fi

if ! command -v syft &>/dev/null; then
  echo "SKIPPED: syft is not installed"
  echo "  Install: https://github.com/anchore/syft#installation"
  echo "  SBOM generation is optional for local/dev; required for release policy."
  exit 0
fi

if [[ -n "$OUTPUT" ]]; then
  syft "$IMAGE" -o spdx-json="$OUTPUT"
  echo "PASSED: SBOM generated at $OUTPUT"
else
  syft "$IMAGE" -o spdx-json
fi
