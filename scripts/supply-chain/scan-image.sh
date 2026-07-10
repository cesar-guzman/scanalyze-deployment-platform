#!/usr/bin/env bash
# scan-image.sh — Scan a Scanalyze service image for vulnerabilities
# Requires: trivy (https://github.com/aquasecurity/trivy)
set -euo pipefail
IMAGE="${1:-}"
if [[ -z "$IMAGE" ]]; then echo "Usage: scan-image.sh <image> [output-file]"; exit 2; fi
if ! command -v trivy &>/dev/null; then
  echo "SKIPPED: trivy is not installed"
  echo "  Install: https://github.com/aquasecurity/trivy#installation"
  exit 0
fi
OUTPUT="${2:-}"
if [[ -n "$OUTPUT" ]]; then
  trivy image --format json --output "$OUTPUT" "$IMAGE"
  echo "PASSED: Scan results at $OUTPUT"
else
  trivy image "$IMAGE"
fi
