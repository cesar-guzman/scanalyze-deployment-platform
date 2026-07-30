#!/usr/bin/env bash
# Generate an SPDX 2.3 JSON SBOM for an immutable Scanalyze artifact.
set -euo pipefail
IFS=$'\n\t'

readonly IMAGE="${1:-}"
readonly OUTPUT="${2:-}"

if [[ ! "$IMAGE" =~ @sha256:[0-9a-f]{64}$ || -z "$OUTPUT" ]]; then
  echo "Usage: generate-sbom.sh <image@sha256:digest> <output-file>" >&2
  exit 2
fi
if ! command -v syft >/dev/null 2>&1; then
  echo "ERROR: required SBOM generator syft is unavailable" >&2
  exit 3
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required to validate SBOM evidence" >&2
  exit 3
fi

syft "$IMAGE" --output "spdx-json@2.3=${OUTPUT}"
[[ -s "$OUTPUT" ]] || { echo "ERROR: syft produced no SBOM evidence" >&2; exit 4; }
python3 -c 'import json, sys; document = json.load(open(sys.argv[1], encoding="utf-8")); assert document.get("spdxVersion") == "SPDX-2.3"' "$OUTPUT" || {
  echo "ERROR: syft output is not SPDX 2.3 JSON" >&2
  exit 4
}
echo "PASSED: SPDX SBOM evidence generated"
