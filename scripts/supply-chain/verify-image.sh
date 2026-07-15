#!/usr/bin/env bash
# Verify an immutable image with an exact OIDC issuer and signing identity.
set -euo pipefail
IFS=$'\n\t'

IMAGE="${1:-}"
shift || true
BUNDLE=""
IDENTITY=""
ISSUER=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bundle)
      BUNDLE="${2:-}"
      shift 2
      ;;
    --certificate-identity)
      IDENTITY="${2:-}"
      shift 2
      ;;
    --certificate-oidc-issuer)
      ISSUER="${2:-}"
      shift 2
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! "$IMAGE" =~ @sha256:[0-9a-f]{64}$ || -z "$BUNDLE" || -z "$IDENTITY" || -z "$ISSUER" ]]; then
  echo "Usage: verify-image.sh <image@sha256:digest> --bundle <file> --certificate-identity <uri> --certificate-oidc-issuer <uri>" >&2
  exit 2
fi
if ! command -v cosign >/dev/null 2>&1; then
  echo "ERROR: required verifier cosign is unavailable" >&2
  exit 3
fi

cosign verify \
  --bundle "$BUNDLE" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE"
echo "PASSED: signature, claims, issuer, identity, and image digest verified"
