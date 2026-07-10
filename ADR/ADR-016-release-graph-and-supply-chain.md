# ADR-016: Release Graph and OCI Supply Chain

- **Status**: Accepted
- **Date**: 2026-07-10

## Context

Scanalyze delivers 7 OCI images per release. There was no formal record of what commit, tag, digest, base image, scan result, and signature status corresponds to each service in a release.

## Decision

1. **Release Graph**: `scripts/supply-chain/release-graph.py` generates a JSON document recording the full lineage of every image in a release.
2. **SBOM**: `generate-sbom.sh` generates SBOMs using syft (SPDX format). SKIPPED if syft is not installed.
3. **Scan**: `scan-image.sh` scans images using trivy. SKIPPED if trivy is not installed.
4. **Sign**: `sign-image.sh` signs images using cosign (keyless/Sigstore). SKIPPED if cosign is not installed.
5. **Verify**: `verify-image.sh` verifies image signatures. SKIPPED if cosign is not installed.

All scripts are tolerant of missing tools (report SKIPPED, not FAIL) to support local development. For release policy, tool availability can be enforced by CI.

## Consequences

- Every release has a traceable supply chain record.
- Tool availability is reported, not assumed.
- CI can enforce tool requirements; local dev is not blocked.
