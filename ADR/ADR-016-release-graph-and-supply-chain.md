# ADR-016: Release Graph and OCI Supply Chain

- **Status**: Superseded by ADR-032
- **Date**: 2026-07-10

## Context

Scanalyze delivers 7 OCI images per release. There was no formal record of what commit, tag, digest, base image, scan result, and signature status corresponds to each service in a release.

## Decision

1. **Historical release graph**: the original script recorded status-only image lineage. ADR-032 limits it to a planning-only inventory that cannot authorize promotion.
2. **SBOM**: the current wrapper requires Syft and a non-empty SPDX output or fails.
3. **Scan**: the current wrapper requires Trivy and fails on missing evidence or blocking findings.
4. **Sign**: the current wrapper requires Cosign, an immutable digest, and a persisted signature bundle.
5. **Verify**: the current wrapper requires Cosign, an exact issuer and identity, and propagates verification failures.

The original fail-open tool behavior is prohibited by ADR-032. Missing evidence tooling now returns a non-zero status, and planning inventories are explicitly ineligible for promotion.

## Consequences

- Every release has a traceable supply chain record.
- Tool availability is reported, not assumed.
- CI can enforce tool requirements; local dev is not blocked.
