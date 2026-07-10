# Supply Chain Reference

## Overview

Scanalyze implements an OCI supply chain that records the full lineage of every image in a release. The supply chain tools are optional for local development but required for release policy compliance.

## Tools

| Tool | Purpose | Required for |
|---|---|---|
| syft | SBOM generation (SPDX format) | Release policy |
| trivy | Vulnerability scanning | Release policy |
| cosign | Image signing (keyless/Sigstore) | Release policy |

## Scripts

| Script | Purpose |
|---|---|
| `scripts/supply-chain/generate-sbom.sh` | Generate SBOM for a service image |
| `scripts/supply-chain/scan-image.sh` | Scan image for vulnerabilities |
| `scripts/supply-chain/sign-image.sh` | Sign image with cosign |
| `scripts/supply-chain/verify-image.sh` | Verify image signature |
| `scripts/supply-chain/release-graph.py` | Generate release graph JSON |

## Behavior When Tools Are Missing

All scripts report `SKIPPED` with a reason when the required tool is not installed. This allows local development to proceed without blocking on tool installation.

In CI, tool availability can be enforced by installing them in the workflow.

## Release Graph

The release graph (`release-graph.py`) generates a JSON document with:
- `schema_version`: For forward compatibility
- `deployment_id`: Which deployment this release targets
- `commit`: Git commit SHA
- `release_tag`: Image tag
- `services[]`: Per-service lineage (digest, scan status, signature status)
- `supply_chain_tools`: Availability of cosign, syft, trivy

## Usage

```bash
# Dry-run (no AWS, no tools required)
python scripts/supply-chain/release-graph.py --dry-run

# Full release graph (requires tools + ECR access)
python scripts/supply-chain/release-graph.py \
  --no-dry-run \
  --deployment-id dep_01SYNTH3T1CABC0XAMP0EHABCD \
  --commit abc123 \
  --tag sha-abc123def456 \
  --ecr-prefix dep-01synth3t1cabc0xamp0ehabcd/scanalyze \
  --output /path/outside/repo/release-graph.json
```
