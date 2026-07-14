# Deployment Manifest Reference

## Overview

A deployment manifest is a declarative YAML file that defines all the inputs needed to deploy Scanalyze for a specific customer in a specific AWS account.

It is not the GitOps request. A deployment request contains only non-sensitive
desired intent and may be reviewed in Git; the resolved manifest contains
account-specific bindings and always remains outside the repository. See
[`gitops-orchestrator.md`](gitops-orchestrator.md).

**Operational schema**: `schemas/deployment-manifest.v2.schema.json`
**Explicit legacy schema**: `schemas/deployment-manifest.schema.json`
**Synthetic example**: `examples/deployments/synthetic-nonprod.yaml`

## Rules

1. **Real manifests never enter Git.** Only synthetic examples with placeholder values are committed.
2. **Every field is validated** by `scripts/deployment/validate-manifest.py` before any operation.
3. **`latest` is forbidden.** Base images must be pinned by digest.
4. **Account ID `000000000000` is rejected.** Placeholder protection.
5. **ECR prefix must match deployment_id.** Cross-deployment image access is prevented.
6. **OIDC role ARN must match account_id.** Cross-account role assumption is prevented.
7. **Backend coordinates are forbidden in v2.** Bucket, key, KMS key, lock
   mechanism, and allowed account are derived from the approved registry,
   ACCOUNT_READY v2, execution lock, and canonical DAG.

## Schema Version

The `schema_version` field enables explicit evolution. Version `"2"` is the
only operational backend-authorization input. Version `"1"` remains parseable
for legacy inventory and migration analysis, but it is denied by the GUG-122
backend authorizer. There is no implicit conversion or fallback.

## Validation

```bash
# Validate a manifest
python scripts/deployment/validate-manifest.py /path/to/manifest.yaml

# Validate the synthetic example
python scripts/deployment/validate-manifest.py examples/deployments/synthetic-nonprod.yaml
```

## Creating a Real Manifest

1. Copy `examples/deployments/synthetic-nonprod.yaml` to a location **outside** the repository.
2. Replace all synthetic intent values with registry-issued assertions. Do not
   add Terraform backend coordinates.
3. Store securely (encrypted at rest, access-controlled).
4. Never commit to Git.
5. Pass to the orchestrator: `scanalyze-deploy.sh validate-manifest --manifest /path/to/real-manifest.yaml`

Do not pass a local manifest path through a GitHub workflow input. A future live
workflow resolves the approved manifest from access-controlled storage using the
Git-safe deployment request.
