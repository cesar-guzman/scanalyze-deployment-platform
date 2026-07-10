# SSM Contracts Reference

## Overview

SSM Parameter Store is the inter-layer contract mechanism for Scanalyze. Each Terraform layer writes its outputs to SSM parameters and reads its inputs from SSM parameters written by upstream layers.

**Schema**: `schemas/ssm-contract.schema.json`

## Contract Rules

1. **One producer per parameter.** Each SSM parameter has exactly one layer that writes it.
2. **One or more consumers.** Any layer may read from any upstream parameter.
3. **Path convention**: `/<deployment_id>/layers/<layer>/outputs/<key>`
4. **Fail closed**: If a required upstream parameter is missing, the downstream layer must fail.
5. **No cross-deployment access**: Parameters are scoped to `/<deployment_id>/`.

## Layer Dependency Order

```
account-ready-gate → global → network → platform → data-foundation →
  edge-identity → edge → cicd → services → addons
```

Each layer may only consume parameters from layers to its left.

## Existing Contracts (from `modules/container-platform/ssm_contracts.tf`)

| SSM Path | Producer | Type | Consumers |
|---|---|---|---|
| `/<dep>/layers/platform/outputs/ecs_cluster_arn` | platform | String | services, cicd |
| `/<dep>/layers/platform/outputs/ecs_cluster_name` | platform | String | services, cicd |
| `/<dep>/layers/platform/outputs/ecs_task_execution_role_arn` | platform | String | services |
| `/<dep>/layers/platform/outputs/alb_arn` | platform | String | services, edge |
| `/<dep>/layers/platform/outputs/alb_listener_arn` | platform | String | services |
| `/<dep>/layers/platform/outputs/alb_dns_name` | platform | String | edge |
| `/<dep>/layers/platform/outputs/alb_security_group_id` | platform | String | services |

## Validation

```bash
python scripts/deployment/validate-ssm-contracts.py /path/to/contract.yaml
```
