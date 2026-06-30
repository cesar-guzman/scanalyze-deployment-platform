# Root: platform

> **Layer**: 2  
> **Scope**: regional  
> **Module**: `modules/container-platform`  
> **Consumes**: network/v1  
> **Deployable**: true  
> **State key**: `{dep_id}/{region}/platform/terraform.tfstate`

## Purpose

Deployment root for the platform lifecycle. Calls `modules/container-platform` and publishes its contract to SSM.

## M1 Constraints

- No terraform_remote_state
- No workspaces for customer isolation
- No hardcoded account IDs, ARNs, or bucket names
- No external modules
- No :latest image tags
- No timestamp()
- Contract gate uses `precondition` (never `check {}`)
