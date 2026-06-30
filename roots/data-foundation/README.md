# Root: data-foundation

> **Layer**: 3  
> **Scope**: regional  
> **Module**: `modules/data-foundation`  
> **Consumes**: platform/v1  
> **Deployable**: true  
> **State key**: `{dep_id}/{region}/data-foundation/terraform.tfstate`

## Purpose

Deployment root for the data-foundation lifecycle. Calls `modules/data-foundation` and publishes its contract to SSM.

## M1 Constraints

- No terraform_remote_state
- No workspaces for customer isolation
- No hardcoded account IDs, ARNs, or bucket names
- No external modules
- No :latest image tags
- No timestamp()
- Contract gate uses `precondition` (never `check {}`)
