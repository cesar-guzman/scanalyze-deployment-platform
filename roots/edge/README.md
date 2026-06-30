# Root: edge

> **Layer**: 5a+  
> **Scope**: global  
> **Module**: `modules/edge`  
> **Consumes**: edge-identity/v1  
> **Deployable**: true  
> **State key**: `{dep_id}/edge/terraform.tfstate`

## Purpose

Deployment root for the edge lifecycle. Calls `modules/edge` and publishes its contract to SSM.

## M1 Constraints

- No terraform_remote_state
- No workspaces for customer isolation
- No hardcoded account IDs, ARNs, or bucket names
- No external modules
- No :latest image tags
- No timestamp()
- Contract gate uses `precondition` (never `check {}`)
