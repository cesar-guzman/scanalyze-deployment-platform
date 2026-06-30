# Root: network

> **Layer**: 1  
> **Scope**: regional  
> **Module**: `modules/network`  
> **Consumes**: global/v1  
> **Deployable**: true  
> **State key**: `{dep_id}/{region}/network/terraform.tfstate`

## Purpose

Deployment root for the network lifecycle. Calls `modules/network` and publishes its contract to SSM.

## M1 Constraints

- No terraform_remote_state
- No workspaces for customer isolation
- No hardcoded account IDs, ARNs, or bucket names
- No external modules
- No :latest image tags
- No timestamp()
- Contract gate uses `precondition` (never `check {}`)
