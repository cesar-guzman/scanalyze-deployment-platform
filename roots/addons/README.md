# Root: addons

> **Layer**: 5b  
> **Scope**: regional  
> **Module**: `modules/addons`  
> **Consumes**: all upstream  
> **Deployable**: true  
> **State key**: `{dep_id}/{region}/addons/terraform.tfstate`

## Purpose

Deployment root for the addons lifecycle. Calls `modules/addons` and publishes its contract to SSM.

## M1 Constraints

- No terraform_remote_state
- No workspaces for customer isolation
- No hardcoded account IDs, ARNs, or bucket names
- No external modules
- No :latest image tags
- No timestamp()
- Contract gate uses `precondition` (never `check {}`)
