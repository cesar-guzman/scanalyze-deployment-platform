# Root: global

> **Layer**: 0  
> **Scope**: global  
> **Module**: `modules/global`  
> **Consumes**: account-ready  
> **Deployable**: true  
> **State key**: `{dep_id}/global/terraform.tfstate`

## Purpose

Deployment root for the global lifecycle. Calls `modules/global` and publishes its contract to SSM.

## M1 Constraints

- No terraform_remote_state
- No workspaces for customer isolation
- No hardcoded account IDs, ARNs, or bucket names
- No external modules
- No :latest image tags
- No timestamp()
- Contract gate uses `precondition` (never `check {}`)
