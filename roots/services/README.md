# Root: services

> **Layer**: 4  
> **Scope**: regional  
> **Module**: `modules/services`  
> **Consumes**: data-foundation/v2
> **Deployable**: true  
> **State key**: `{dep_id}/{region}/services/terraform.tfstate`

## Purpose

Deployment root for the services lifecycle. Calls `modules/services` and publishes its contract to SSM.

## M1 Constraints

- No terraform_remote_state
- No workspaces for customer isolation
- No hardcoded account IDs, ARNs, or bucket names
- No external modules
- No :latest image tags
- No timestamp()
- Contract gate uses `precondition` (never `check {}`)
