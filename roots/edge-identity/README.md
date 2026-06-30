# Root: edge-identity

> **Layer**: 5a  
> **Scope**: regional  
> **Module**: `modules/edge-identity`  
> **Consumes**: services/v1,global/v1  
> **Deployable**: true  
> **State key**: `{dep_id}/{region}/edge-identity/terraform.tfstate`

## Purpose

Deployment root for the edge-identity lifecycle. Calls `modules/edge-identity` and publishes its contract to SSM.

## M1 Constraints

- No terraform_remote_state
- No workspaces for customer isolation
- No hardcoded account IDs, ARNs, or bucket names
- No external modules
- No :latest image tags
- No timestamp()
- Contract gate uses `precondition` (never `check {}`)
