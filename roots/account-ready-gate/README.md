# Root: account-ready-gate

> **Layer**: pre  
> **Scope**: global  
> **Module**: `modules/none`  
> **Consumes**: account-ready  
> **Deployable**: false  
> **State key**: `{dep_id}/account-ready-gate/terraform.tfstate`

## Purpose

Validation-only root that consumes the ACCOUNT_READY contract and verifies preconditions fail-closed. Does not create resources, produce contracts, or own state backend.

## M1 Constraints

- No terraform_remote_state
- No workspaces for customer isolation
- No hardcoded account IDs, ARNs, or bucket names
- No external modules
- No :latest image tags
- No timestamp()
- Contract gate uses `precondition` (never `check {}`)
