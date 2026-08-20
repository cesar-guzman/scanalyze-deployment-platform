# Root: account-ready-gate

> **Layer**: pre  
> **Scope**: regional
> **Module**: `modules/none`  
> **Consumes**: `account-ready/v2`
> **Deployable**: false  
> **State key**: none

## Purpose

Validation-only root that consumes an externally produced and independently
anchored `ACCOUNT_READY v2` contract. The Python verifier first validates the
complete eight-role, state-infrastructure, control, tuple, and digest evidence;
this root then binds its identity/digest projection to the deployment registry.

The root does not create baseline resources, produce contracts, own state, or
permit apply/destroy. Account baseline creation remains exclusively owned by
the external AccountVendingProvider.

## M1 Constraints

- No terraform_remote_state
- No workspaces for customer isolation
- No hardcoded account IDs, ARNs, or bucket names
- No external modules
- No :latest image tags
- No timestamp()
- Contract gate uses `precondition` (never `check {}`)
- Only schema version `2` is accepted; v1 has no compatibility fallback
