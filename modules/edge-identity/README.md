# Module: edge-identity

> **Layer**: 5a  
> **Scope**: regional  
> **Produces contract**: `edge-identity/v1`  
> **Consumes**: services/v1,global/v1

## Purpose

Interface skeleton for the edge-identity layer. M1 does not implement production
AWS resources — this module defines the typed input/output interface that
the root skeleton (`roots/edge-identityedge-identity`) will call.

## Files

| File | Purpose |
|---|---|
| `versions.tf` | Terraform version constraint (no provider) |
| `variables.tf` | Typed inputs aligned with M0 schemas |
| `outputs.tf` | Contract-aligned outputs |
| `locals.tf` | Layer metadata |
| `contract.tf` | Contract producer gate |

## M1 Constraints

- No production AWS resources
- No provider configuration (injected by root)
- Interface-only skeleton
- All inputs/outputs schema-aligned
