# Module: replicated-data

> **Layer**: sub  
> **Scope**: regional  
> **Produces contract**: `none`  
> **Consumes**: data-foundation internal

## Purpose

Interface skeleton for the replicated-data layer. M1 does not implement production
AWS resources — this module defines the typed input/output interface that
the root skeleton (`roots/replicated-datareplicated-data`) will call.

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
