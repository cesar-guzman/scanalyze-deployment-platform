# Module: services

> **Layer**: 4  
> **Scope**: regional  
> **Produces contract**: `services/v1`  
> **Consumes**: data-foundation/v1

## Purpose

Interface skeleton for the services layer. M1 does not implement production
AWS resources — this module defines the typed input/output interface that
the root skeleton (`roots/servicesservices`) will call.

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
