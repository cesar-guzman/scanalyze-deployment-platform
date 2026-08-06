# Module: edge

> **Layer**: 5a+  
> **Scope**: global  
> **Produces contract**: `edge/v2`
> **Consumes**: `edge-identity/v2`

## Purpose

Edge implementation for CloudFront, WAF, ACM, Route53, the shared frontend S3
origin, and the Terraform-owned public `frontend-config/v3` object. Its
Terraform root is `roots/edge`; this repository-only contract does not certify
the live deployment wrapper or authorize an apply.

## Files

| File | Purpose |
|---|---|
| `versions.tf` | Terraform and provider constraints |
| `variables.tf` | Typed, fail-closed contract inputs |
| `outputs.tf` | Contract and public runtime-config outputs |
| `locals.tf` | Layer metadata |
| `contract.tf` | Contract producer gate |
| `runtime_config.tf` | Canonical runtime-config rendering and exact S3 publication |
| `cloudfront.tf` | Edge routing and isolated no-store runtime-config behavior |

## Constraints

- Provider configuration is injected by the root
- No `terraform_remote_state`
- Runtime config contains public routing/identity metadata only and grants no authority
- API Gateway, Cognito, frontend origin, and upstream digest bindings fail closed
- All inputs/outputs schema-aligned
