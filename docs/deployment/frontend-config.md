# Frontend Configuration Reference

## Overview

Terraform is the single owner of the frontend `config.json`. This file is rendered by the `edge` Terraform layer and deployed to S3 behind CloudFront.

**Current schema**: `schemas/frontend-config.v2.schema.json`

The SPA accepts only v2. Missing, legacy, malformed, oversized, mixed-region,
identity-authoritative, or policy-conflicting configuration blocks startup.
There is no Vite environment or local endpoint fallback. `customer_id` and
`deployment_id` are deployment/display bindings only; they never establish
backend authority.

## Ownership Rule

No manual editing of `config.json`. All values come from Terraform outputs of upstream layers.

The source repository never tracks `public/config.json`. A deployment publishes
the reviewed runtime document alongside an immutable frontend artifact in a
separately authorized workflow.

## Validation

```bash
python scripts/deployment/validate-frontend-config.py /path/to/config.json
```
