# Frontend Configuration Reference

## Overview

Terraform is the single owner of the frontend `config.json`. This file is rendered by the `edge` Terraform layer and deployed to S3 behind CloudFront.

**Schema**: `schemas/frontend-config.schema.json`

## Ownership Rule

No manual editing of `config.json`. All values come from Terraform outputs of upstream layers.

## Validation

```bash
python scripts/deployment/validate-frontend-config.py /path/to/config.json
```
