# Identity Contract Reference

## Overview

The identity contract aligns Cognito configuration, JWT claims, authorization logic, and deployment binding into a single validated document.

**Schema**: `schemas/identity-contract.schema.json`

## Key Rules

1. **Deployment binding is enforced**: The JWT `custom:deployment_id` claim must match the running service's `DEPLOYMENT_ID`.
2. **Cross-account access is forbidden**: `restrictions.cross_account_access` must be `false`.
3. **Cross-deployment access is forbidden**: `restrictions.cross_deployment_access` must be `false`.
4. **No passwords in documentation**: `restrictions.password_in_docs` must be `false`.
5. **Customer ID source must be trusted**: Only `claim`, `client_id_map`, or `static` — never from untrusted request payload.
6. **Allowed domains are explicit**: Only `bank`, `personal`, `gov`.

## Authorization Modes

| Mode | Description |
|---|---|
| `cognito_jwt` | Default. JWT validation with Cognito User Pool. |
| `iam` | IAM-based authorization for service-to-service calls. |
| `api_key` | API key-based authorization (for external integrations). |

## Validation

```bash
python scripts/deployment/validate-identity-contract.py /path/to/contract.yaml
```
