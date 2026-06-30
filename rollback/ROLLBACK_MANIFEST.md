# Rollback Manifest — M2 Level A

> **Purpose**: Manifest-based rollback for M0+M1+M2 scaffold and declarations.
> All changes are additive within `scanalyze-deployment-platform/`.
> No files outside this repository were modified.
> No AWS resources were created (all declarations are `authored_not_provider_validated`).

## Verification Before Rollback

1. Confirm all paths listed below are under `scanalyze-deployment-platform/`.
2. Confirm brownfield `scanalyze-micros/` is intact (no files were modified).
3. Confirm no git push has occurred.
4. Confirm no `terraform apply` was executed.

## Rollback Procedure

1. Review this manifest to confirm scope.
2. Remove or revert only the paths listed below.
3. Do NOT use `git stash`, `git reset`, `git clean`, `git checkout -- .`, or `rm -rf`.
4. To revert to M1: remove only M2-added paths (see M2 Additions section).
5. To revert to M0: remove M1+M2 paths.
6. To revert completely: remove all listed paths.
7. Verify that brownfield remains intact after removal.

## M0 Foundation Paths

All paths relative to `scanalyze-deployment-platform/`:

### Core Configuration
- `pyproject.toml`
- `Makefile`
- `.gitignore`
- `.tool-versions`
- `.terraform-version`
- `required-artifacts.yaml`
- `sentinel_allowlist.yaml`

### ADR Documents
- `ADR/` — 12 imported ADRs + SOURCE_MANIFEST.json

### Schemas
- `schemas/` — 16 JSON Schema files

### Fixtures
- `fixtures/valid/` — 15 valid fixtures
- `fixtures/invalid/` — 8 invalid fixtures

### Policies
- `policies/iam/` — 10 IAM role policies
- `policies/trust/` — 6 trust policies
- `policies/s3/` — 4 S3 bucket policies
- `policies/kms/` — 3 KMS key policies
- `session-policies/` — 8 session policies

### Tooling (M0)
- `tooling/validate_schema.py`
- `tooling/validate_policy.py`
- `tooling/validate_digest.py`
- `tooling/security_sentinel.py`
- `tooling/check_required_artifacts.py`
- `tooling/__init__.py`

### Tests (M0)
- `tests/test_account_ready/`
- `tests/preconditions/contract_gate/`

### Reports (M0)
- `reports/` — discrepancy register, patch reports

## M1 Additions

### Module Skeletons
- `modules/global/` — README.md, versions.tf, variables.tf, outputs.tf, locals.tf, contract.tf
- `modules/network/` — same structure
- `modules/container-platform/` — same structure
- `modules/data-foundation/` — same structure
- `modules/services/` — same structure
- `modules/edge-identity/` — same structure
- `modules/edge/` — same structure
- `modules/addons/` — same structure
- `modules/replicated-data/` — same structure

### Root Skeletons
- `roots/account-ready-gate/`
- `roots/global/`
- `roots/network/`
- `roots/platform/`
- `roots/data-foundation/`
- `roots/services/`
- `roots/edge-identity/`
- `roots/edge/`
- `roots/addons/`

### Contract Framework
- `contracts/` — contract schemas and definitions
- `tests/preconditions/layer_contract_matrix/` — HCL harness + runner

### Tooling (M1)
- `tooling/lint_forbidden_patterns.py`

### Tests (M1)
- `tests/test_supply_chain/`
- `tests/test_task_definitions/`

## M2 Level A Additions

### Module Resource Declarations (authored_not_provider_validated)
- `modules/global/iam.tf` — workload IAM roles, permissions boundary
- `modules/global/locals_ownership.tf` — ownership guard documentation
- `modules/network/vpc.tf` — VPC, subnets, NAT, IGW, routes
- `modules/network/endpoints.tf` — VPC endpoints
- `modules/network/security_groups.tf` — base SGs
- `modules/container-platform/ecs.tf` — ECS cluster
- `modules/container-platform/alb.tf` — internal ALB
- `modules/data-foundation/dynamodb.tf` — documents + jobs tables
- `modules/data-foundation/sqs.tf` — per-worker queues + DLQs
- `modules/data-foundation/s3.tf` — document storage bucket
- `modules/data-foundation/kms.tf` — application data KMS key
- `modules/services/ecs_services.tf` — ECS services + task definitions
- `modules/edge-identity/cognito.tf` — user pool, clients, resource server
- `modules/edge-identity/api_gateway.tf` — HTTP API, JWT authorizer, VPC link
- `modules/edge/cloudfront.tf` — distribution + OAC
- `modules/edge/waf.tf` — WAF CLOUDFRONT scope
- `modules/edge/acm.tf` — ACM certificate
- `modules/edge/route53.tf` — DNS records
- `modules/addons/cloudwatch.tf` — dashboard, alarms, log groups
- `modules/addons/dlq_monitoring.tf` — DLQ depth alarms, SNS topic

### Updated Module Interfaces (variables.tf/outputs.tf updated with resource refs)
- All 8 M2 modules had variables.tf and outputs.tf rewritten with real references

### Tooling (M2)
- `tooling/lint_module_ownership.py` — global ownership boundary linter
- `tooling/lint_edge_split.py` — edge-identity/edge split linter
- `tooling/lint_services_ownership.py` — services task-def ownership linter
- `tooling/check_module_interfaces.py` — static interface completeness check

### Reports (M2)
- `reports/m2-final-report.md`
- `reports/platform-v2-discrepancy-register.md` (updated)

## Explicitly NOT Modified

- `scanalyze-micros/` — brownfield, untouched
- System Python / Terraform installations
- Any AWS resources
- Any git remote state

## Post-Rollback Verification

```bash
# Confirm brownfield is intact
ls -la ../scanalyze-micros/

# Confirm no .terraform dirs remain
find . -name '.terraform' -type d

# Confirm no .tfstate files
find . -name '*.tfstate'

# Confirm no .env files
find . -name '.env'
```
