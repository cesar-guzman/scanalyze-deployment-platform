# M2 Level A — Final Report

> **Date**: 2026-06-30  
> **Branch**: feature/platform-v2-repository-bootstrap  
> **Status**: M2_LOCAL_EVIDENCE_GENERATED  
> **All declarations**: authored_not_provider_validated

---

## Scope

M2 Level A implements local Terraform resource declarations for all 8 operational modules. No AWS provider was downloaded, no `terraform init` with provider, no `terraform plan` against AWS, and no `terraform apply` was executed.

## Modules Implemented

| Module | Resources | Files | Vars | Status |
|--------|-----------|-------|------|--------|
| global | ECS execution role, per-service workload roles, permissions boundary | iam.tf, locals_ownership.tf | 7 | interface_complete |
| network | VPC, subnets (AZ ID), NATs, IGW, routes, VPC endpoints, SGs | vpc.tf, endpoints.tf, security_groups.tf | 11 | interface_complete |
| container-platform | ECS cluster (Fargate+Insights), internal ALB, HTTPS listener | ecs.tf, alb.tf | 11 | interface_complete |
| data-foundation | DynamoDB (documents+jobs), SQS (6 workers × 2), S3 docs bucket, KMS | dynamodb.tf, sqs.tf, s3.tf, kms.tf | 7 | interface_complete |
| services | ECS services + task definitions (Terraform sole owner, @sha256 enforced) | ecs_services.tf | 15 | interface_complete |
| edge-identity | Cognito (user pool, SPA PKCE, M2M), API GW HTTP API, JWT authorizer | cognito.tf, api_gateway.tf | 17 | interface_complete |
| edge | CloudFront, WAF CLOUDFRONT, ACM us-east-1, Route53, OAC | cloudfront.tf, waf.tf, acm.tf, route53.tf | 12 | interface_complete |
| addons | CloudWatch dashboard, CPU alarms, DLQ alarms, log groups, SNS | cloudwatch.tf, dlq_monitoring.tf | 9 | interface_complete |
| replicated-data | M1 skeleton only | — | — | skeleton_m1 |

## Ownership Boundaries Enforced

| Boundary | Linter | Status |
|----------|--------|--------|
| global/ no baseline resources | lint_module_ownership.py | ✅ PASS |
| edge-identity (regional) vs edge (global) | lint_edge_split.py | ✅ PASS |
| services task-def ownership | lint_services_ownership.py | ✅ PASS |
| module interface completeness | check_module_interfaces.py | ✅ 8/8 PASS |

## Validation Evidence

| Check | Command | Result |
|-------|---------|--------|
| M0 gate | `make preflight-m0` | ✅ PASS |
| Module skeletons | `make module-check` | ✅ 9/9 |
| Root skeletons | `make root-check` | ✅ PASS |
| Task-def schema | `make taskdef-check` | ✅ PASS |
| Supply chain | `make supply-chain-check` | ✅ 13/13 |
| Module ownership | `make module-ownership-check` | ✅ PASS |
| Edge split | `make edge-split-check` | ✅ PASS |
| Services ownership | `make services-ownership-check` | ✅ PASS |
| Module interfaces | `make module-interface-check` | ✅ 8/8 |
| Terraform fmt | `make terraform-fmt-check` | ✅ PASS |
| Contract matrix | `make contract-matrix` | ✅ 90/90 |
| All tests | `pytest tests/ -v` | ✅ 51/51 |
| Git safety | `make git-safety` | ✅ PASS |
| Security sentinel | `make security-check` | ✅ 0 findings (5 allowlisted) |
| **Aggregate** | **`make preflight-m2`** | **✅ PASS** |

## Toolchain Status

| Tool | Pinned | Actual | Match |
|------|--------|--------|-------|
| Python | 3.11.12 | 3.11.14 | ⚠ Minor patch mismatch |
| Terraform | 1.12.1 | 1.14.6 | ⚠ Minor version mismatch |

Both mismatches block any promotion beyond `authored_not_provider_validated`.

## Contract Matrix Expansion (M2)

M2 expanded the HCL contract harness from 73 to 90 scenarios:

| Category | Scenarios Added |
|----------|----------------|
| Release manifest digest value-match | stale-release-manifest-digest, missing-expected-release-digest |
| Unknown critical field detection | unknown-critical-field, unknown-non-allowlisted-field, allowed-extension-field |

New preconditions added:
- `expected_release_manifest_digest` — fail-closed if empty, value-match required
- `contract_raw_json` + `allowed_contract_keys` — unknown field detection with allowlist

## Active Discrepancies

| ID | Description | Severity | Blocks |
|----|-------------|----------|--------|
| D-001 | Terraform 1.14.6 vs pin 1.12.1 | ⚠ Warning | provider_validated, verified_in_aws |
| D-001b | Python 3.11.14 vs pin 3.11.12 | ℹ Low | — |
| D-002 | All declarations authored_not_provider_validated | ⚠ Expected | provider_validated |
| D-003 | Roots not wired to M2 module interfaces | ℹ Info | terraform plan |
| D-004 | replicated-data still M1 skeleton | ℹ Info | — |

## Rollback

Rollback is manifest-based only. See `rollback/ROLLBACK_MANIFEST.md`.

Prohibited rollback mechanisms:
- ❌ `git stash`
- ❌ `git reset`
- ❌ `git clean`
- ❌ `git checkout -- .`
- ❌ `rm -rf`

## Files Created/Modified in M2

### New Files (23)
- 20 resource .tf files across 8 modules
- 3 linter scripts in tooling/
- 1 interface checker in tooling/

### Modified Files (28)
- 8 modules × variables.tf + outputs.tf (16)
- Makefile (M2 targets + preflight-m2)
- Contract harness main.tf + run_matrix.sh
- Rollback manifest
- Discrepancy register
- Various module locals.tf (fmt)

### Prohibited Artifacts Verification

| Artifact | Staged? |
|----------|---------|
| .venv/ | ❌ No (in .gitignore) |
| __pycache__/ | ❌ No (in .gitignore) |
| .pytest_cache/ | ❌ No (in .gitignore) |
| .terraform/ | ❌ No (cleaned + in .gitignore) |
| *.tfstate | ❌ No |
| *.tfplan | ❌ No |
| .env | ❌ No |
| Provider/plugin caches | ❌ No |
| Files outside scanalyze-deployment-platform/ | ❌ No |
| Brownfield files | ❌ No |
