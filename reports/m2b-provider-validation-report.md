# M2 Level B — Provider Validation Report

> **Date**: 2026-07-02  
> **Branch**: feature/platform-v2-repository-bootstrap  
> **Status**: M2B_PROVIDER_VALIDATED_LOCALLY  
> **All declarations**: provider_validated_locally

---

## Scope

M2 Level B validates all M2 Level A Terraform declarations against the real AWS provider schema, without backend, credentials, `terraform plan`, or `terraform apply`.

## Provider Version

| Field | Value |
|-------|-------|
| **Provider** | hashicorp/aws |
| **Version** | 5.100.0 |
| **Constraint** | ~> 5.80 |
| **Lock file** | .terraform.lock.hcl committed per root |
| **Source** | registry.terraform.io/hashicorp/aws |

## Terraform Version

| Field | Value |
|-------|-------|
| **Pin** | 1.14.6 |
| **.terraform-version** | 1.14.6 |
| **.tool-versions** | terraform 1.14.6 |
| **required_version** | >= 1.14.6, < 1.15.0 |

## Python Version

| Field | Value |
|-------|-------|
| **Pin** | 3.11.14 |
| **.tool-versions** | python 3.11.14 |

## Per-Root Validation Results

| Root | terraform init | terraform validate | Provider Version | Status |
|------|---------------|-------------------|-----------------|--------|
| account-ready-gate | ✅ PASS | ✅ PASS | 5.100.0 | provider_validated_locally |
| global | ✅ PASS | ✅ PASS | 5.100.0 | provider_validated_locally |
| network | ✅ PASS | ✅ PASS | 5.100.0 | provider_validated_locally |
| platform | ✅ PASS | ✅ PASS | 5.100.0 | provider_validated_locally |
| data-foundation | ✅ PASS | ✅ PASS | 5.100.0 | provider_validated_locally |
| services | ✅ PASS | ✅ PASS | 5.100.0 | provider_validated_locally |
| edge-identity | ✅ PASS | ✅ PASS | 5.100.0 | provider_validated_locally |
| edge | ✅ PASS | ✅ PASS | 5.100.0 | provider_validated_locally |
| addons | ✅ PASS | ✅ PASS | 5.100.0 | provider_validated_locally |

**Result: 9/9 roots PASS**

## Errors Found and Corrected During Validation

| # | Root/Module | Error | Fix |
|---|-----------|-------|-----|
| 1 | roots/platform | `private_subnet_ids` type mismatch (list vs map) | Changed root variable to `map(string)` to match module |
| 2 | roots/services | Same as #1 | Same fix |
| 3 | roots/edge-identity | Same as #1 + `access_log_settings` missing `format` | Type fix + added JSON log format to apigatewayv2_stage |

These are exactly the kind of errors M2B is designed to catch — schema mismatches that static analysis cannot detect.

## Root Wiring Changes

All 8 module-consuming roots were updated to pass required variables through:

| Root | Module | Extra Vars Added to Root |
|------|--------|------------------------|
| global | global | None (module has defaults for service_names, ecs_task_execution_managed_policies) |
| network | network | upstream_contract_digest, expected_upstream_digest |
| platform | container-platform | vpc_id, private_subnet_ids, vpc_cidr_block, internal_certificate_arn |
| data-foundation | data-foundation | upstream_contract_digest, expected_upstream_digest |
| services | services | ecs_cluster_arn, ecs_task_execution_role_arn, workload_role_arns, vpc_id, private_subnet_ids, alb_listener_arn, alb_security_group_id, service_definitions |
| edge-identity | edge-identity | domain_name, vpc_id, private_subnet_ids, alb_listener_arn, alb_security_group_id, api_access_log_group_arn |
| edge | edge | domain_name, route53_zone_id, api_gateway_endpoint, frontend_bucket_domain_name + providers block with aws.us_east_1 alias |
| addons | addons | upstream_contract_digest, expected_upstream_digest |

## Edge Module Provider Alias

The edge module uses `provider = aws.us_east_1` for all resources (CloudFront, WAF, ACM, Route53) because these are global/us-east-1 scoped. The module declares `configuration_aliases = [aws.us_east_1]` and the root passes both providers.

## Lock File Hashes

All 9 lock files contain:
- Provider: `registry.terraform.io/hashicorp/aws` version `5.100.0`
- h1 hashes present
- zh hashes present
- No unauthorized providers
- Same exact version across all roots

## Validation Evidence (from `make` targets)

### `make aws-credentials-guard`
```
=== AWS Credentials Guard ===
PASS: No AWS credentials in environment
```

### `make provider-check` (init + validate aggregate)
```
=== Provider Init (backend=false) ===
  Initializing roots/account-ready-gate... initialized
  Initializing roots/global... initialized
  Initializing roots/network... initialized
  Initializing roots/platform... initialized
  Initializing roots/data-foundation... initialized
  Initializing roots/services... initialized
  Initializing roots/edge-identity... initialized
  Initializing roots/edge... initialized
  Initializing roots/addons... initialized
Provider init complete.
=== Provider Validate ===
  PASS: roots/account-ready-gate
  PASS: roots/global
  PASS: roots/network
  PASS: roots/platform
  PASS: roots/data-foundation
  PASS: roots/services
  PASS: roots/edge-identity
  PASS: roots/edge
  PASS: roots/addons

Provider validate: ALL PASS (9/9)
=== Provider Check Complete ===
```

### `make lock-file-check`
```
=== Lock File Check ===
  roots/account-ready-gate: aws 5.100.0
  roots/addons: aws 5.100.0
  roots/data-foundation: aws 5.100.0
  roots/edge: aws 5.100.0
  roots/edge-identity: aws 5.100.0
  roots/global: aws 5.100.0
  roots/network: aws 5.100.0
  roots/platform: aws 5.100.0
  roots/services: aws 5.100.0

  All roots use provider version: 5.100.0
Lock file check: PASS
  Provider: hashicorp/aws 5.100.0
  Roots checked: 9
  Unauthorized providers: 0
  .terraform/ staged: no
```

### `make preflight-m2b` (full aggregate)
```
=== PREFLIGHT-M2B COMPLETE ===
All M0+M1+M2+M2B checks passed.
Status: M2B_PROVIDER_VALIDATED_LOCALLY
Declarations status: provider_validated_locally
Provider: hashicorp/aws (version from lock files)
```

preflight-m2b includes: preflight-m2 → preflight-m1 → toolchain-status, preflight-m0, module-check, root-check, taskdef-check, supply-chain-check, git-safety, security-check, test, module-ownership-check, edge-split-check, services-ownership-check, module-interface-check, terraform-fmt-check, contract-matrix → provider-check → aws-credentials-guard, provider-init, provider-validate → lock-file-check.

### `git diff --check`
```
(clean — 0 issues)
```

### `git status` summary

42 modified files + 19 new files. All within `scanalyze-deployment-platform/`.

### Prohibited Artifacts Audit

| Artifact | Staged? | Result |
|----------|---------|--------|
| `.terraform/` | No | ✅ PASS |
| `*.tfstate` | No | ✅ PASS |
| `*.tfplan` | No | ✅ PASS |
| `.env` | No | ✅ PASS |
| credentials / `*.pem` / `*.key` | No | ✅ PASS |
| provider cache dirs | No | ✅ PASS |
| `.venv/` | No | ✅ PASS |
| `__pycache__/` | No | ✅ PASS |
| `.pytest_cache/` | No | ✅ PASS |
| raw plan JSON | No | ✅ PASS |
| brownfield files | Intact | ✅ PASS |

## Prohibited Operations Verification

| Operation | Executed? |
|-----------|----------|
| terraform plan | ❌ No |
| terraform apply | ❌ No |
| terraform import | ❌ No |
| terraform state | ❌ No |
| terraform init -upgrade | ❌ No |
| terraform init with backend | ❌ No |
| AWS CLI | ❌ No |
| AWS credentials in env | ❌ No |
| git push | ❌ No |

**Statement**: No `terraform plan`, `terraform apply`, `terraform import`, `terraform state`, or AWS CLI command was executed during M2B. Only `terraform init -backend=false` and `terraform validate` were run, both without AWS credentials.

## Discrepancy Resolutions

| Discrepancy | Before M2B | After M2B |
|-------------|-----------|-----------|
| D-001 (Terraform 1.14.6 vs pin 1.12.1) | OPEN | **RESOLVED** — pin updated to 1.14.6 |
| D-001b (Python 3.11.14 vs pin 3.11.12) | OPEN | **RESOLVED** — pin updated to 3.11.14 |
| D-002 (authored_not_provider_validated) | OPEN | **RESOLVED** — 9/9 roots provider_validated_locally |
| D-003 (roots not wired to modules) | OPEN | **RESOLVED** — all roots wired and validated |

## New Active Discrepancies

| ID | Description | Severity |
|----|-------------|----------|
| D-004 | replicated-data remains M1 skeleton | ℹ Info |
| D-005 | AWS provider 5.100.0 not tested against real AWS account | ⚠ Expected |

## Status

- **Declarations**: `provider_validated_locally`
- **Not**: `verified_in_aws`, `ready_to_plan`, `ready_to_apply`
- **Provider**: hashicorp/aws 5.100.0 (schema validation only, not tested against AWS API)

## Rollback

Manifest-based. See `rollback/ROLLBACK_MANIFEST.md`.

1. Review `rollback/ROLLBACK_MANIFEST.md` section "M2 Level B Additions".
2. Confirm all paths are under `scanalyze-deployment-platform/`.
3. Remove or revert only paths listed in the manifest.
4. Do NOT use `git stash`, `git reset`, `git clean`, or `git checkout -- .`
5. Do NOT use `git checkout HEAD~1 -- <paths>`.
6. `.terraform/` (provider cache) can be deleted manually — never committed, in `.gitignore`.
7. `.terraform.lock.hcl` is committed evidence. Remove only if listed in manifest.
8. Run `make git-safety` and `make security-check` after rollback.

Artifact clarification:

| Artifact | Status | Committed |
|----------|--------|-----------|
| `.terraform.lock.hcl` | Versioned evidence | ✅ Yes |
| `.terraform/` | Local provider cache | ❌ No (in `.gitignore`) |
