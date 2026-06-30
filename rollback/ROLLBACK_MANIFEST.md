# Rollback Manifest — M0 Foundation

> **Purpose**: Manifest-based rollback for M0 scaffold changes.
> All changes are additive within `scanalyze-deployment-platform/`.
> No files outside this repository were modified.

## Verification Before Rollback

1. Confirm all paths listed below are under `scanalyze-deployment-platform/`.
2. Confirm brownfield `scanalyze-micros/` is intact (no files were modified).
3. Confirm no git push has occurred.

## Rollback Procedure

1. Review this manifest to confirm scope.
2. Remove only the paths listed below.
3. Do NOT use `git reset`, `git clean`, `stash`, or `rm -rf`.
4. Verify that brownfield remains intact after removal.

## Affected Paths

All paths are relative to `scanalyze-deployment-platform/`:

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

### Tooling
- `tooling/` — 7 Python validation scripts + `__init__.py`

### Tests
- `tests/test_account_ready/` — ACCOUNT_READY verification tests
- `tests/preconditions/contract_gate/` — HCL fail-closed harness + 7 tfvars

### Reports
- `reports/` — discrepancy register, patch reports

### Virtual Environment
- `.venv/` — local Python venv (not committed)

## Post-Rollback Verification

```bash
# Confirm brownfield is intact
ls -la ../scanalyze-micros/
# Confirm no platform-v2 artifacts remain
ls -la .  # Should show empty or only .git/
```
