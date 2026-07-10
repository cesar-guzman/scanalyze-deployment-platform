# Reproducibility Guide

> How to reproduce every validation from a clean `git clone`.

## Prerequisites

| Tool | Version | Source |
|---|---|---|
| Python | 3.11.x (pinned in `.tool-versions`) | [python.org](https://www.python.org/) |
| Terraform | 1.12.x (pinned in `.terraform-version`) | [terraform.io](https://www.terraform.io/) |
| jq | 1.6+ | [github.com/jqlang/jq](https://github.com/jqlang/jq) |
| Docker | 24+ (optional; for local image builds) | [docker.com](https://www.docker.com/) |
| Bash | 5+ | System or Homebrew |

> [!NOTE]
> No AWS credentials are required for local reproducibility checks.
> The `repro-check` target runs entirely offline.

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/cesar-guzman/scanalyze-deployment-platform.git
cd scanalyze-deployment-platform

# 2. Bootstrap local environment
make bootstrap-local

# 3. Run reproducibility check
make repro-check

# 4. Run full release dry-run (no AWS)
make release-dry-run
```

## What `bootstrap-local` Does

1. Creates a Python virtual environment in `.venv/` if it does not exist.
2. Installs Python dependencies from `pyproject.toml`.
3. Verifies toolchain versions match `.tool-versions` and `.terraform-version`.
4. Initializes Terraform providers in all roots with `-backend=false` (no state).
5. Validates JSON schema syntax.
6. Reports any missing optional tools (Docker, shellcheck, actionlint).

## What `repro-check` Does

1. Verifies the seven microservices exist with correct structure.
2. Runs security sentinel and allowlist checks.
3. Validates JSON schemas, fixtures, and policies.
4. Validates Terraform modules and roots structure.
5. Checks Terraform formatting.
6. Runs all Python tests.
7. Validates the deployment manifest schema.
8. Verifies no forbidden artifacts in the worktree.

## What `release-dry-run` Does

1. Runs `repro-check` as a prerequisite.
2. Validates the synthetic deployment manifest (`examples/deployments/synthetic-nonprod.yaml`).
3. Validates SSM contract schema.
4. Validates identity contract schema.
5. Validates frontend config schema.
6. Simulates the orchestrator in `--dry-run` mode with the synthetic manifest.
7. Reports which supply chain tools are available vs. SKIPPED.
8. Does **not** touch AWS, Docker, ECR, SSM, or any external system.

## Clean Clone Verification

To verify that the repository is fully self-contained:

```bash
scripts/repro/verify-clean-clone.sh --ref HEAD
```

This script:
- Clones the repo into a temporary directory.
- Checks out the specified ref.
- Runs `make bootstrap-local` and `make repro-check`.
- Verifies all 7 services, docs, and schemas are present.
- Verifies no forbidden artifacts exist.
- Does **not** touch AWS.

## Validation State Classification

| State | Meaning |
|---|---|
| `clone-ready` | Repository can be cloned and bootstrapped |
| `repro-check-passed` | All offline validations pass |
| `release-dry-run-passed` | Full dry-run sequence completes |
| `PR-ready` | Ready for code review |
| `merge-ready` | Ready to merge after review approval |
| `nonprod-deploy-ready` | Ruta prepared for non-production deployment |
| `live-validated` | Non-production deployment executed with evidence |
| `production-ready` | All blockers closed, live validation approved |

> [!CAUTION]
> `repro-check-passed` does NOT equal `live-validated`.
> `live-validated` does NOT equal `production-ready`.
> Each state requires its own evidence.

## Files That Must Never Enter Git

- `*.tfstate`, `*.tfplan`, `*.plan.json`
- `.env`, `.env.*`
- `.work/`, `.terraform/` (except lock files)
- `.aws/`, `credentials`, `*.pem`, `*.key`
- `~$*.docx` (Word lockfiles)
- Customer documents, PII, dumps, logs
- Real deployment tfvars (only `.example` templates)

## Reporting Issues

If `repro-check` fails on a clean clone, file an issue with:
1. The exact `git clone` command used.
2. Output of `make toolchain-check`.
3. The failing target and its output.
4. Your OS and shell version.
