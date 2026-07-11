# Reproducibility Guide

> How to reproduce every validation from a clean `git clone`.

## Prerequisites

| Tool | Version | Source |
|---|---|---|
| Python | 3.11.14 (pinned in `.tool-versions`) | [python.org](https://www.python.org/) |
| Terraform | 1.14.6 (pinned in `.terraform-version`) | [terraform.io](https://www.terraform.io/) |
| jq | 1.6+ | [github.com/jqlang/jq](https://github.com/jqlang/jq) |
| Docker | 24+ (optional; for local image builds) | [docker.com](https://www.docker.com/) |
| Bash | 5+ | System or Homebrew |

> [!NOTE]
> No AWS credentials are required for local reproducibility checks.
> `bootstrap-local` installs Python dependencies and may require network access
> when they are not already cached. After a successful bootstrap, `repro-check`
> does not call AWS. Terraform provider initialization is a separate check.

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

1. Fails closed unless Python and Terraform match `.tool-versions` and
   `.terraform-version` exactly.
2. Creates a Python virtual environment in `.venv/` if it does not exist.
3. Installs Python dependencies from `pyproject.toml`; installation failures stop
   the bootstrap. This step may require network access or a configured package
   cache.
4. Re-verifies the virtual environment's Python version.
5. Validates JSON syntax.

`bootstrap-local` does not initialize Terraform providers. `provider-check` is
separate because `terraform init -backend=false` may download providers:

```bash
make provider-check
```

The provider check refuses to run when AWS credential/profile variables are
present and never initializes a remote backend, but provider downloads can still
require network access.

## What `repro-check` Does

1. Verifies the seven microservices exist with correct structure.
2. Runs security sentinel and allowlist checks.
3. Validates JSON syntax and repository-global GitHub governance policy.
4. Validates the canonical GitOps DAG and its deployment tests.
5. Checks Terraform formatting.
6. Runs all Python tests.
7. Verifies no forbidden artifacts in the worktree.

It does not run `provider-check`; record that result separately when provider
initialization is part of the required evidence.

## What `release-dry-run` Does

1. Runs `repro-check` as a prerequisite.
2. Validates the synthetic deployment manifest (`examples/deployments/synthetic-nonprod.yaml`).
3. Generates the supply-chain release graph in dry-run mode.
4. Runs the orchestrator doctor and reports required/optional local tools.
5. Runs `plan-all --dry-run` with the synthetic manifest across every canonical
   DAG layer, using a temporary plan directory outside the repository that is
   removed on exit.
   The wrapper prefers the repository `.venv` locally and otherwise accepts the
   `python3` provisioned by CI only after verifying that `PyYAML` and
   `jsonschema` are importable.
6. Validates the required documentation inventory.
7. The deployment dry-run stage does **not** touch AWS, Docker, ECR, or SSM.
   Its bootstrap prerequisite may contact the configured Python package source,
   as described above.

## Clean Clone Verification

To verify that the repository is fully self-contained:

```bash
scripts/repro/verify-clean-clone.sh --ref HEAD
```

This script:

- Clones the repo into a temporary directory.
- Resolves the requested ref to an exact commit and checks out that SHA.
- Fails if the exact commit is not available from the cloned remote; it never
  substitutes the remote's default `HEAD`.
- Runs `make bootstrap-local` and `make repro-check`.
- Verifies all 7 services, docs, and schemas are present.
- Verifies no forbidden artifacts exist.
- Does **not** touch AWS.

### Automated workflow

`.github/workflows/repro-check.yml` runs the bootstrap, reproducibility, and
release dry-run targets in GitHub's fresh checkout workspace:

- for every pull request targeting `main`;
- once after a push reaches `main`;
- every Monday at 06:00 UTC; and
- on demand through `workflow_dispatch`.

Feature branches are validated by their pull-request run, so they do not also
create a duplicate push run. The workflow pins Python 3.11.14 and Terraform
1.14.6 to the same versions declared by the repository toolchain files. The
manual `verify-clean-clone.sh` wrapper remains the evidence that an exact commit
can be fetched from a named remote; the workflow does not invoke that wrapper.

When `--ref HEAD` names a local commit that has not been pushed to the selected
remote, clean-clone verification fails intentionally. Push the reviewed commit
or pass a remote that is authoritative for that exact SHA; do not treat another
remote HEAD as equivalent evidence.

## Validation State Classification

| State | Meaning |
|---|---|
| `clone-ready` | Exact requested commit can be cloned and bootstrapped |
| `repro-check-passed` | Included local checks pass; provider evidence is separate |
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
