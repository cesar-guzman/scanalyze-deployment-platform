# Scanalyze microservices

This directory is the canonical source for the seven Scanalyze services. Every
customer deployment uses this code; deployment differences belong in contracts,
Terraform inputs, SSM parameters, or other reviewed declarative configuration.

## Services

| ID | Source directory | Tests |
|---|---|---|
| `ingest-api` | `scanalyze-ingest-api/` | `scanalyze-ingest-api/tests/` |
| `ocr-worker` | `scanalyze-ocr-worker/` | `scanalyze-ocr-worker/tests/` |
| `postprocess-worker` | `scanalyze-postprocess-worker/` | `scanalyze-postprocess-worker/tests/` |
| `classifier-worker` | `scanalyze-classifier-worker/` | `scanalyze-classifier-worker/tests/` |
| `bank-worker` | `scanalyze-bank-worker/` | `scanalyze-bank-worker/tests/` |
| `personal-worker` | `scanalyze-personal-worker/` | `scanalyze-personal-worker/tests/` |
| `gov-worker` | `scanalyze-gov-worker/` | `scanalyze-gov-worker/tests/` |

Each service is self-contained. No cross-service source import or external local
Python package is required by the migrated baseline.

## Run tests locally

Use Python 3.11 and create an isolated environment outside the source directory
or in the ignored `.venv/` path:

```bash
service=ocr-worker
service_dir="backend/workers/scanalyze-${service}"

python3.11 -m venv .venv
.venv/bin/python -m pip install -r "${service_dir}/requirements.txt" pytest
AWS_REGION="<AWS_REGION>" \
PYTHONPATH="${service_dir}/src:${service_dir}" \
  .venv/bin/python -m pytest "${service_dir}/tests" -q
```

Some tests set additional synthetic service configuration. Never point unit
tests at a customer account or use production data as fixtures.

## Build a local image

Every Dockerfile is fail-closed and requires `BASE_IMAGE`. The repository script
always passes it explicitly:

```bash
scripts/microservices/build-push.sh \
  --service ocr-worker \
  --tag local-dev \
  --base-image python:3.11-slim \
  --no-push \
  --no-write-ssm
```

`python:3.11-slim` is a local-development example only. Enterprise publication
requires a digest-pinned base image in the target account ECR, such as:

```text
<account>.dkr.ecr.<region>.amazonaws.com/base-images/python@sha256:<digest>
```

The build script targets `linux/amd64`, applies OCI source/revision/created
labels, rejects `latest`, and uses a closed seven-service allowlist.

## Publish for a customer deployment

Publishing is an explicit mutation. Confirm the approved AWS profile/region and
caller identity before running it. The script repeats the caller-account check
and fails closed on an existing immutable tag:

```bash
scripts/microservices/build-push.sh \
  --all \
  --account-id "<AWS_ACCOUNT_ID>" \
  --region "<AWS_REGION>" \
  --deployment-id "dep_<ULID>" \
  --ecr-prefix "dep-<lowercase-ulid>/scanalyze" \
  --tag "sha-<commit>" \
  --base-image "<AWS_ACCOUNT_ID>.dkr.ecr.<AWS_REGION>.amazonaws.com/base-images/python@sha256:<digest>" \
  --push \
  --write-ssm
```

`--no-push` and `--no-write-ssm` are the defaults. `--write-ssm` is rejected
unless `--push` is active. After a push, the script verifies the ECR digest and
then writes `image_tag` followed by the authoritative `image_digest` under:

```text
/<deployment_id>/cicd/images/<service>/
```

The services Terraform layer must still consume an approved `repository@sha256`
reference. The script never updates ECS.

If ECR accepted an immutable tag but digest lookup or SSM writing failed, do not
delete or overwrite the tag. From a clean checkout, obtain the tag's digest with
a read-only ECR query, compare it with the build evidence, and reconcile one
service explicitly:

```bash
scripts/microservices/build-push.sh \
  --service ocr-worker \
  --account-id "<AWS_ACCOUNT_ID>" \
  --region "<AWS_REGION>" \
  --deployment-id "dep_<ULID>" \
  --ecr-prefix "dep-<lowercase-ulid>/scanalyze" \
  --tag "sha-<commit>" \
  --push \
  --write-ssm \
  --reconcile-existing "sha256:<verified-digest>"
```

Reconciliation requires an immutable repository, an existing tag, an exact
digest match, the correct caller account, and a clean Git worktree. It builds
and pushes nothing.

## GitHub Actions

`.github/workflows/microservices-build.yml` detects affected services and runs a
matrix of tests and no-push Docker builds for pull requests and `main`.
Publication is disabled unless explicitly requested through a protected GitHub
Environment or a reviewed `MAIN_PUBLISH_ENABLED` repository mapping.

Global build-tool/workflow changes validate all seven services but do not cause
automatic publication by themselves. On `main`, the publish matrix contains
only service directories changed in that push; manual dispatch remains explicit.

Each customer GitHub Environment must define:

- `AWS_ROLE_ARN`
- `AWS_ACCOUNT_ID`
- `AWS_REGION`
- `DEPLOYMENT_ID`
- `ECR_PREFIX`
- `BASE_IMAGE_URI` (target-account ECR, digest-pinned)

The repository-level `CI_BASE_IMAGE` variable supplies the non-credentialed PR
base image. Configure the Environment deployment-branch rule to permit only
`main`; the workflow also rejects publication from any other ref. OIDC trust
must bind the exact repository and environment subject; no AWS access key
belongs in GitHub.

## Never commit

- Customer documents, uploads, dumps, production logs, or real PII
- Credentials, tokens, private keys, certificates, or environment files
- Terraform state, plans, local/generated tfvars, or generated config
- Python caches, virtual environments, coverage, build output, or logs
- Finder-numbered duplicates, local backups, archives, or legacy per-service
  buildspecs

Run `make microservices-check`, `make security-check`, and `make git-safety`
before review.
