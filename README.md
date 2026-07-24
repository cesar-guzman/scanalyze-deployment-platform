# Scanalyze Deployment Platform

> Dedicated, account-per-deployment enterprise platform

## Purpose

This repository is the Scanalyze monorepo for infrastructure, deployment
contracts, security policy, validation tooling, and the seven application
microservices used by every customer deployment.

One source tree and one release train serve every customer. Customer-specific
behavior is injected through reviewed contracts, safe Terraform inputs, SSM
parameters, and declarative runtime configuration; customer forks are not
supported.

## Architecture

- One dedicated AWS account per customer deployment
- Customer-local data, compute, identity, encryption, observability, and ECR
- Terraform layers with one declarative owner per resource
- Application source is canonical only in this repository; the target state
  delivers images, not source, to customer accounts
- Immutable OCI images delivered through ECR and consumed by digest
- GitHub OIDC for automated AWS access; no static AWS keys

## Repository structure

```text
backend/workers/        Canonical source for all seven microservices
frontend/               Canonical source for the portable Scanalyze SPA
.github/workflows/      Path-aware validation and protected image publishing
governance/             Declarative, client-independent repository policy
deployment/             Canonical GitOps stage graph and orchestration metadata
scripts/microservices/  Reusable build/push and change-detection entrypoints
ADR/                    Architecture decisions
schemas/                Canonical JSON schemas and contracts
fixtures/               Synthetic valid/invalid test fixtures
policies/               IAM, S3, and KMS policy fixtures
session-policies/       Per-layer session policy documents
modules/                Terraform modules
roots/                  Deployable Terraform roots
environments/           Safe tracked examples and reviewed deployment inputs
tooling/                Validation and security utilities
tests/                  Platform test suites
playbooks/              Operator procedures
reports/                Historical implementation evidence
```

## Microservices

| Service | Path | Role |
|---|---|---|
| ingest-api | `backend/workers/scanalyze-ingest-api` | Authenticated ingest/API surface |
| ocr-worker | `backend/workers/scanalyze-ocr-worker` | Textract submission and polling |
| postprocess-worker | `backend/workers/scanalyze-postprocess-worker` | Validation, persistence, notification |
| classifier-worker | `backend/workers/scanalyze-classifier-worker` | Document classification |
| bank-worker | `backend/workers/scanalyze-bank-worker` | Bank-document extraction |
| personal-worker | `backend/workers/scanalyze-personal-worker` | Personal-document extraction |
| gov-worker | `backend/workers/scanalyze-gov-worker` | Government-document extraction |

See [`backend/workers/README.md`](backend/workers/README.md) for local tests and
image-build instructions.

## Build entrypoint

All Dockerfiles require an explicit `BASE_IMAGE`. A public image can be passed
explicitly for local development only:

```bash
scripts/microservices/build-push.sh \
  --service ingest-api \
  --tag local-dev \
  --base-image python:3.11-slim \
  --no-push \
  --no-write-ssm
```

Enterprise publication uses a digest-pinned base image from the target customer
ECR and a protected GitHub Environment. The workflow resolves the pushed digest
and may write only these release metadata parameters when explicitly enabled:

```text
/<deployment_id>/cicd/images/<service>/image_tag
/<deployment_id>/cicd/images/<service>/image_digest
```

ECS promotion remains Terraform-owned and uses the verified image digest; an SSM
metadata update is not itself a deployment.

Some existing deployments may temporarily retain a non-canonical legacy
CodeCommit mirror while source retention is reviewed. It is excluded from the
build path; access must be restricted separately by IAM. A reviewed Terraform
plan must remove it to reach the no-source-in-customer target state.

## Validation

```bash
make microservices-check
make frontend-check
make github-governance-check
make security-check
make git-safety
make gitops-orchestrator-check
make preflight-core
make preflight-m1
make preflight-m2
```

Run the narrowest relevant gate first, then the broader gates before review.
No validation target authorizes AWS mutation.
Passing local gates does not replace a real image build and reviewed Terraform
plan in non-production before any production release.

## Contributing

Human contributors start with [`CONTRIBUTING.md`](CONTRIBUTING.md). It defines
the end-to-end Linear-to-branch-to-PR workflow, risk classification, review,
testing, documentation, evidence, rollback, cloud boundaries, and Definition of
Done. Security vulnerabilities must be reported privately according to
[`SECURITY.md`](SECURITY.md).

New team members should also follow the step-by-step
[`GitHub contributor walkthrough`](docs/engineering/GITHUB_CONTRIBUTOR_WALKTHROUGH.md)
to request and verify access, understand the GitHub interface, create an
isolated worktree, open a Draft PR, interpret checks, and perform a review.

The repository validates this contract offline:

```bash
make contributor-docs-check
```

## Safety principles

1. Evidence before claims
2. One declarative owner per resource
3. No customer-specific source forks
4. Customer documents and PII remain inside the customer account
5. Build from one reviewed source line and deploy immutable artifacts by digest
6. Terraform state is not a release rollback mechanism
7. No state, plans, local deployment inputs, credentials, or client material in Git
8. No manual AWS configuration as source of truth
9. No production apply, push, SSM write, or ECS mutation without explicit approval
10. No unverified multi-region or supply-chain claims
11. Required CI contexts are static and client-independent; dynamic matrix jobs are evidence, not branch-protection APIs
12. Every deployment uses its own protected GitHub Environment and binding variables

## Migration record

The monorepo source decision, source revision, exclusions, Terraform compatibility
plan, and residual risks are documented in
[`docs/migration/monorepo-microservices-migration.md`](docs/migration/monorepo-microservices-migration.md).
The frontend source snapshot, exclusions, provenance class, and rollback are
recorded separately in
[`docs/migration/frontend-source-consolidation.md`](docs/migration/frontend-source-consolidation.md).

## Deployment documentation

- Production Readiness Phase 0: [`docs/production-readiness/README.md`](docs/production-readiness/README.md)
- Canonical operator source: [`playbooks/enterprise-client-deployment.md`](playbooks/enterprise-client-deployment.md)
- GitOps orchestrator architecture: [`docs/deployment/gitops-orchestrator.md`](docs/deployment/gitops-orchestrator.md)
- GitHub CI governance and multi-client Environment runbook: [`docs/operations/github-governance.md`](docs/operations/github-governance.md)
- Enterprise Word deliverable: generated locally from the canonical playbook;
  the binary is not versioned in this repository.
- Curated NotebookLM corpus: [`_NotebookLM_Brain/00_INDEX_AND_SOURCE_MAP.md`](_NotebookLM_Brain/00_INDEX_AND_SOURCE_MAP.md)

The current guide is intentionally marked **DRAFT / NON-EXECUTABLE / NO-GO**.
Local gates validate repository behavior, but production deployment remains
blocked until the account-bound Terraform execution path, runtime contracts,
complete OCI supply chain, identity contract, declarative frontend configuration
and live non-production evidence are implemented and approved.

The Phase 0 foundation is planning and governance evidence only. It does not
change production NO-GO, enable the live Terraform path, or make a dry-run AWS
evidence.
