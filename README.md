# Scanalyze Deployment Platform

> Track B — Greenfield Customer Factory

## Purpose

This repository contains the Scanalyze Dedicated Deployment Platform v2:
the infrastructure, schemas, policies, tests, and tooling required to deploy
isolated Scanalyze environments into dedicated AWS accounts.

## Architecture

- **One source code + one release train**
- **One shared control plane** (Shared Services account)
- **One dedicated AWS account per customer deployment**
- **Customer-local data, compute, identity, encryption, runtime observability, and ECR**

## Repository Structure

```
ADR/                    Architecture Decision Records (imported, patched)
schemas/                Canonical JSON Schemas for all contracts
fixtures/               Valid and invalid golden test fixtures
policies/               IAM, S3, KMS policy fixtures
session-policies/       Per-layer session policy documents
modules/                Terraform modules (scaffold only until acceptance gates pass)
roots/                  Terraform roots (scaffold only until acceptance gates pass)
tooling/                Validation and canonicalization utilities
tests/                  All test suites
reports/                Implementation and progress reports
```

## Current Milestone

**M0 — Repository Foundation & Executable Evidence**

No AWS mutations. No Terraform modules. Schemas, fixtures, policy fixtures,
tests, and acceptance gates only.

## Make Targets

```bash
make agent-context    # Print repo baseline
make fmt              # Format all files
make lint             # Lint all source files
make schema-check     # Validate schemas + fixtures
make policy-check     # Validate policy fixtures
make contract-check   # Contract canonicalization + digest + replay
make test             # Run all tests
make security-check   # PII + secret + state/plan sentinel
make preflight        # All non-mutating checks
make git-safety       # Branch safety + secret scan
```

## Principles

1. Security and correctness before speed
2. Evidence before claims
3. One declarative owner per resource
4. No customer-specific code forks
5. Customer documents and PII remain inside the customer deployment account
6. Build once, deploy many
7. Terraform state is not a release rollback mechanism
8. No accepted write may be discarded
9. No manual AWS configuration as source of truth
10. No unverified multi-region promises
