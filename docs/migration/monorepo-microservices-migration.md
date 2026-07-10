# Monorepo Microservices Migration Plan

## Status

- Plan date: 2026-07-09
- Target repository HEAD: `8623412f5c124ffe532265e0cddf513e6cd01c40`
- Isolated implementation branch: `feat/monorepo-microservices`
- Isolated worktree: `../scanalyze-deployment-platform-monorepo`
- AWS activity: none; this migration is local-only until a separately approved deployment

## 1. Current state

### Workspace containment

The original checkout was on `main` and was not safe for this migration. It had
48 modified tracked files and 46 untracked files. The tracked changes span
`modules/` (27), `roots/` (20), and `reports/` (1). The untracked files span
`.github/` (5), `_NotebookLM_Brain/` (7), `docs/` (1), `environments/` (4),
`modules/` (5), `reports/` (5), `roots/` (14), and `scripts/` (5).

High-risk untracked artifacts include binary Terraform plans, Terraform state
backups, a local `deployment.tfvars`, generated configuration, Office temporary
files, reports, and an untracked `.github/workflows/pr_validation.yml`. None of
those files are used or copied by this migration. The original checkout remains
untouched.

### Source locations investigated

| Location | Git state | Relevant revision | Assessment |
|---|---|---|---|
| `../scanalyze-micros/backend/workers` | Parent repo dirty; 36 tracked and 66 untracked worker changes | `origin/main` = `9e6a14d` | Canonical committed baseline; do not copy the working tree |
| `../srv-scanalyze/scanalyze-micros/backend/workers` | Clean | feature `a45cc94` | Later unmerged feature branch; CodeCommit-backed checkout |
| `../p1-003-worktree/scanalyze-micros/backend/workers` | Dirty | feature `a45cc94` | Worktree for the same unmerged feature branch |
| local branch `deploy/p1-003-worker-metering` | Commit only | `04c7fdf` | Later local branch, not the default remote branch |

`ADR/SOURCE_MANIFEST.json` records
`brownfield_head=9e6a14d240373ced4b23523097b1207982aa6004`, which matches the
GitHub `origin/main` revision in the brownfield repository. Therefore the
migration source is the exact Git object
`9e6a14d:scanalyze-micros/backend/workers`, exported with `git archive`. This
avoids all dirty and untracked source files and makes the copy reproducible.

The feature branches are not silently merged into this migration. They require
an explicit follow-up reconciliation after their ownership and merge status are
confirmed.

### Services found

All seven expected services and their canonical Dockerfiles are present:

- `scanalyze-ingest-api`
- `scanalyze-ocr-worker`
- `scanalyze-postprocess-worker`
- `scanalyze-classifier-worker`
- `scanalyze-bank-worker`
- `scanalyze-personal-worker`
- `scanalyze-gov-worker`

No service is missing. Each service has `requirements.txt`; tests are present in
all seven service trees. The code uses service-local modules; no required shared
Python package was found outside the service directories.

The source tree contains 248 entries. It also contains 89 non-canonical
artifacts: `.DS_Store`, five ZIP archives, numbered Finder-style duplicates,
and a `_local_backup` directory. The migration will copy only the seven service
directories and exclude those artifacts. No first-pass copy will use `--delete`.

Filename-only secret scanning found no AWS access key, private-key header, or
common API-key pattern in the committed source. PII-shaped values occur only in
domain logic/tests and will be reviewed as synthetic fixtures; no document,
upload, dump, or client data file was found. The copied tree will be scanned
again before it is eligible for review.

### Current CI/CD and Terraform

- The target repository has no tracked GitHub Actions workflow.
- The original dirty checkout has an unrelated untracked PR workflow; it is not
  imported.
- `modules/cicd` owns customer-local immutable, KMS-encrypted, scan-on-push ECR
  repositories and release metadata SSM parameters.
- The same module optionally owns the legacy CodeCommit + CodeBuild +
  CodePipeline build path. It has no ECS deploy stage.
- Today `enable_codecommit=false` preserves ECR and SSM but also removes the
  legacy CodeBuild/CodePipeline stack. With seven services, changing the flag
  from true to false can plan approximately 30 destroys.
- ECS service definitions consume explicit image references. Existing deployed
  examples use ECR digests, but tracked client-specific tfvars predate this
  migration and are not modified here.

## 2. Technical decision

1. Make `backend/workers/scanalyze-*` the canonical application source paths in
   this repository.
2. Keep one code line and release train. Customer differences remain in
   contracts, approved tfvars, SSM, and declarative configuration.
3. Keep customer-local ECR and SSM image metadata. Runtime deployments continue
   to consume immutable image digests.
4. Make the reusable local script and GitHub Actions the primary monorepo build
   entrypoints. GitHub Actions uses OIDC and a pre-provisioned, deployment-scoped
   role; no static AWS keys are accepted.
5. Separate `enable_codepipeline` from `enable_codecommit` with a nullable,
   backwards-compatible flag. When omitted, it inherits the old
   `enable_codecommit` resource-enablement behavior. State moves avoid IAM
   replacement; a separate `ECR_REPO_NAME` correction may still update projects
   in place, so a zero-diff plan is not claimed.
6. Do not delete CodeCommit or CodePipeline resources in this change. Operators
   must review a live plan and migrate in two explicit steps. ECR and SSM remain
   independent.
7. Require `ARG BASE_IMAGE` / `FROM ${BASE_IMAGE}` in every Dockerfile. Local or
   PR builds may explicitly pass a documented public development image;
   enterprise publish jobs must pass an approved ECR base image, preferably by
   digest.

## 3. Risks and controls

| Risk | Control in this migration |
|---|---|
| Dirty target checkout | Dedicated clean worktree and file allowlist |
| Dirty/divergent source checkouts | Export exact Git commit; never copy a working tree |
| Secrets or PII | Filename exclusions, content-pattern sentinel, no real fixtures |
| Hardcoded base image/account/client | Parameterized Dockerfiles and repository check |
| CI/CD documentation drift | Update README, playbook, CI/CD README, and ADR |
| Accidental CodeCommit/CodePipeline destruction | Backwards-compatible flags, no tfvars switch, explicit plan warning |
| Missing AWS credentials or live evidence | No AWS claims; live plan/build/push/SSM remain unexecuted |
| Public registry dependency in production | Publish requires explicit `BASE_IMAGE`; local fallback is documented as non-production only |
| Mutable image deployment | ECR immutable tags plus post-push digest resolution and SSM digest metadata |
| Cross-client writes | Caller identity must match `--account-id`; deployment-specific SSM namespace |

## 4. Implementation plan

1. Export the seven service directories from the recorded source commit.
2. Copy with an explicit exclusion set for secrets, caches, state/plan files,
   archives, backups, generated reports, and numbered duplicate artifacts.
3. Normalize the seven Dockerfiles and add a restrictive `.dockerignore` per
   service without changing business behavior.
4. Replace client-specific examples with synthetic identifiers.
5. Add `scripts/microservices/build-push.sh` with strict input validation,
   service allowlisting, no-push mode, caller-account verification, immutable
   tagging, optional push, digest lookup, and separately gated SSM writes.
6. Add a path-aware GitHub Actions workflow with PR validation, a service matrix,
   OIDC-only publish jobs, and deployment-scoped GitHub environment variables.
7. Add a repository microservice safety check and wire it into existing local
   gates.
8. Decouple the legacy CodePipeline flag while retaining old defaults. Document
   a two-stage migration and the expected destroy surface; do not change a live
   client tfvars file.
9. Update repository, worker, deployment, CI/CD, and architecture-decision docs.
10. Run syntax, unit, Terraform format/static, secret/safety, workflow, and
    container validations available locally. Record every skipped check.

## 5. Acceptance criteria

- Seven services exist under `backend/workers/scanalyze-*`.
- Every canonical Dockerfile uses a caller-supplied `BASE_IMAGE` and contains no
  hardcoded AWS account, region, customer, or `latest` dependency.
- A single script builds one or all services for an explicit account, region,
  deployment, ECR prefix, tag, and base image.
- PR validation cannot push to ECR or write SSM. Publish jobs use GitHub OIDC and
  fail closed without an approved role/configuration.
- ECR repositories and SSM digest metadata remain Terraform-owned and usable
  when legacy source/build pipelines are disabled.
- The CodeCommit/CodePipeline transition is explicit and does not change live
  flags in this PR.
- Git ignores and safety checks cover state, plans, credentials, local tfvars,
  generated config, logs, archives, and raw client documents without hiding safe
  tracked contract examples.
- Documentation describes the monorepo, base-image policy, multi-client build,
  digest flow, risks, and rollback.
- Local validations either pass or are reported with exact blockers.

## 6. Change allowlist

Only the following paths may be modified by this task:

- `backend/workers/**`
- `scripts/microservices/**`
- `.github/workflows/microservices-build.yml`
- `tooling/check_microservices.py`
- `tooling/security_sentinel.py`
- `tests/test_microservices/**`
- `tests/sentinel/**`
- `Makefile`
- `.gitignore`
- `sentinel_allowlist.yaml`
- `README.md`
- `modules/cicd/{main.tf,variables.tf,outputs.tf,README.md}`
- `roots/cicd/{main.tf,variables.tf,providers.tf,README.md}`
- `environments/cicd.github-monorepo.tfvars.example`
- `playbooks/enterprise-client-deployment.md`
- `reports/scanalyze-environment-destroy-playbook.md`
- `ADR/ADR-011-monorepo-microservices-source.md`
- `docs/migration/monorepo-microservices-migration.md`

## 7. Stop-condition evaluation

No stop condition currently applies:

- The source was located and pinned to the target repository's recorded
  brownfield revision.
- Divergent branches were identified and excluded rather than overwritten.
- The target has no existing microservice directories.
- No secret or real client-data artifact has been identified in the pinned
  service source.
- No Terraform apply, destroy, state command, Docker push, SSM write, or other
  AWS mutation is required to prepare this change.

This evaluation covers the monorepo consolidation. Independent review found two
pre-existing blockers for a live end-to-end customer onboarding (identity claim
binding and declarative frontend config ownership). They do not require copying
different source, but the playbook now stops before those live actions and
records the required architecture decisions in Section 9.

If a later scan identifies a real secret/PII value or an existing target path
appears unexpectedly, implementation stops before that content is staged.

## 8. Implementation result and evidence

Implementation completed in the isolated worktree. The reproducible source
object is `9e6a14d240373ced4b23523097b1207982aa6004` and the exported workers tree is
`81535f1493c7b9719f10e38ea9ed72c386fc55bb`. The copy retained 152 canonical
service files from the baseline before adding monorepo hardening and tests. It
excluded 89 Finder/archive/backup artifacts and seven legacy per-service
`buildspec.yml` files. No dirty source-checkout file was imported.

All seven services are now present. Their Dockerfiles require an explicit base
image and run as non-root. Build, change-detection, policy, GitHub Actions, and
Terraform compatibility changes described above are implemented. No live
customer tfvars was switched and no legacy resource was removed.

The CI/CD root now binds the AWS provider to the declared customer account with
`allowed_account_ids`, closing a pre-existing wrong-account execution path.
Omitting the new pipeline flag preserves historic state addresses through
explicit `moved` blocks. Setting it to `false` is intentionally destructive for
legacy pipelines, projects, log groups, roles, and policies and still requires
a reviewed live plan. The corrected CodeBuild ECR repository value may produce
an in-place update even when the flag is omitted; no zero-diff claim is made.

### Tracked tfvars inventory

The repository intentionally tracks these tfvars categories:

| Path | Classification | Action in this migration |
|---|---|---|
| `environments/bcm-corp-services.tfvars` | Existing deployment-specific configuration | Left unchanged; follow-up repository-history and secret-hygiene review required |
| `environments/cicd.tfvars` | Existing deployment-specific CI/CD configuration | Left unchanged; follow-up repository-history and secret-hygiene review required |
| `environments/m3-sandbox.synthetic.tfvars.example` | Synthetic example | Retained |
| `environments/cicd.github-monorepo.tfvars.example` | New safe migration overlay | Added |

The ignore rules distinguish safe tracked examples from new local/generated
`deployment.tfvars`, `*.auto.tfvars`, and other operational tfvars. Existing
tracked files were not silently removed or rewritten.

### Validation completed

- Platform test suite: 75 passed, including 18 focused build/publish/change-
  detection and fail-closed Git safety tests, plus six fail-closed sentinel
  tests.
- The seven service suites passed 419 tests under the workflow's runtime
  environment contract (ingest 214, OCR 23, postprocess 37, classifier 6,
  bank 34, personal 96, government 9). This local service run used the
  available Python 3.14 dependency environment; the workflow's Python 3.11
  execution remains a required PR check.
- The stale `tests/contracts/` Make target was corrected to the existing
  `tests/test_account_ready/` contract/anchor suite; its 11 tests passed.
- Python compilation, Bash syntax, YAML parsing, `git diff --check`, and
  microservice policy checks: passed.
- All six Terraform files changed by this migration pass
  `terraform fmt -check`; `roots/cicd` offline initialization and validation
  also pass. No backend, state, plan, or AWS mutation was used.
- `make git-safety`, `make security-check`, `make schema-check`,
  `make contract-check`, `make cicd-safety-check`, `make preflight-core`, and
  `make preflight-m2`: passed; the M2 contract matrix passed all 90 scenarios.
- `actionlint` 1.7.12 passed against the GitHub Actions workflow.
- The security sentinel reported zero unallowlisted findings. Its 192 allowed
  matches are narrowly documented synthetic CURP/RFC/CLABE/NSS domain fixtures
  and prompt examples, not customer records.

`cicd-safety-check` retained eight informational brownfield blockers in the
historic source assessment and one pre-existing image-reference warning under
`modules/services`; it reported zero V2 blockers for this migration.

### Validation intentionally not completed

- Repository-wide `terraform fmt -recursive -check` reports 100 pre-existing
  Terraform fixture and configuration files outside this change. None
  intersects the modified or untracked migration files. They were not
  reformatted here because doing so would mix unrelated baseline cleanup into
  this PR.
- Container images were not built because the local Docker daemon is not
  available. The Docker client is present and every no-push command path was
  exercised with a mocked Docker/AWS harness.
- `shellcheck` and `yamllint` are not installed. Available checks were used:
  Bash syntax, `actionlint`, PyYAML parsing, focused unit tests, and repository
  policy checks.
- No live Terraform plan, Docker push, ECR lookup, SSM write, ECS update, or
  other AWS call was run. No AWS profile/region was authorized for this task.

## 9. Residual risks and operator gates

### Production-readiness boundary

This migration makes the source consolidation and customer-scoped image build
path reviewable; it does **not** make the wider platform production-executable.
The enterprise deployment guide is therefore NO-GO until all deployment roots
have an account-bound provider/backend execution path, runtime configuration has
one declarative owner, the seven-image release is represented by a complete
signed manifest with SBOM/signature/provenance evidence, service log ownership is
available before task start, and the identity/frontend gates are closed in a
live non-production environment.

1. Run a reviewed, non-production Terraform plan before changing either legacy
   CI/CD flag. Export audit-required build logs before Stage 1 disables
   CodePipeline. Only a separately reviewed Stage 2 may remove CodeCommit.
2. Reconcile the excluded `a45cc94` and `04c7fdf` feature branches with their
   owners before closing the brownfield repository.
3. Configure protected GitHub Environments with deployment-scoped OIDC role,
   account, region, ECR prefix, base image digest, and SSM policy. Main-branch
   publication remains disabled until explicitly enabled.
4. Execute real container builds against an approved, customer-account ECR
   base image in non-production CI before merge.
5. Review the two existing deployment-specific tracked tfvars independently;
   rotate/remediate through a dedicated security change if sensitive history is
   confirmed.
6. Replace ranged/transitive Python dependency resolution with reviewed,
   hash-locked inputs (or an approved wheel repository) before claiming
   deterministic rebuilds.
7. Add SBOM, signing, provenance, vulnerability gating, and evaluate a signed
   central build plus verified customer-account image promotion model. The
   current implementation builds customer-scoped images from one source line.
8. Resolve the pre-existing identity contract before live onboarding: Cognito
   does not currently define the customer claim required by ingest, while the
   services layer binds the expected customer to `deployment_id`. This requires
   an explicit ADR and coordinated identity/services/backend change; it was not
   guessed inside the source migration.
9. Add one declarative owner for frontend `config.json` and exact
   CloudFront/API/S3 bindings. The playbook now blocks first-resource selection,
   imperative upload, invalidation, user creation, and E2E claims until these
   config and identity gates are closed.
10. Replace mutable `apt`/package-index resolution with an approved package
    source and multi-stage builds; some migrated images still retain
    `build-essential` in the runtime layer. This migration does not claim
    byte-identical rebuilds or a fully hardened SBOM/signing pipeline.
