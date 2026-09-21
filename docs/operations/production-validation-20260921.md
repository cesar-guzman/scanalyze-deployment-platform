# Independent production validation — 2026-09-21 UTC

**PRODUCTION NO-GO.** This assessment found and repaired local release-workflow
defects. It does not certify a deployed application or a connected document
journey. The implementation is tracked by [GUG-421](https://linear.app/guguce/issue/GUG-421/repair-express-production-offline-admission-and-fail-closed),
a child of GUG-124. [Draft PR #121](https://github.com/cesar-guzman/scanalyze-deployment-platform/pull/121)
is published at `9248a441caa209c3335f4b206aa13705e66e6518`; hosted CI is blocked
and human review remains required. The follow-up documented below is local only.

## Source custody and attribution

Repository: `cesar-guzman/scanalyze-deployment-platform`.
The latest observed main snapshot is
`2effaa39268a90d1ea54d1e5fce3524a9ca0537c`, corroborated by
[PR #120](https://github.com/cesar-guzman/scanalyze-deployment-platform/pull/120)
and the corresponding
[main workflow run](https://github.com/cesar-guzman/scanalyze-deployment-platform/actions/runs/35285451823).
Direct main-branch and protection API queries were rejected by automatic
approval review. This is a corroborated snapshot, not certification of current
protection settings.

The repair uses branch `fix/express-production-offline-admission` in the isolated
`scanalyze-production-validation/scanalyze-deployment-platform` worktree,
created from that exact SHA. The primary checkout was not changed.

The historical candidate is `fix/production-runtime-readiness`, HEAD
`55b336b787b2fdc68a4cacbc11e0460ea9ac37b5`. At initial inspection it had 175
modified tracked files, 297 untracked entries and was 31 commits behind the
observed main. Its changes were preserved. Tests on that candidate and tests on
main are different evidence sets; neither may stand in for the other.

PRs #108–#120 are merged, with approval by `guguce-google` on each recorded
head. Their author metadata is `cesar-guzman`; Linear comments are also recorded
under the owner's account. Neither source proves which changes Grok authored.
The review covers these production-preparation changes and eight critical
Linear gates, not every historical issue or every possible code path.

## GitHub and delivery evidence

| Change group | Observed outcome | Limit |
| --- | --- | --- |
| #108 Express release | Merged; 15 successful checks, publication skipped | Four dispatches all failed before jobs started |
| #109 bootstrap/workforce hardening | Merged; exact-head approval | Local and source authority are distinct from installed authority |
| #110–#113 offline foundation, route policy, registry and frontend archive | Merged; exact-head approvals | No application publication or deployment receipt established |
| #114–#117 JWT/OIDC, Signer archive and single-owner preparation | Merged; exact-head approvals | Provider authentication and live installation still require evidence |
| #118–#119 parameter drafts/validator | Merged; explicitly offline material | Draft inputs are not an approved execution packet |
| #120 force-Signer comment | Merged; successful offline/reproducibility checks | A template comment does not prove a signing job occurred |

Each PR #109–#120 has eight successful checks and two skipped checks in the
readback. The skipped service matrix and publication job do not establish an
image build or publication. The four Express runs are
[Express dispatch one](https://github.com/cesar-guzman/scanalyze-deployment-platform/actions/runs/34495798769),
[Express dispatch two](https://github.com/cesar-guzman/scanalyze-deployment-platform/actions/runs/34496159838),
[Express dispatch three](https://github.com/cesar-guzman/scanalyze-deployment-platform/actions/runs/34497827861),
[Express dispatch four](https://github.com/cesar-guzman/scanalyze-deployment-platform/actions/runs/34497913910).
All ran at `16dec52b2522e80f2a85ad9551ee3a0cdafbb4a8`, all `startup_failure`.
The last run returned no jobs. The nested permission mismatch below is a
reproduced source defect and likely cause; a remote failure annotation was not
retrieved.

PR #121 publication readback verified all eleven committed file SHA-256 values
against the reviewed packet and a clean worktree. The initial hosted snapshot
had twelve successful checks, two failures, Python still running and publication
skipped. Terraform, seven service validation jobs and frontend reproducibility
passed. Successful service jobs do not independently prove image construction;
their build steps may skip when the corresponding inputs are absent.
Security sentinel failed in the
[PR validation run](https://github.com/cesar-guzman/scanalyze-deployment-platform/actions/runs/35553633763).
Release dry-run failed in the
[reproducibility run](https://github.com/cesar-guzman/scanalyze-deployment-platform/actions/runs/35553633747).
Both annotations report exit 2. The latter target depends on `security-check`,
so a shared cause is plausible but not proven by step metadata. Downstream
checks skipped after the sentinel failure, including frontend E2E, did not pass.

Source inspection identified public eleven-digit run identifiers in this report
that match the sentinel's NSS rule. The follow-up uses the existing exact
allowlist mechanism: one report path, one complete repository-specific URL
line, the NSS detector and seven pinned value fingerprints. It preserves all
run links, scanner detectors and CI gates. Thirteen in-memory metadata contract
cases cover accepted identifiers and rejection of new values, other files,
non-URL context, other detectors and other repositories. Before the exception,
eight cases failed and five passed; afterward all thirteen passed, including an
independent rerun. `make docs-check` and `git diff --check` also passed. These
metadata tests do not scan repository content.
The local scanner diagnostic was rejected by automatic approval review for
possible sensitive-file/environment access and was not retried. The complete
sentinel and release dry-run still need hosted confirmation after publication.

## Findings and local remediation

### P1 — Express production could not start or validate its own request

Eleven offline jobs called a reusable workflow containing a live job requiring
`actions: read` and `id-token: write`; their callers granted only
`contents: read`. GitHub permits permissions to remain the same or decrease in
[reusable workflow chains](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations).
A regression on unmodified main found 22 incompatible requested permissions.
The production-only dispatch also rejected `production` during request validation.

The repair introduces `_terraform-layer-offline.yml`, used by those eleven
offline jobs. It validates the existing DAG and performs backend-disabled
Terraform initialization and validation. It has no live job or OIDC permission.
A closed production request v2 is admitted only in the Express lane. The old
nonproduction reusable and its Plan/Apply checks are unchanged. Production live
execution remains blocked pending reviewed authority integration.

Affected files: `.github/workflows/express-production-release.yml`,
`.github/workflows/_terraform-layer-offline.yml`,
`schemas/deployment-request-production.v2.schema.json`.

### P2 — Publication reported authorization without publishing

The legacy `Publication NO-GO` job only printed an authorization sentence and
returned zero. Two tests explicitly required that sentence. This is a false
success signal, not evidence of an unauthorized cloud write.

The job now emits an error and exits 1 until a protected publisher exists.
The restored assertions and a behavioral test execute the actual step without
external commands. That behavioral test failed before the fix and passed after.
Affected files: `.github/workflows/microservices-build.yml`,
`tests/test_gug124_build_once_contract.py`,
`tests/test_governance/test_workflow_gates.py`.

### P2 — Request tracking and evidence provenance were incomplete

A tracked symbolic link could point at an untracked JSON file and pass both
request validators. Both validators now reject symbolic links and paths that
resolve through links or parent traversal. Schema and JSON/YAML parse failures
produce sanitized messages. Negative tests exercise real shell steps and Git
tracking in temporary synthetic repositories.

The Express evidence producer also labeled production as `nonprod-release`.
Its workflow identifier, artifact name and path now identify Express production.
A behavioral test reads the produced JSON and verifies the exact source and
release pins, private file mode, `NO-GO`, and false publication/plan/apply flags.

### P2 — Product candidate has unresolved frontend acceptance defects

The full mounted SPA suite on the preserved candidate yielded 85 passes and one
failure: `tests/document_result_contract.spec.ts:151` expects `Historial`, which
the current `src/pages/BankStatements.tsx` removed. General bank history and CSV
are explicitly pending in that page. Do not skip the test to declare readiness;
restore the accepted feature or obtain a reviewed replacement contract retaining
result, nullable-field and actor-binding coverage.

Playwright discovery also imports six `node:test` browser harness files because
`playwright.config.ts` has no restrictive `testMatch`. Discovery returned zero
despite 51 failing TAP cases; the correct Node runner passes all 96 cases.
Integrate the complete candidate source, restrict Playwright to its specs, and
invoke Node harnesses explicitly in CI after Chromium installation. Failure of
either runner must fail the check.

The existing Axios metadata and upload clients have no finite configured
deadline. A local server that never replies leaves the request pending and can
retain the active operation. This predates the reviewed candidate. Add bounded
deadlines/cancellation while preserving ambiguous-write reconciliation and
idempotency keys. No automatic duplicate CREATE or submit retry is acceptable.

These product findings were not changed in GUG-421. They need separate source
integration and acceptance; they are not defects introduced by this workflow patch.

## Fresh validation

Counts below are scoped separately and may overlap between snapshots; do not
sum them into one production E2E result.

| Source / suite | Result | Evidence boundary |
| --- | --- | --- |
| Clean main: bootstrap, selection, identity adapters, DNS, document driver, VSA, registry, route policy and archive suites | 550 passed | Local, synthetic services |
| Preserved candidate: bootstrap, selection, DNS, metadata inventory, identity and production admission/workflow suites | 337 passed | Dirty candidate only |
| Preserved candidate: document driver/recovery | 263 passed | Synthetic HTTP, real protocol logic |
| Preserved candidate: ingest journey/assurance | 376 passed | Local service/router/repository |
| Preserved candidate: enrollment transport | 60 passed | Contract helpers, no installed broker |
| Preserved candidate: frontend unit / Node browser harnesses | 83 / 96 passed | Node 22.23.1, local Chromium |
| Preserved candidate: all nine Playwright specs | 85 passed, 1 failed | Synthetic sessions and API responses |
| Preserved candidate: TypeScript, ESLint, Vite build | Passed | Build output isolated locally |
| GUG-421 final regression suite | 306 passed | Actual admission/evidence shell steps, temporary Git repos, schema/governance/terminal identity |
| GUG-421 syntax/whitespace | actionlint 1.7.12 and git diff --check passed | Three changed workflows; embedded shellcheck was not run |
| Repository documentation/schema gates | make docs-check and make schema-check passed | Draft 2020-12 validation: zero errors; 55 selected schema regression cases passed |

The product-agent subtotal is 963 passed and one failed; discovery diagnostics
are excluded from it. Local servers were stopped after validation.

The GUG-421 final command is:

```sh
python3 -m pytest -q tests/test_governance/test_reusable_workflow_permissions.py tests/test_deployment/test_express_offline_admission.py tests/test_deployment/test_production_deployment_request_schema.py tests/test_gug124_build_once_contract.py tests/test_governance/test_workflow_gates.py tests/test_governance/test_gug123_terminal_identity.py tests/test_deployment/test_gug121_strict_contracts.py
```

The expanded JWT/OIDC/trust-root matrix initially had 764 passes and three SDK
closure failures. The host had botocore 1.42.57 instead of 1.42.97, s3transfer
0.16.0 instead of 0.16.1 and urllib3 2.6.3 instead of 2.7.0. The three unchanged
cases passed in 2.04 seconds in a temporary Python 3.11.14 venv installed from
the repository's seven-wheel hash-verified lock. These are reruns of the same
three cases, not additional tests or a fresh single-run result for all 767.
The verifier, lock and global packages were not changed.

An independent final review reran all 44 executable Express admission tests
successfully and found no remaining P1/P2 in the scoped patch. That review is
not a complete repository-wide security scan.

## Linear reconciliation

| Gate | Current property | Outstanding acceptance |
| --- | --- | --- |
| GUG-376 | In Progress | Upstream signing/runtime certification and GUG-365 handoff |
| GUG-215 | In Progress | Fresh reader window, broker/ledger authority and certified retirement |
| GUG-274 | Done | Historical repository closure only; live work belongs to GUG-206 |
| GUG-206 | In Progress | Governed authority installation, blocked by GUG-215 |
| GUG-124 | In Review | Immutable publication, signed evidence, promotion and rollback |
| GUG-117 | In Progress | Connected customer identity/lifecycle and multi-deployment isolation |
| GUG-127 | In Progress | Signed staging evidence, rollback/restore and acceptance |
| GUG-128 | Backlog | Production pilot remains blocked on upstream gates |

The [project activity update](https://linear.app/guguce/project/scanalyze-product-and-platform-delivery-f22d0fb5321e/activity#comment-3f66854c)
and [GUG-421 validation comment](https://linear.app/guguce/issue/GUG-421/repair-express-production-offline-admission-and-fail-closed#comment-ff43a55f)
were saved and read back. The pending browser-runner defect is tracked as
[GUG-422](https://linear.app/guguce/issue/GUG-422/separate-node-browser-harnesses-from-playwright-discovery-and-enforce)
(High / Backlog), and Bank history acceptance as
[GUG-423](https://linear.app/guguce/issue/GUG-423/reconcile-bank-history-acceptance-with-document-result-recovery-ui)
(Medium / Backlog). Both are children of GUG-127; neither was marked fixed.
The pre-existing transport-deadline gap is tracked as
[GUG-424](https://linear.app/guguce/issue/GUG-424/bound-document-api-and-upload-requests-without-duplicating-ambiguous)
(Medium / Backlog), also under GUG-127, with idempotency and reconciliation
acceptance criteria. Its description and properties were read back after creation.

The project overview and some issue descriptions are older than the comments;
embedded issue badges also differed from current properties. GUG-274 was not
reopened because its historical closure explicitly excludes live installation.
GUG-215's last documented reader window ended on September 16 and is expired.
No earlier approval window was reused.

## Connected checks and remaining prerequisites

The user authorized profile `905418363887_ScanalyzeSandboxDeploy`, account
`905418363887`, region `us-east-1`, for read-only inspection. The first STS call
failed because SSO expired. After renewal, STS verified the expected account.
The committed `tooling.production_readonly_inventory` collected fixed-query
metadata between `2026-09-21T02:17:55Z` and `2026-09-21T02:18:07Z`. Its private
local artifact is `production-metadata.json` in the assessment artifact directory,
outside Git. It remains `INCOMPLETE_METADATA`, not an accepted complete report.

- ECS returned no cluster ARNs in the authorized region.
- Scanalyze-name/alias filtered ECR, S3, DynamoDB, IAM, CloudFront and log-group
  metadata returned empty lists. Filters are discovery hints, not proof that
  unrelated names or resources in other regions do not exist.
- Route53 returned the public `prod.scanalyze.cloud` zone. CloudFormation
  returned one active unrelated scheduler stack and no Scanalyze stack.
- Four KMS keys were AWS-managed and enabled. SSM exposed 29 parameter names,
  types and versions; no values were requested. Parameter metadata does not
  establish existence or health of the referenced resources.
- ACM and Bedrock were `UNKNOWN / RESPONSE_INVALID`. Supplemental metadata-only
  queries observed an issued `api.scanalyze.cloud` certificate with algorithm
  `RSA-2048`, and authorized/available Nova Pro metadata for response model ID
  `amazon.nova-pro-v1`. The collector expects `RSA_2048` and exact request ID
  `amazon.nova-pro-v1:0`. These response-contract mismatches require a separate
  tested repair; the original report was not rewritten as successful. Certificate
  issuance does not prove routing or served TLS, and model availability does not
  prove invocation or an operational document pipeline.

Commands used: explicit-profile/region STS, the committed read-only inventory
with `--expected-account-id`, ACM `list-certificates` and Bedrock
`get-foundation-model-availability`, with fixed metadata projections. No cloud
mutation, parameter value, object content, log event or document was accessed.

Public DNS at `2026-09-21T00:50:00Z` returned four AWS nameservers for
`prod.scanalyze.cloud` and no A/AAAA answers for that name or `api.scanalyze.cloud`.
Apex delegation remained on Google nameservers and DEV had its existing AWS
delegation. This confirms delegation, not application reachability or TLS.

Real login/MFA/enrollment, tenant isolation against deployed services, synthetic
document upload through S3/SQS/OCR/extraction/result, retry/DLQ behavior, durable
retrieval, restore, alarms and rollback still need connected acceptance.
No customer document was used. The local optional passkey ownership path and
enrollment serializer do not establish an installed enrollment broker.

Next sequence: repair and confirm PR checks through ordinary review/CI gates;
integrate remaining candidate fixes issue by issue; repair the metadata response
contracts and collect fresh complete metadata; bind signed release and protected
execution inputs; review the
exact production command; then execute the separately authorized deployment and
connected acceptance. None of these gates may be replaced by local test counts.

## Changes, risk and rollback

No cloud resource, DNS record, database, queue, deployment or release was changed.
Local edits are limited to GUG-421 workflow/schema/tests, exact documented
sentinel exceptions and this documentation.
Linear was updated with the scoped implementation and remaining validation gaps.
The owner committed and pushed the reviewed packet and created draft PR #121.
The subsequent documentation/allowlist follow-up remains uncommitted. No merge,
manual workflow dispatch, artifact publication or deployment was performed.

Risk: the new offline workflow still needs complete hosted CI confirmation;
Terraform validation passed, but two required checks failed. It does not grant
production live capability.
The legacy publication job intentionally fails when selected until its protected
publisher exists. No Terraform resource definition changed, and no plan/apply ran.

Rollback before publication is to remove only the GUG-421 additions and revert
its targeted hunks. After publication, use a reviewed revert PR. Preserve the
historical dirty candidate and its worktrees; do not use a global clean/reset.

Automatic approval review prevented branch/protection queries and some verbose
agent-report writes. Protection remains unverified. Reduced metadata reports
and this scoped implementation record do not certify the blocked reads.
