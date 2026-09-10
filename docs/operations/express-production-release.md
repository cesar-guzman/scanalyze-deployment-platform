# Express production release — 11 September 2026

## Delivery decision

The owner requested an express production version for Friday, 11 September 2026
(America/Mexico_City), and corrected the target to a **new environment**. The
existing DEV installation is not a deployment target for this release.

The owner subsequently confirmed account `905418363887` for that new production
environment in `us-east-1`. This supersedes its historical sandbox designation
for target selection. The existing Zendesk integration must remain intact. The
confirmation selects the destination; cloud mutations still require the exact
reviewed deployment action and plan.

The initial proposed product scope is one bank-statement journey: a named user
signs in, uploads a PDF, follows processing, and reads the extracted result.
Processing and persistence must be real. Browser fixtures are local regression
evidence only. Additional document families and bulk/onboarding features are
outside this first acceptance scope; their runtime availability has not been
changed by this patch.

This note records preparation and a proposed delivery sequence. It does not
authorize a cloud write or amend the deployment, identity, or release policies.
The express exception's concrete changes must be reviewed against the selected
account and release before execution.

## Preparation evidence — 10 September 2026

| Surface | Observation | Meaning |
| --- | --- | --- |
| Source baseline | `main@914ffad7c1aca0e3443be7d6a965c80a935afb17` fetched from GitHub | PRs #104 and #105 are merged; current patch remains local |
| Local candidate | `codex/friday-express-production` | API-path, canonical-result, upload-recovery and infrastructure preparation; no commit or publication |
| Baseline CI | [Reproducibility check 123456789](https://github.com/cesar-guzman/scanalyze-deployment-platform/actions/runs/123456789), completed successfully on `914ffad7...` | Baseline frontend reproducibility only; local patch has not run in GitHub CI |
| Frontend validation | Typecheck, lint, build, 82 unit tests and all 57 Chromium tests passed, including navigation and actor-change races | Local behavior with simulated services; no real login or OCR proof |
| Physical-name validation | Six Terraform mock runs and `terraform validate` passed in three modules with AWS provider 5.100.0 | Synthetic provider plans only; no AWS plan or state access |
| Routing/TLS validation | 61 Terraform tests passed: 39 services (including its two physical-name cases), 20 edge-identity, 2 services-root; four `validate`, 32 strict-contract tests and ownership/interface/schema checks passed | Mock provider; TLS hostname changes were verified to change the deployment digest; no live certificate/target-health proof |
| Independent patch review | Review found and corrected a late-response journal overwrite after navigating away; final bounded review found no additional P1/P2 | Static review plus a passing browser regression; not a required human approval |
| Historical application | Public `app.dev.scanalyze.cloud/config.json` returned HTTP 200, `env=dev`, `cognitoRegion=us-east-1`, API base `https://dev.scanalyze.cloud/api/v1` | Older configuration/API contract; not the current main release |
| AWS identity | Read-only profile `905418363887_AWSReadOnlyAccess`, `us-east-1`, STS account match | Session refreshed successfully; account identity only |
| Narrow account inventory | 0 ECS clusters, 0 ALBs/NLBs, 1 HTTP API belonging to an existing Zendesk integration | Account is not empty; do not alter the unrelated integration |
| CloudFront response | CLI returned an empty aggregate object with no `DistributionList` | No distribution observed; not evidence that the DEV domain belongs to this account |
| Additional account metadata | Existing VPC `10.0.0.0/16`, EC2/RDS scheduler stack and immutable base-image repository; no hosted zones returned | Preserve existing resources; choose new network and resolve DNS ownership |
| Parameter inventory | SSM `DescribeParameters` denied for the Scanalyze prefix | Existing parameters remain unknown |
| Production target | Owner-confirmed new production environment in account `905418363887`, `us-east-1` | Deployment identity, hostname, resource plan and execution approval remain to be completed |

Only public configuration metadata and AWS control-plane metadata were read.
There were no application writes, customer-document reads, object/log/state
reads, infrastructure mutations, commits, pushes, or deployments.

## Implemented product fixes

`src/api/documentApi.ts` now appends `/v2/...` to the configured same-origin
`/api` base for create, submit, status, and result. Previously Axios constructed
`/api/api/v2/...`.

`src/domain/documents.ts` reuses the canonical `BankStatementResult` type.
`DocumentPage.tsx` and `BankStatements.tsx` consume its nested data, 0–100
confidence, warning codes and credit/debit direction. A missing amount remains
missing rather than becoming zero. Empty transactions are displayed explicitly.

The upload regression now matches exact URL paths and checks extracted values.
Five additional browser tests cover nullable results, warnings, zero confidence,
empty transactions, denied access, and history consumption. A configurable
Playwright port allows testing this isolated checkout without reusing another
running frontend.

`Upload.tsx` now journals the original CREATE key before sending it, reconciles
unknown responses, renews capabilities for the same document, and checks status
before retrying an uncertain SUBMIT. Storage failures stop the next write.
Expected-subject checks bind API dispatch to the initiating user; unmounted
views and journal key comparisons prevent late responses from overwriting a
newer operation. See [browser upload recovery](document-upload-recovery.md) for
the exact flow and the same-tab storage limitation.

Physical names now preserve the full deployment identity while meeting AWS
limits: a 30-character ALB name, an S3-safe documents bucket name, and a
31-character target-group name derived from both complete identifiers. These
changes may force replacements if applied to an existing deployment; this
candidate targets a new environment.

`modules/services/alb_routing.tf` connects explicitly selected HTTP services to
the ALB listener before ECS registration. Routing requires complete service
coverage, unique priorities and bounded V1/V2 API paths; workers remain
unrouted. `modules/edge-identity/api_gateway.tf` now enables TLS/SNI with a
required certificate hostname and preserves the request path. TLS and path
configuration are included in the manual deployment digest. The upstream
listener's default 404, JWT scopes and security groups are unchanged.
The [API routing note](../deployment/express-production-api-routing.md) describes
the required inputs, path semantics, certificate binding and rollback.

The new root inputs still require a reviewed transport path in the deployment
engine. The current baseline role also lacks listener-rule creation permission.
These execution prerequisites are documented in the deployment packet; this
local infrastructure patch does not make the existing controller ready for
production.

From `frontend/scanalyze-frontend-ui`, with repository-compatible Node 22:

```sh
npm ci
npm run check
SCANALYZE_E2E_PORT=5187 CI=1 npm run test:e2e
git diff --check
```

`npm ci` reported zero dependency vulnerabilities at its observation. Terraform
mock validation used isolated temporary copies and the repository's locked
provider; locks and provider requirements remain unchanged. A preexisting S3
lifecycle warning about missing `filter`/`prefix` remains outside this patch.
Automatic review rejected the optional wrapper that would rerun naming tests
against the original formulas, citing sensitive file/environment access. It did
not execute; the six positive mock runs and three validations completed.
All later routing suites passed, including the updated physical-name cases in
services. The final scoped routing review found no additional P1/P2 regression.

No broader security assessment, backend regression suite, real infrastructure
plan, live processing test, or production validation has run for this candidate.
Backend code has not changed; connected validation requires the prepared
environment and reviewed execution action.
`tflint`, `checkov`, `trivy` and `tfsec` were not installed locally, and no
configuration for them was found in the inspected workflows/scripts; those
additional scans were not run.

## Remaining release work, in order

1. **Bind the new production deployment.** The account and region are confirmed:
   `905418363887`, `us-east-1`. Bind deployment/customer identity, DNS,
   isolated data/runtime resources, operator and cost limits. Produce a reviewed
   plan that preserves the existing integration and DEV application. The
   [deployment preparation packet](../deployment/express-production-execution-plan.md)
   records verified inventory, exact source gaps, required inputs and order.
2. **Complete the human result-access path.** The current Cognito membership
   adapter in `backend/workers/scanalyze-ingest-api/app/auth.py` creates a snapshot
   with no assurance evidence. `RESULTS_READ_FULL` in the v2 router requires
   recent phishing-resistant MFA and trusted event provenance through
   `enterprise_authorization.py`. Design and implement the provider-backed
   adapter and test the real sign-in/step-up flow. Do not invent assurance or
   substitute an M2M result for human acceptance. A concrete
   [human access design](../deployment/express-production-human-access.md) is
   available, including provider limitations and negative/connected tests.
3. **Validate upload recovery against the connected deployment.** Local recovery
   is implemented, including uncertain CREATE/PUT/SUBMIT and late-response
   handling. Verify real ledger, S3 and queue behavior. Closing the tab can lose
   the local recovery reference; operator-assisted reconciliation remains a
   release operating requirement.
4. **Prepare an executable release and production plan.** The microservices
   publication job deliberately exits with NO-GO, and the nonproduction release
   engine rejects production. Reuse the established infrastructure layering,
   immutable artifacts and release contracts while preparing the exact express
   production route. Review its policy/workflow/IAM changes and rollback before
   enabling execution. Renaming a production target to `dev` is not a release
   mechanism.
5. **Validate the deployed candidate.** Match frontend configuration, API v2,
   workers and image digests. Use synthetic PDFs first; demonstrate the human
   journey, result accuracy, duplicate handling, failed-processing visibility,
   denied foreign access, monitoring and recovery. The current
   `document-journey-smoke.py` supports only DEV/STAGING and is insufficient as a
   production or browser certification tool.
6. **Open the initial production cohort.** Release only the proven scope with an
   identified operator, bounded volume/cost, rollback reference and explicit
   production execution approval. Keep the production decision tied to the
   actual immutable candidate and environment.

## Target schedule and rollback

- **Wednesday night / Thursday:** bind the new destination, resolve human access
  and upload recovery, prepare the release/plan and required reviews.
- **Thursday:** provision the approved new environment, deploy the candidate,
  validate synthetic processing and rehearse recovery.
- **Friday:** admit the initial users after acceptance evidence passes.

This is a target schedule, not a claim that the new environment is deployed or
that delivery is assured. The identity and publishing gaps make the date at risk
until they are closed.

Local rollback is to discard only the named patch in this isolated worktree.
Before any deployment, record the last valid release and configuration. For a
first deployment without such a release, rollback initially means closing
admission and preserving data/evidence for reconciliation; it must not silently
delete documents or shared resources. No cloud rollback is currently needed.
