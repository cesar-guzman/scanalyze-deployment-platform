# Monday production delivery

For the current independent review and local corrective work, see
[production validation — 2026-09-21](production-validation-20260921.md).
The dated observations below remain historical evidence, not current readiness.

Updated 2026-09-14 UTC (Monday after midnight in America/Mexico_City).
Target: initial production use on Monday, 14 September 2026.

**BLOCKED — DNS DELEGATED AND API CERTIFICATE ISSUED; APPLICATION NOT DEPLOYED.** This record separates current observations,
validated local repairs and the remaining release prerequisites. It does not
authorize publication, account registration, IAM changes or deployment.

## Working source and ownership

Worktree: `production-runtime-readiness/scanalyze-deployment-platform`.
Branch: `fix/production-runtime-readiness`.
Base and earlier verified GitHub main: `16dec52b2522e80f2a85ad9551ee3a0cdafbb4a8`.
The owner later supplied CLI output with the same main SHA and one environment,
`production`; this is not protected collector evidence. The selected environment
`scanalyze-dep_01M260EYHD8VGSR9MB6Q32BP9K-production` is absent from that output.
The existing uncommitted candidate has been preserved. The dirty primary
checkout and unrelated worktrees are not release sources.

The six-file bootstrap checkpoint was committed locally as
`fdbf25dc2a9e6d82aff800958ba51324adc03da8`. A separate clean detached worktree
built its canonical unsigned ZIP successfully, SHA-256
`8db796cd75e6cf11b46518281e37a4e7eeea7594fe0d83a540a5d939305eea8f`, and passed
all 103 GUG-274 tests with the authenticated SDK. That premerge package is not
deployable evidence. Review then identified that Lambda's mutable bundled SDK
may fail the exact version guard. The candidate now vendors the existing seven
pinned distributions; its trust-boundary and real-closure matrix passed 131
tests in root's run. The earlier package is superseded by the verified v2 build
from actual commit `997354d2891465268b8a58216bf99cf6203d8f36` described below.

The [recreation playbook](production-recreation-playbook.md) records the later
verified Signer, KMS, artifact foundation, active account identity instance and
disabled custom application. No users, service actors, normal-authority stack,
registry or application runtime have been installed by those steps. The KMS
adapter passed 114 tests in both Codex and Grok's runs. The new production
document-journey driver passed 221 tests in Codex's independent run; no connected
journey has been executed. A minimal synthetic Nova request was denied because
the installer profile lacks InvokeModel, and worker-principal verification
remains pending.

The owner identified CodeCommit in account `533420168743` as an additional
source for reusable improvements. After SSO renewal, the reviewer verified the
account and independent frontend repository, with main
`007b36c9733a8c289a61bb2c4532ee17787b096b` dated August 8. The bounded comparison
confirmed selection-feedback reuse and an inherited duplicate-CREATE retry
defect now corrected locally and verified in independent browser runs. See
[comparison and limits](codecommit-reuse-review-20260914.md).

Session continuity also passed 24 tests in real Chromium in both the product
agent's run and root's rerun. These tests reproduce delayed 403s, monotonic
clock boundaries and actor replacement during OIDC events. They verify client
continuity, not connected backend authentication or MFA.

The combined SDK/PKCE suite passed 186 tests in root's run. The actual callback
grant installation remains blocked: CloudTrail records `ValidationException:
Grant type: authorization_code not supported` for the single attempt at
`2026-09-14T06:52:54Z`. The exact application remains DISABLED with zero grants;
the write was not repeated. Resolve provider compatibility before activation.

The owner subsequently selected the JWT bearer alternative. Its local
[operator integration](../deployment/gug274-jwt-bearer-operator.md) now connects
the pinned public OIDC client, anonymous-pipe launcher, operation-bound JWT
prefilter and existing AWS/STS/CAS proof chain. The template supports explicit
v2 configuration and passed AWS `validate-template` without resource changes.
Read-only inventory still returned zero trusted issuers and zero application
grants; no real issuer or operator binding has been installed. Local tests
do not resolve the remaining upstream-token TTL/context compatibility check.

César then confirmed himself as the sole responsible owner. The explicit
[single-owner mode](../deployment/gug274-single-owner-decision-20260914.md)
records `independent_approval_present=false`, keeps Plan/review/Apply roles and
the existing Change Set CAS key, and expires within a reviewed maximum 24-hour
window. The operator guide and recreation playbook now use this selected mode.
The exact rendered template passed AWS validation with 28 parameters; this was
a read-only check, not installation. Real issuer/owner authentication, protected
publication, application installation and the production journey remain pending.

After the automated commit was denied, the owner created normal local commit
`997354d2891465268b8a58216bf99cf6203d8f36`. Codex matched its 20 files, blob hashes
and parent to the previous reviewed manifest. The index is empty. A private
review patch, file hashes and validation manifest are retained in
`/Users/cesarguzmanguadarrama/.codex/artifacts/scanalyze-production-20260914/review-checkpoint-20260914T0704Z/`.
The clean actual commit passed 186 tests, with no skips, and two independent
canonical builds produced identical ZIP and manifest bytes. The unsigned ZIP
contains 2,142 entries, is 22,420,992 bytes and has SHA-256
`6b6f957a5d87a2fe4cd5f7df25aa179d4cea281e49720cf9da43d2b35ae06879`.
It remains `deployable=false` / `NO-GO`. Its durable evidence checkpoint is
recorded in the playbook. No upload, signing job, protected-source publication
or production E2E has occurred. A successful query returned no branch PR;
branch-protection inspection was denied, and automatic review also rejected
saving the proposed PR body as possible sensitive-file access. No PR body was
created and no alternate route was used for either denied operation.
[Provider diagnosis and support draft](../deployment/gug274-provider-compatibility-20260914.md)
are ready for review; no case or alternative authentication flow was submitted.

- Codex: infrastructure binding, input transport, workflow, product recovery,
  human authorization composition, validation and integration.
- Antigravity: initial route-policy AST inventory/verifier; Codex took exclusive
  ownership after review found independent-pin and portable-test failures.
- Grok Bot: independently reviewed the production DNS compiler and reran 68 tests;
  previously repaired the two-phase bootstrap publication producer. Its latest
  four adversarial bulk-recovery tests execute the real modules in Chromium;
  Codex independently reran and accepted them.

For the latest frontend checkpoint, Codex owns the upload recovery, mounted
Bank page and Dashboard export repairs. Antigravity identified the polling and
reconnection defects; after its initial implementation failed review, Codex
took over the hook and page while a separate reviewer rebuilt the browser
tests. Antigravity then reviewed this delivery's recreation playbook read-only.

The external agents have explicit, disjoint file scopes. Their status messages
are not acceptance evidence; actual diffs and tests must be reviewed.
After the second Antigravity checkpoint, Codex took exclusive ownership of
identity adapter corrections and transport. Grok's publication producer is at
its reviewed local checkpoint; no external agent is executing cloud operations.

## Current connected observations

The owner supplied `905418363887_ScanalyzeSandboxDeploy`; after SSO renewal,
STS returned the expected account `905418363887`. All AWS commands specified
`us-east-1`. The following table records the earlier read-only inventory; the
subsequent owner-requested DNS mutation is recorded separately below:

| Source | Observed result | Limit |
| --- | --- | --- |
| STS GetCallerIdentity | Expected account matched | Identity, not permission to apply an unspecified plan |
| ECS ListClusters | Empty | No ECS cluster observed in this region |
| CloudFormation ListStacks, excluding DELETE_COMPLETE | Only `bcm-dev-ec2-rds-scheduler`, CREATE_COMPLETE | Preserve the unrelated scheduler |
| ACM ListCertificates, all seven supported key types | Empty | No regional certificate candidate |
| Route53 ListHostedZones, before DNS operation | Empty | Superseded for the new prod zone by the verified creation below |
| IAM ListRoles, Scanalyze/scanalyze/dep-/dep_ prefixes | Empty | No matching terminal/workload baseline role candidate |
| ECR DescribeRepositories | Only `base-images/python`, immutable tags | No published application release identified |
| S3 ListBuckets, scanalyze-/dep- prefixes | Empty | No matching backend/frontend/document bucket candidate |
| Bedrock GetFoundationModelAvailability, Nova Pro | AUTHORIZED; agreement, entitlement and region AVAILABLE | Model metadata only; no inference or chargeable processing performed |
| CFN DescribeType, AWS::Cognito::UserPool | Regional public schema supports WebAuthnFactorConfiguration | Handler execution and permissions not verified |
| Cognito ListUserPools plus narrow metadata description | One generic existing pool, us-east-1_bK2MLPTV2, with no selected ownership tags returned | Preserve it; ownership unknown, no users read or migration authorized |

GCP authentication was renewed by the owner. `gcloud dns managed-zones list`
in project `cs-poc-j1zdh7qfprmlptav4v1vkka` found public zone
`scanalyze-cloud` for `scanalyze.cloud.`. Its four Google nameservers match
public NS delegation. A bounded record listing confirmed the existing
`dev.scanalyze.cloud.` delegation to AWS; preserve it. No app/api production
record was returned. Public A queries for `app.scanalyze.cloud` and
`api.scanalyze.cloud` returned NXDOMAIN at 2026-09-14T01:09:56Z.

The owner supplied the management Founder PEP profiles. STS succeeded for
`839393571433_ScanalyzeFounderPepIdentityAdmin` after renewal, but IAM ListRoles
and Signer ListSigningProfiles were denied. The repository also limits these
profiles to the founder identity/bootstrap lane; they are not established
release publisher identities. The owner subsequently approved the existing
`839393571433_ReadOnlyAccess` and `042360977644_AWSReadOnlyAccess` profiles for
inventory. STS and Organizations ListAccounts with the former confirmed:

- `839393571433`: `mpa-aws-bcm-corp`, ACTIVE.
- `042360977644`: `scanalyze-platform-authority`, ACTIVE.
- `905418363887`: `BCM Corp AWS`, ACTIVE, the owner's selected destination.

The authority-account read-only session subsequently succeeded. IAM metadata
returned the existing AuthorityBootstrapPlan SSO role; DynamoDB listed no tables
and KMS listed one unclassified key. Signer listing, key description and SSM
metadata were denied. CloudFormation showed `scanalyze-platform-authority-state-backend`
in `REVIEW_IN_PROGRESS`. The owner explicitly authorized
`042360977644_ScanalyzeAuthorityBootstrapPlan` for read-only inspection; after
routine SSO renewal, STS confirmed account `042360977644`. DescribeChangeSet
showed `scanalyze-platform-authority-bootstrap-20260717150949`, created July 17,
`CREATE_COMPLETE` / `AVAILABLE`, containing only four Add operations: state S3
bucket/policy and KMS key/alias. It is an unexecuted backend proposal, not a
signing/publication deployment. DescribeKey remains denied with that profile.
No authority-account mutation, administrative substitution or permission change
occurred; the old change set was not executed.
Follow-up bounded Signer listing and SSM parameter metadata listing with the
authorized Plan profile were also denied. No parameter values were requested.
The owner then requested investigation and selection of the two installer-profile
candidates. STS proved that `ScanalyzePlatformAuthorityBootstrap` actually uses
`AWSAdministratorAccess`; the Founder Apply candidate returned SSO `No access`.
Bounded IAM inventory found only the canonical Scanalyze Plan role. The
[installer decision](authority-installer-profile-decision-20260914.md) selects
the normal governed bootstrap path, whose Approval/Apply roles and services
remain unestablished. The administrator session was used only for this authorized
read-only investigation. It also identified the previously unclassified key as
an AWS-managed symmetric encryption key, with no regional Signer profiles or
Scanalyze-prefixed Lambda functions returned. No installer substitution occurred.

The owner explicitly selected **`prod.scanalyze.cloud`** and requested creation
of the new subdomain. Codex created public Route53 zone `Z09109262K9DWFLJCUDF2`
in account `905418363887` at `2026-09-14T04:11:44.597Z`; AWS change
`C0304452DD3DLARO1R8Y` was read back `INSYNC`. GCP change `105` added exactly
one production NS record (TTL 300), with no deletion or SOA update, and reached
`done`. Readback at `04:14:14Z` matched all four actual AWS nameservers; all four
previous parent records remained unchanged. Public resolver and authoritative
Google DNS both returned the new delegation. Apex and DEV retained their original
NS. [DNS evidence and exact operations](production-dns-handoff.md) include the
resource IDs, server values and private metadata directory. The subsequent API
certificate operation returned `3f5e694a-a088-49ca-8010-c1be288d05c7`; GCP change
106 added its exact validation CNAME. At 05:32:29Z, ACM reported `ISSUED` and
public/authoritative DNS matched, with all five preceding parent records intact.
The certificate is ready; ALB attachment and the application remain pending.

GitHub PRs 105–108 are merged. Four Express Production dispatches on main
ended in `startup_failure`; the last was
[run 34497913910](https://github.com/cesar-guzman/scanalyze-deployment-platform/actions/runs/34497913910).
Its caller lacked permissions required by the reusable workflow. Successful
push CI and merged PRs did not publish or deploy the local candidate.

Automatic approval review rejected direct main/environment and branch-protection
reads because approval was required while approval mode was Never. The later
owner-provided main/environment output is recorded above with that provenance;
it does not establish protection settings. Rejected reads were not retried
through another tool. Environment protection remains unverified.
The connected Linear workspace exposes SCA onboarding issues, not the GUG
delivery workspace; no issue was substituted or changed.

## Read-only collector response compatibility (GUG-425)

The metadata collector, `python3 -m tooling.production_readonly_inventory`,
accepts two narrowly observed response variations from the September 21, 2026
metadata investigation. This parser correction does not refresh the historical
observations above or establish a connected deployment. Its regression tests use
an injected CLI runner and forbid real subprocesses.

- ACM response `key_algorithm` accepts `RSA-2048` in addition to the existing
  values, preserving the returned spelling. The outbound `--includes keyTypes`
  filter remains unchanged and contains `RSA_2048`. The official
  [CertificateSummary response contract](https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateSummary.html)
  also documents the underscore spelling; the hyphen spelling is compatibility
  with the observed CLI response, not a newly documented AWS enum. No other
  hyphen or case variant is inferred, and certificate account/region checks
  remain binding.
- Bedrock still sends the exact requested model ID and accepts an exact echo.
  The only additional pair is request `amazon.nova-pro-v1:0` with response
  `amazon.nova-pro-v1`. The item retains the returned `model_id` and adds
  `requested_model_id`; the report scope and `exact_model_id` filter retain the
  request. The official
  [availability response contract](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GetFoundationModelAvailability.html)
  permits model-ID strings but does not document this specific alias pair.
  Other versions, sibling models and reverse aliases are not inferred.

Unknown algorithms, model mismatches and unsupported availability statuses still
produce `UNKNOWN` / `RESPONSE_INVALID`. `NOT_AUTHORIZED`, `NOT_AVAILABLE`,
`PENDING` and `ERROR` retain their observed meanings; even a fully observed report
keeps `production_authorized=false` and `readiness=NOT_EVALUATED`. Availability
metadata does not prove model invocation, tenant access or application readiness.

The local GUG-425 candidate was validated with 55 regression cases (also rerun
independently); the two positive compatibility cases failed before the fix.
A subsequent connected read used profile
`905418363887_ScanalyzeSandboxDeploy`, region `us-east-1`, and STS verified account
`905418363887` at `2026-09-21T02:33:53Z`. Between `02:33:52Z` and `02:34:04Z`, all
thirteen metadata categories were observed. ACM retained `RSA-2048` and Bedrock
retained both requested and returned IDs. ECS returned no cluster ARNs in the
region; filtered resource metadata and DNS checks still do not establish an
application runtime. The new private artifact `gug425-production-metadata.json`
has SHA-256 `63f859a7557e3ca4ff2e0514bcfd696161d97ee14b49cb8106e6c4a16dbcac72`.
The earlier `INCOMPLETE_METADATA` artifact was preserved. This connected result
validates the local parser against observed responses, not hosted CI, publication,
deployment, model invocation or application E2E. No cloud write occurred.

Rollback is to revert only this issue's collector, regression-test and runbook
changes; the prior parser will again reject these two observed response forms.

## Repairs validated during this continuation

| Change | Current local evidence |
| --- | --- |
| Selection must match the exact requested layer and declared AWS partition | Four new negative cases failed before the repair; selector suite now 36 passed |
| Three infrastructure inputs reach real Terraform-variable JSON | 500 focused transport/deployment tests passed, including signed-release verification, real materializer/controller/argv/CLI and 0600 outputs; missing/altered sources fail without output |
| Express offline reusable no longer inherits live OIDC/action requirements | 295 focused workflow/admission tests passed; official actionlint 1.7.12 accepted Express, offline and live reusable workflows |
| Late document A response cannot replace document B; failed GET is retryable | Source-main regression reproduced; 11 Chromium tests passed in the destination worktree, plus TypeScript and ESLint |
| Passkey uses exact SPA client and explicitly selects WEB_AUTHN | 342 authentication tests and 20 services Terraform mock runs passed; no password/OTP fallback or authority relaxation |
| Human authorization runtime is composed at startup only with complete configuration | Complete ingest API suite 1125 passed; consistent membership reads and durable audit write/readback precede the effect; activation stays closed until live dependencies exist |
| Human token scopes follow the current role during HostedAuth and refresh | 263 tests passed; disallowed Scanalyze scopes are suppressed; refreshed membership does not reset authentication assurance |
| Bootstrap content and publication are separate phases | Codex independently reran 39 tests after Grok's receipt-integrity correction; changing object versions changes only the parent, and complete receipts are checked against the anchored tuple/digest |
| GCP DNS handoff supports the explicit prod delegation without an API certificate | 61 tests passed and Grok independently accepted the change; real zone/NS publication and full parent-record preservation were verified |
| Session renewal and passkey bridge preserve actor/session continuity | Frontend check passed (82 unit tests, types, lint, build); 82 Chromium tests passed, followed by 22 focused final cases; real enrollment/RP/Cognito configuration remains pending |
| Passkey requests carry the initiating session through the JWT gateway | Chromium reproduction failed before the header repair; all 24 session cases then passed, plus TypeScript and scoped ESLint; gateway 401 at either phase does not publish a replacement session or retry an effect |
| CloudFront preserves already versioned v1 passkey paths | Two executable regressions failed on duplicated `/v1`; six Node composition tests and 70 document/config regressions passed after the repair and obsolete test-input correction; all 82 frontend unit tests and the production build passed |
| Invalid chunks, provider output and truncated OCR cannot become completed extraction | Complete worker suites passed: bank 112, personal 184, government 80; the reproduced partial-success cases now fail before final artifacts/completion/handoff |
| Identity artifact verification and seven root inputs reach the actual caller | 603 adapter/transport/regression cases passed, with separate document/manifest pins, actual HCL SHA-256 validation and an explicit optional Cognito ownership setting; real publication and registry evidence remain absent |
| Identity archive path digest matches the signed artifact without ambiguity | Six real CLI negative cases failed before the correction; 112 adapter/transport/root-guard cases passed afterward, including the nine new negative/positive address cases |
| Application KMS/frontend storage and explicit OAC second phase | Latest agent checkpoint: 174 Python cases and 32 Terraform mock runs passed; roots/modules validate and generated OAC template passes cfn-lint; independent review found and closed the R-to-R+1 release cycle; no storage installation |
| Protected application storage reaches real plan/apply hooks | 860 Python regressions passed; exact initial/apply file layouts, durable binding, current readbacks and historical OAC release pins preserved. Reproduced directory-emptiness and next-release cycle failures repaired; bash syntax checks passed |
| Cognito can express passkey MFA without changing the native default | Full module 35 mock runs and root/module validation passed; complete CloudFormation schema parity and both forbidden owner switches were verified locally; no enrollment or runtime activation |
| Authority root has explicit production admission and registry v2 attribute parity | 25 Terraform mock scenarios and 44 Python cases passed; Codex independently reran all 44 Python cases. Production defaults off, trust unchanged, IAM adds only runtime_origin; no authority installation |
| Cognito email-only invitation preserves generated identity and reserves the provider effect | Complete ingest suite 1139 passed, including 14 new ambiguity/concurrency/receipt cases; Codex independently reran 38 focused provider/lifecycle cases; no real invitation or membership write |
| Offline edge route policy verifies mounted source and independent pins | 67 focused cases passed and were independently rerun by both reviewer and coordinator; the reviewer also checked 144 synthetic route/scope combinations. Dependency rebinding was reproduced and corrected; source provenance, transport and production publication remain external prerequisites |
| Conditional registry I/O preserves existing transition authority | 180 tests passed and were independently rerun by Codex; independent review also validated 7 negative probes and 6 SDK request shapes, with no P1/P2 found. Client identity, installed table and protected operation/anchor delivery remain external |
| VSA producer admits inputs before a single injected signature and verifies afterward | 135 tests passed and were independently rerun by Codex; 55 differential gate cases preserved admission outcomes. Real artifact/evidence assembly, upstream authentication and a connected signer remain absent |
| Offline publication derives ten verified destinations and compares complete readback | 115 tests passed, including 62 preparation/readback cases; Codex independently reran the suite. Historical OAC binding and input snapshots preserve the new-release path. No copy executor or frontend archive expansion is implemented |
| Bulk and Bank preserve file identity across ambiguous CREATE/SUBMIT, reload and session changes | Root independently passed 21 Chromium cases plus Grok's four adversarial cases; three workers maximum, current-tab journal, explicit recovery and confirmed-submission labels. General bank history and CSV remain unavailable |
| Dashboard export matches the implemented filters and cannot download after an actor change | Root independently passed 12 Chromium cases, including same-event double invocation, session replacement before React and unmount; health failures are no longer shown as available |
| Artifact helpers target the mounted v1 routes while document status/result retain v2 | The executable Axios URL test failed for both helpers before the correction, then passed for all eight calls |
| Reviewed SDK can be recreated from its seven hash-pinned wheels | 22 focused provisioner tests passed in root's rerun; fresh installation passed the existing validator and reproduced the same unsigned 997354d ZIP and manifest |
| Status polling preserves one request/timer and allows GET-only reconnection | 11 real Chromium cases passed in the author and root runs, including hidden backoff, stop/start with pending response, unmount and the mounted DocumentPage buttons; app TypeScript and scoped ESLint passed |

Codex also independently reran the storage foundation/OAC and DNS suites together:
143 cases passed, followed by 27 critical storage release/freshness/real-hook
cases after the final controller correction. This does not include installation or connected processing.

Counts belong to overlapping suites and must not be added as a unique total.
The latest four disjoint frontend browser files contain 48 passed cases:
21 Bulk/Bank, four Grok adversarial recovery, 12 Dashboard and 11 polling. Codex
independently ran each finalized file. The executable Axios URL case also passed.
These later changes received app TypeScript and scoped ESLint checks; a full
application build and connected production journey were not rerun. Earlier broad
checks in the table are historical checkpoints, not validation of every later edit.
Final scoped checks covered syntax, JSON and whitespace for 23 changed/new
files; tracked `git diff --check` passed. This local checkpoint includes the
untracked additions explicitly and does not claim current GitHub CI.
Browser/provider fixtures do not prove a real Cognito login or document journey.
The infrastructure and identity changes provide transport for ten of the prior
twelve missing inputs. The edge route-policy and legacy-identity handoff
adapters remain unresolved; all ten transported inputs still need actual
independent production authority. Empty identity transport now fails explicitly
instead of being described as a successful E2E test. Separate storage ownership
and Cognito-mode integration gates are tracked beyond that original inventory.
The [extraction review](extraction-output-readiness.md) also records unresolved
long-document output budgets and processing latency; rejecting incomplete output
does not prove representative long statements can finish.

## Remaining dependencies before deployment

1. Establish a working registration and sign-in path at the exact SPA passkey
   origin, plus the reviewed second-phase human-runtime activation. Preserve
   recent phishing-resistant MFA and tenant isolation. Native AWS provider
   5.100.0 cannot express the required factor; the optional single Cloud Control
   owner is now implemented with full control parity and the native default
   preserved. [Ownership evidence](cognito-passkey-ownership.md) records the
   module and lifecycle checks. Real origin/enrollment, installer permissions,
   handler behavior and live configuration readback remain open.
2. Obtain actual bootstrap content/publication anchors and publish/read back
   immutable child template versions. The local producer now separates stable
   content from publication; synthetic VersionIds are not installation inputs.
3. Review the completed local storage/OAC transport and obtain actual installation
   and fresh readback evidence. The phase transition and protected seven-input
   transport are implemented, with the historical-edge/current-release cycle
   corrected. See the
   [OAC interface review](application-storage-oac-phase2-interface.md) and
   [protected storage transport](../deployment/application-storage-runtime-authority.md).
   Keep CreateKey and key-policy administration absent from ApplyRole.
4. Complete the [publication authority prerequisites](publication-authority-readiness-20260914.md)
   and obtain the actual shared publication/signing authority, independently
   anchored registration and immutable release evidence. Only synthetic
   release bundles were found in the inspected repository paths; no production
   VSA trust policy/source release is established.
5. Bind actual DNS, certificates, log groups, route policy and identity handoff
   evidence; prepare exact bootstrap/layer plans, cost bounds and rollback.
   [The edge audit](edge-runtime-input-readiness.md) accounts for 52 mounted
   routes, including 48 with operation metadata, and identifies two phantom
   endpoints in the synthetic fixture. Passkey prefilters, publication selection
   and verified legacy-identity disposition still require explicit authority;
   the audit does not create a deployable map or set handoff to true. The
   [route verifier](edge-route-policy-verifier.md) now validates external pins,
   the fixed repository schema, mounted source graph and necessary scope across
   allowed principals/operations. Independent review closed the dependency
   rebinding defect. Protected transport, externally authenticated source-commit
   provenance and an explicitly reviewed production route policy remain pending.
   The owner-requested prod DNS delegation and API certificate issuance are
   complete and verified. No application alias or ALB attachment is evidenced.
6. Publish/merge and execute only after the concrete reviewed actions are
   authorized. Read back installed versions/resources, then test authorized
   sign-in, synthetic upload, OCR/extraction, persistence, result retrieval,
   retries, session expiry and cross-tenant denial against the deployed system.

Cloud writes now include the prod zone/NS, API certificate/CNAME, canonical
bootstrap Signer profile and P-256 release signing key. The latter key has no
Sign grant. The three-resource bootstrap artifact foundation reached `CREATE_COMPLETE`;
its S3/KMS policies and controls were independently verified at 05:58:38Z.
See [installation evidence](gug274-artifact-foundation-installation-20260914.md). Two local bootstrap commits now exist; the broader product candidate is uncommitted. No Terraform plan/apply,
push, merge, workflow dispatch, inference, real document access or production
acceptance occurred. Local evidence does not prove the Monday release is ready.

### Decisions and external prerequisites

The owner explicitly authorized autonomous creation, publication, deployment,
testing and a recreation playbook. TLS and the prod subdomain are resolved.
Signer `fo5PB1XOji` is Active; release key
`4d1420e0-ab6f-4d24-a31b-090ba4144427` is ECC_NIST_P256/SIGN_VERIFY with no Sign
grant. Protected release execution and registry authority still need actual
installation and independently authenticated evidence. The
local production-admission patch, registry I/O, VSA signing port and offline
copy preparer/readback verifier are implemented. Authenticated operation and
anchor delivery, actual release evidence assembly, a connected signer and the
copy executor remain absent. A profile name or backend-only change set does not
satisfy these dependencies. The
[archive permission proposal](../deployment/artifact-publication-permission-plan.md)
records the missing two-Lambda S3/KMS destination grants and the boundary update
that must be derived from actual installed contracts before review.

The [enrollment and activation plan](passkey-enrollment-activation-plan.md)
identifies a material lifecycle decision before human activation: Cognito's
reserved scope permits passkey registration and direct user self-service,
including deletion. Native USER_AUTH already emits it. Preserving exclusive
application lifecycle requires a server-held enrollment token and suppression
of that scope from every browser issuance; a browser enrollment wrapper alone
does not enforce that boundary. No grant or activation was added.

A subsequent automatic local hook blocked an attempted source/configuration
read needed for lifecycle startup review, stating possible sensitive-data access.
That blocked read was not repeated through another route. This is separate from
the earlier rejected GitHub Environments metadata request.
Automatic review also blocked updating the obsolete SDK recipe in
`normal-authority-installation-20260914.md` as possible sensitive-file access.
That document remains unchanged; the independently prepared
[SDK provisioning guide](../deployment/gug274-sdk-provisioning.md), linked from
the recreation playbook, supersedes its defective fresh-root recipe. The denied
operation was not retried through another tool.

## Rollback

Application changes are local. Review/revert only the specifically owned patches,
preserving the previous worktree edits. A future first installation has no
known-good production release: close admission on failure and retain keys,
documents, queues, memberships and evidence. Do not destroy the environment or
erase state to recover from an incomplete installation.

The new DNS delegation has a separate rollback boundary: review only the exact
new production NS record against fresh readback; preserve apex/DEV and retain
the child zone until dependencies are assessed. No automatic teardown is planned.

The CodeCommit review now includes the actual independent frontend repository
in account `533420168743`, after renewed SSO and successful STS. The earlier
dirty local clones were preserved. [The comparison](codecommit-reuse-review-20260914.md)
records exact source hashes and limits; source reuse and browser tests do not
establish the historical or current deployed application's behavior.
