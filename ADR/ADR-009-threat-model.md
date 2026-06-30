# ADR-009: Threat Model, Data Boundaries, Logging and Observability

> **Status**: `DRAFT rev3`  
> **Date**: 2026-06-25  
> **Decision makers**: César Guzmán  
> **Scope**: Scanalyze Dedicated Deployment Platform  
> **Depends on**: ADR-001, ADR-002, ADR-003 rev3, ADR-004 rev3, ADR-005, ADR-006 rev3, ADR-007 rev3, ADR-008 rev3, ADR-010 rev3  
> **Rev3 changes**: Reconciliation with all rev3 ADRs — new Domain 9 (Migration & Rollout, 10 threats), new Domain 10 (Economic & Availability, 4 threats), updated existing threats, corrected cross-references

---

## Context

Scanalyze processes regulated financial, personal and government documents containing PII. The platform operates across multiple AWS accounts with cross-account deployment orchestration, centralized artifact management, and customer-dedicated data planes. This threat model identifies and prioritizes threats across ten domains using the STRIDE classification.

---

## STRIDE Classification Reference

| Category | Description | Primary controls |
|---|---|---|
| **S**poofing | Impersonating an identity | Authentication, principal validation |
| **T**ampering | Modifying data or code | Integrity controls, signing, checksums |
| **R**epudiation | Denying an action occurred | Audit logging, CloudTrail, immutable records |
| **I**nformation disclosure | Exposing sensitive data | Encryption, access controls, masking |
| **D**enial of service | Disrupting availability | Rate limiting, redundancy, circuit breakers |
| **E**levation of privilege | Gaining unauthorized access | Least privilege, permissions boundaries, SCPs |

---

## Threat Domains

### Domain 1: Identity and Access

#### T1.1 — Orchestrator role compromise (S, E)

| Attribute | Value |
|---|---|
| **Threat** | Attacker compromises the ScanalyzeDeploymentOrchestrator role in Shared Services |
| **Impact** | Access to all customer accounts via assumed deployment roles |
| **Likelihood** | Medium (high-value target) |
| **Controls** | Exact principal trust (ADR-004 rev3), 6 scoped roles (Plan/Apply/Promotion/Validation/Diagnostic/StateRecovery), separate STS statements per action (AssumeRole, TagSession, SetSourceIdentity per ADR-004 rev3), session tags (`deployment_id`, `release_version`, `change_id`), SourceIdentity set once at first hop (`exec_<ULID>`), transitive tag control, short session (1h), CloudTrail, permissions boundary, MFA for human access to Shared Services, no persistent credentials. Roles bootstrapped via AccountVendingProvider (ADR-004 rev3), not by deployment pipeline |
| **Residual risk** | Medium — blast radius is all customers |
| **Test** | Assume deployment role without required tags → DENIED; Assume from wrong principal → DENIED; Assume without SourceIdentity → DENIED; TagSession with unauthorized tag → DENIED; SourceIdentity override on chained assume → DENIED |
| **Owner** | Platform security |

#### T1.2 — JWT forgery or misvalidation (S)

| Attribute | Value |
|---|---|
| **Threat** | Attacker presents a forged, stolen, or partially validated JWT to bypass customer identity |
| **Impact** | Cross-customer data access within a deployment |
| **Likelihood** | Low (Cognito-signed, per-deployment pool) |
| **Controls** | Full verification chain: signature (RS256 only) → kid against JWKS of matching issuer → issuer allowlist → audience/client_id → expiration → nbf/iat → token_use = access → required scopes → `custom:customerId == SCANALYZE_DEPLOYMENT_CUSTOMER_ID`. **NOTE**: API Gateway native JWT authorizer accepts only ONE issuer; during failover, a Lambda authorizer is required for multi-issuer validation (ADR-008 rev3 corrections). Lambda authorizer must validate ALL checks above, cache JWKS per issuer, and fail closed if JWKS is unavailable |
| **Residual risk** | Low — per-deployment Cognito isolates pools |
| **Test** | Forged token → REJECTED; Expired token → REJECTED; Wrong audience → REJECTED; Missing customerId → REJECTED; Algorithm=none → REJECTED; JWKS from wrong domain → REJECTED; Issuer not in allowlist → REJECTED; Token from decommissioned pool → REJECTED |
| **Owner** | Application security |

#### T1.3 — Lateral movement between customer accounts (E)

| Attribute | Value |
|---|---|
| **Threat** | Process in customer account A accesses resources in customer account B |
| **Impact** | Cross-customer data breach |
| **Likelihood** | Very low (no network routes, no shared roles, no shared credentials) |
| **Controls** | Account boundary (strongest isolation), no VPC peering/TGW between customers, per-account KMS, per-account IAM roles, SCP restrictions, no shared Security Groups |
| **Residual risk** | Very low |
| **Test** | Attempt cross-account S3 access → DENIED; Attempt cross-account DDB access → DENIED; Attempt cross-account SQS access → DENIED |
| **Owner** | Platform security |

#### T1.4 — IAM user persistence (S, R)

| Attribute | Value |
|---|---|
| **Threat** | Long-lived IAM user credentials leaked (SEC-PLATFORM-001) |
| **Impact** | Persistent unauthorized access; no session expiration without explicit revocation |
| **Likelihood** | Medium (current state — IAM user with long-lived access keys) |
| **Controls** | Migrate to IAM Identity Center permission sets, retire all IAM users, SCP deny `iam:CreateUser` and `iam:CreateAccessKey`, automated key age alarms |
| **Residual risk** | **HIGH** until SEC-PLATFORM-001 is resolved |
| **Test** | `iam:CreateUser` → DENIED by SCP; Access key age > 90 days → ALARM; IAM user count in account → monitoring metric |
| **Owner** | Platform operations |

#### T1.5 — Break-glass abuse (E, R)

| Attribute | Value |
|---|---|
| **Threat** | Break-glass access used for routine operations or without audit |
| **Impact** | Unaudited privileged actions; erosion of least-privilege model |
| **Likelihood** | Low if procedures are enforced |
| **Controls** | Break-glass limited to 2 scoped roles: `ScanalyzeCustomer-Diagnostic` (read-only) and `ScanalyzeCustomer-StateRecovery` (state bucket write only, requires `operation=state-recovery` tag) per ADR-004 rev3. Break-glass CANNOT assume Plan/Apply/Promotion roles. Separate trust policy statement for break-glass principal. CloudTrail mandatory, alarm on use, time-limited (30min), dual approval, post-incident report mandatory |
| **Residual risk** | Low with controls |
| **Test** | Break-glass use → CloudWatch alarm fires within 1 minute; Routine use pattern (>2/week) → alert; Break-glass without incident ticket → audit finding |
| **Owner** | Platform security |

#### T1.6 — Confused deputy (S, E)

| Attribute | Value |
|---|---|
| **Threat** | A third-party service or internal tool tricks the orchestrator into assuming a deployment role for a customer it shouldn't access |
| **Impact** | Unauthorized operations in wrong customer account |
| **Likelihood** | Low with proper controls |
| **Controls** | Session tag `deployment_id` validated against target account in registry, ExternalId for future customer-managed accounts, orchestrator validates target account_id before AssumeRole, deployment record lookup is authoritative, SourceIdentity anchored at first hop |
| **Residual risk** | Low |
| **Test** | Orchestrator attempts AssumeRole on account not in registry for given deployment_id → BLOCKED; session tag deployment_id mismatch → DENIED |
| **Owner** | Platform security |

---

### Domain 2: Customer Data

#### T2.1 — PII leakage via logs or metrics (I)

| Attribute | Value |
|---|---|
| **Threat** | OCR text, prompts, LLM responses, personal identifiers (CURP, RFC, NSS, CLABE, account numbers) appear in centralized logs/metrics |
| **Impact** | PII exposure outside customer account boundary |
| **Likelihood** | Medium (common in unguarded systems) |
| **Controls** | Observability export schema (ADR-005), field-level allowlist, sentinel tests, structured logging with masking library, sanitized exceptions (no raw stack traces), `deployment_id` as primary dimension (not `customer_id` in every metric) |
| **Residual risk** | Medium until sentinel tests are operational and running per release |
| **Test** | Inject CURP, RFC, CLABE, NSS patterns → verify NOT present in exported logs/metrics; Raw stack trace → verify sanitized; Document content in error message → masked |
| **Owner** | Application security |

#### T2.2 — S3 bucket public exposure (I)

| Attribute | Value |
|---|---|
| **Threat** | Customer document bucket made publicly accessible |
| **Impact** | Mass PII disclosure |
| **Likelihood** | Very low with controls |
| **Controls** | S3 Block Public Access (account level + bucket level), SCP deny `s3:PutBucketPolicy` with public principal, no public ACLs, CT controls, AWS Config rule, bucket policy explicit deny of public access |
| **Residual risk** | Very low |
| **Test** | Create public bucket → DENIED; Set public ACL → DENIED; Put bucket policy with `"Principal": "*"` → DENIED |
| **Owner** | Platform security |

#### T2.3 — KMS key deletion or compromise (T, I)

| Attribute | Value |
|---|---|
| **Threat** | Application encryption key deleted or access compromised |
| **Impact** | Data loss (deletion) or data breach (compromise) |
| **Likelihood** | Low |
| **Controls** | SCP restrict `kms:ScheduleKeyDeletion` to break-glass role with dual approval, key policy per-deployment, per-domain keys (documents, state, queue, evidence, contracts per ADR-003 rev3), 30-day minimum waiting period, key rotation enabled, IAM Access Analyzer for key policy review. Multi-region keys for HA tiers (ADR-008 rev3) — replica key deletion also restricted |
| **Residual risk** | Low |
| **Test** | Non-authorized role schedules key deletion → DENIED; Key rotation → verified enabled; Waiting period < 30 days → DENIED; Replica key deletion without primary owner → DENIED |
| **Owner** | Platform security |

#### T2.4 — Cross-domain data mixing (T)

| Attribute | Value |
|---|---|
| **Threat** | Bank documents processed by gov worker or vice versa |
| **Impact** | Data misattribution, processing errors, compliance violation |
| **Likelihood** | Low with proper routing |
| **Controls** | SQS queue per processing domain, worker reads only its queue, task role restricts S3/DDB access by domain prefix, classifier validates domain before routing, DLQ for unroutable messages |
| **Residual risk** | Low |
| **Test** | Worker A reads queue B → DENIED by IAM; Worker A writes to domain B prefix → DENIED; Misclassified document → DLQ, not silent |
| **Owner** | Application |

#### T2.5 — Bedrock/LLM prompt injection (T, I)

| Attribute | Value |
|---|---|
| **Threat** | Malicious document content injected into LLM prompts leads to data extraction or control flow manipulation |
| **Impact** | Data leakage via crafted prompts, incorrect processing results |
| **Likelihood** | Medium (active research area) |
| **Controls** | Input sanitization before prompt construction, input length limits per field, output validation against expected JSON schema (strict mode, reject non-conforming), model output never used as system instruction, Bedrock guardrails configured (content filters, denied topics, PII filters), prompt templates not user-editable, document content treated as untrusted data, separate model invocation per document (no cross-document context) |
| **Residual risk** | Medium — prompt injection defense is not fully solved |
| **Test** | Known injection patterns in test documents → no unauthorized data in response; Model output schema validation → reject non-conforming responses; Output exceeding expected length → truncated and flagged |
| **Owner** | Application security |

---

### Domain 3: Network

#### T3.1 — Customer VPC egress to unauthorized destinations (I)

| Attribute | Value |
|---|---|
| **Threat** | Compromised workload exfiltrates data via internet egress |
| **Impact** | Data exfiltration |
| **Likelihood** | Low |
| **Controls** | Private subnets with NAT Gateway (egress path exists but limited to AWS API endpoints), VPC endpoints for all AWS services used by workers (S3, DDB, SQS, ECR, CW, Secrets Manager, Textract, Bedrock), security groups deny-by-default, VPC Flow Logs enabled (ALL traffic). **Workers have egress via NAT — this is not "no internet".** Controlled egress proxy for build environments (ADR-007 rev3). Future: Network Firewall or egress filtering |
| **Residual risk** | Medium — NAT provides egress path |
| **Test** | Worker task resolves external DNS → only via NAT; Flow Logs capture all traffic; No IGW route in private route tables; VPC endpoints configured for all required services; Default execute-api endpoint disabled (ADR-008 rev3 corrections) |
| **Owner** | Platform security |

#### T3.2 — Cross-customer network paths (I, E)

| Attribute | Value |
|---|---|
| **Threat** | Network route exists between customer account VPCs |
| **Impact** | Network-level cross-customer access |
| **Likelihood** | Very low (no peering, no TGW) |
| **Controls** | No VPC peering between customer accounts, no Transit Gateway, no shared subnets, per-account VPC with non-overlapping CIDRs, SCP deny `ec2:CreateVpcPeeringConnection` |
| **Residual risk** | Very low |
| **Test** | Verify no VPC peering connections; Verify no TGW attachments; SCP blocks peering creation |
| **Owner** | Platform security |

#### T3.3 — DNS hijacking (S)

| Attribute | Value |
|---|---|
| **Threat** | Customer domain DNS redirected to attacker |
| **Impact** | Credential theft, data interception |
| **Likelihood** | Low |
| **Controls** | DNSSEC where supported, ACM certificate validation, domain ownership verification at onboarding, CAA records |
| **Residual risk** | Low |
| **Test** | DNS validation in preflight; ACM certificate for correct domain; CAA record present |
| **Owner** | Platform operations |

#### T3.4 — Data exfiltration via DNS tunneling (I)

| Attribute | Value |
|---|---|
| **Threat** | Compromised workload exfiltrates data via DNS queries to attacker-controlled domains |
| **Impact** | Data exfiltration bypassing egress controls |
| **Likelihood** | Low |
| **Controls** | Route53 Resolver DNS Firewall with allowlist, DNS query logging, GuardDuty DNS analysis (when available), anomalous query volume alerting |
| **Residual risk** | Medium — requires DNS Firewall deployment |
| **Test** | DNS query to known malicious domain → BLOCKED; Query volume anomaly → alert |
| **Owner** | Platform security |

---

### Domain 4: Secrets and Credentials

#### T4.1 — Deployment role credential theft (S, I)

| Attribute | Value |
|---|---|
| **Threat** | Temporary credentials from AssumeRole intercepted |
| **Impact** | Unauthorized operations in customer account |
| **Likelihood** | Low |
| **Controls** | Short session duration (1h/30min), SourceIdentity (immutable, set once at first hop per ADR-004 rev3), transitive session tags, CloudTrail event logging, no credential persistence to disk, credentials never logged |
| **Residual risk** | Low |
| **Test** | Session duration > max → DENIED; Missing SourceIdentity → DENIED; Credentials in build output → sentinel alert |
| **Owner** | Platform security |

#### T4.2 — Cognito secret leakage (I)

| Attribute | Value |
|---|---|
| **Threat** | App client secret or JWKS endpoint misused. **JWKS is public by design** — the threat is issuer/JWKS misvalidation, not JWKS leakage |
| **Impact** | Token forgery capability (M2M), impersonation via weak validation |
| **Likelihood** | Low (PKCE flow for SPA, no client secret) |
| **Controls** | PKCE for SPA (no secret), M2M client_credentials secret in Secrets Manager with auto-rotation, secret never in env vars or code, JWKS served over HTTPS only from Cognito domain, Lambda authorizer validates kid against JWKS of the correct issuer (not just any valid JWKS) |
| **Residual risk** | Low |
| **Test** | No client secrets in code, env vars, build output, or logs; Secrets Manager rotation configured; Token validated against wrong pool's JWKS → REJECTED |
| **Owner** | Application security |

#### T4.3 — State backend credential access (I)

| Attribute | Value |
|---|---|
| **Threat** | Unauthorized access to Terraform state (contains resource IDs, some config, potentially sensitive attributes) |
| **Impact** | Information disclosure, state tampering |
| **Likelihood** | Low |
| **Controls** | Three-bucket model (ADR-003 rev3): state bucket (no Object Lock), evidence bucket (COMPLIANCE Object Lock for immutable evidence, separate plan-execution zone for ephemeral plans), contracts bucket (large payloads). KMS encryption at rest per bucket with separate keys. Versioning enabled. S3-native lockfile. `sensitive = true` on outputs. State never in CI logs. **Pre-apply snapshots stored in evidence bucket recovery prefix** — this is authorized evidence, not leakage. Plan JSON output used by orchestrator for bounds verification (ADR-006 rev3) — rendered plan stored in plan-execution zone with short retention, NOT in state bucket |
| **Residual risk** | Low |
| **Test** | Non-deployment role reads state bucket → DENIED; State version history preserved; State file not in CI logs or build artifacts; Plan output in plan-execution zone with TTL |
| **Owner** | Platform security |

#### T4.4 — Environment variable credential leakage (I)

| Attribute | Value |
|---|---|
| **Threat** | Credentials passed via environment variables leaked through error reports, debug logs, or /proc filesystem |
| **Impact** | Credential exposure |
| **Likelihood** | Low with controls |
| **Controls** | Credentials injected via ECS task role (not env vars), sensitive config from Secrets Manager not env vars, error handlers sanitize environment before reporting, no `/proc/*/environ` access |
| **Residual risk** | Low |
| **Test** | Error report does not contain AWS_ACCESS_KEY, AWS_SECRET_KEY, or credential patterns; Task definition does not contain secrets in environment block |
| **Owner** | Application security |

---

### Domain 5: Supply Chain

#### T5.1 — Compromised container image (T)

| Attribute | Value |
|---|---|
| **Threat** | Malicious code injected into a container image via build compromise or dependency poisoning |
| **Impact** | Code execution in all customer accounts that receive the image |
| **Likelihood** | Low with controls |
| **Controls** | Image scanning with gate policy (ADR-007 rev3 §13), SBOM generation, explicit signing: AWS Signer for OCI images + KMS ECDSA_SHA_256 DSSE for release manifest and attestation (ADR-007 rev3), digest-only references, full OCI artifact graph promotion (image + signature + SBOM + provenance), incomplete graph → ABORT, waiver policy, pinned base images by digest, pinned dependencies. Central signing identity is authoritative — never replaced by customer-side re-sign. Promotion copies graph + verifies (ADR-007 rev3 §8) |
| **Residual risk** | Medium — supply chain attacks are sophisticated; SLSA L2+ mitigates but doesn't eliminate |
| **Test** | Unsigned image → REJECTED at promotion; Image with critical CVE → REJECTED at gate; Digest mismatch after promotion → REJECTED and alarm; Missing SBOM artifact → promotion ABORTED |
| **Owner** | Platform security |

#### T5.2 — Terraform module tampering (T)

| Attribute | Value |
|---|---|
| **Threat** | Attacker modifies a Terraform module to introduce backdoor resources |
| **Impact** | Unauthorized infrastructure in customer accounts |
| **Likelihood** | Low |
| **Controls** | Module versioning with git tags, package digests in release manifest, source revision tracking, code review (mandatory), branch protection, CI ownership validation, no external module sources |
| **Residual risk** | Low |
| **Test** | Module digest mismatch vs manifest → REJECTED; PR without required approvals → BLOCKED; Module uses external source → CI FAIL |
| **Owner** | Platform security |

#### T5.3 — Release manifest forgery (T, S)

| Attribute | Value |
|---|---|
| **Threat** | Attacker creates a fake release manifest pointing to malicious images |
| **Impact** | Deployment of unauthorized code/config |
| **Likelihood** | Low |
| **Controls** | Release manifest signed with KMS ECDSA_SHA_256 via DSSE envelope (ADR-007 rev3), separate signed attestation, approval chain, manifest digest verification before deployment, manifest stored in versioned S3 with access controls |
| **Residual risk** | Low |
| **Test** | Unsigned manifest → REJECTED; Attestation digest mismatch → REJECTED; Modified manifest → signature verification fails; DSSE envelope with wrong payloadType → REJECTED |
| **Owner** | Platform security |

#### T5.4 — Dependency confusion / substitution (T)

| Attribute | Value |
|---|---|
| **Threat** | Public package with same name as private dependency installed instead of private version |
| **Impact** | Arbitrary code execution in build environment |
| **Likelihood** | Low with controls |
| **Controls** | Explicit package source configuration (pip `--index-url`, npm `.npmrc`), lock files committed, dependency review in PRs, no wildcard package sources, private packages scoped/namespaced, controlled egress proxy in build (ADR-007 rev3 — proxy allowlist) |
| **Residual risk** | Low |
| **Test** | Build with tampered lock file → CI FAIL (hash mismatch); Package installed from unexpected source → alert; Direct egress from build → DENIED (proxy only) |
| **Owner** | Application security |

#### T5.5 — Base image compromise (T)

| Attribute | Value |
|---|---|
| **Threat** | Upstream base image (e.g., `python:3.11-slim`) is compromised at source |
| **Impact** | All built images inherit the compromise |
| **Likelihood** | Very low (major registries have security controls) |
| **Controls** | Pin base images by digest (`@sha256:...`), scheduled base image update cycle with review, SBOM includes base image layers, vulnerability scan covers base image, base image change requires explicit PR |
| **Residual risk** | Low |
| **Test** | Dockerfile uses tag without digest → CI FAIL; Base image digest changed → PR required with review |
| **Owner** | Platform security |

---

### Domain 6: Terraform State

#### T6.1 — State tampering (T)

| Attribute | Value |
|---|---|
| **Threat** | Attacker modifies state file to change resource ownership/config |
| **Impact** | Infrastructure drift, data loss, privilege escalation |
| **Likelihood** | Low |
| **Controls** | S3 versioning, KMS encryption (separate state KMS key per ADR-003 rev3), bucket policy scoped to Plan/Apply/Diagnostic/StateRecovery roles. S3-native lockfile (`use_lockfile = true`). Pre-apply state snapshot saved to evidence bucket recovery prefix with COMPLIANCE Object Lock on evidence objects. Conditional apply (plan digest verification). State bucket has NO Object Lock or default retention (required for lockfile deletion and .tflock cleanup). Regional state keys: `{dep_id}/{region}/{layer}/terraform.tfstate` (ADR-003 rev3, ADR-008 rev3) |
| **Residual risk** | Low |
| **Test** | Non-authorized role writes to state bucket → DENIED; State version history preserved; .tflock can be deleted by Plan role (no Object Lock interference) |
| **Owner** | Platform security |

#### T6.2 — State leakage (I)

| Attribute | Value |
|---|---|
| **Threat** | State file contents exposed (resource IDs, ARNs, some sensitive attributes) |
| **Impact** | Information disclosure enabling further attacks |
| **Likelihood** | Low |
| **Controls** | KMS encryption at rest, bucket policy restrict access, no state in CI logs or build artifacts, `sensitive = true` for sensitive outputs, no `terraform show` in CI. **Plan JSON output** (`terraform show -json saved.plan`) is used by orchestrator for bounds verification (ADR-006 rev3) — this is the planned resource changes only, stored in plan-execution zone with short retention, accessible only to Plan/Apply roles. The full state file is NOT rendered to JSON in CI |
| **Residual risk** | Low |
| **Test** | State file not present in build artifacts; Full state not rendered in CI; Plan JSON in plan-execution zone with TTL; Sensitive outputs marked |
| **Owner** | Platform security |

#### T6.3 — Dual ownership / orphaned state (T)

| Attribute | Value |
|---|---|
| **Threat** | Two roots manage the same resource, or no root manages a live resource |
| **Impact** | Unintended resource modification, invisible drift, failed destroys |
| **Likelihood** | **HIGH** (current brownfield state — see state audit) |
| **Controls** | 1:1 root/state key mapping, CI ownership validation (ownership.yaml), state audit procedures, no `terraform import` without evidence/approval, Track B eliminates by design. Ownership manifest (ADR-003 rev3) documents per-region, per-layer ownership |
| **Residual risk** | **HIGH** for Track A (brownfield); **LOW** for Track B (greenfield by design — not NONE because drift remains possible) |
| **Test** | CI check: no duplicate backend keys; Ownership YAML validates 1:1 mapping; `terraform state list` matches expected resources |
| **Owner** | Platform operations |

#### T6.4 — State drift (T, I)

| Attribute | Value |
|---|---|
| **Threat** | Resources modified outside Terraform (console, CLI, other tools) causing state/reality divergence |
| **Impact** | Unexpected behavior, security control bypass, failed applies |
| **Likelihood** | Medium (especially during brownfield recovery) |
| **Controls** | Scheduled `terraform plan` drift detection (non-apply), CloudTrail monitoring for manual resource changes, AWS Config rules for configuration compliance, SCP restrict manual changes in production |
| **Residual risk** | Medium for Track A; Low for Track B |
| **Test** | Manual resource change → next plan detects drift; Config rule non-compliance → alert |
| **Owner** | Platform operations |

---

### Domain 7: Operations

#### T7.1 — Uncontrolled onboarding (E)

| Attribute | Value |
|---|---|
| **Threat** | Account provisioned without proper approval or baseline |
| **Impact** | Insecure deployment, compliance violation |
| **Likelihood** | Low with workflow |
| **Controls** | Deployment request via PR with schema validation, approval chain (code review + business approval), preflight checks (region capability matrix per ADR-008 rev3, quotas, SCPs, model access), baseline verification before workload deployment, ACCOUNT_READY contract verified with authenticated digest (ADR-004 rev3) |
| **Residual risk** | Low |
| **Test** | Invalid request schema → REJECTED; Missing approval → BLOCKED; Failed preflight → BLOCKED; Account without baseline → deployment BLOCKED; ACCOUNT_READY digest verification failure → BLOCKED |
| **Owner** | Platform operations |

#### T7.2 — Incomplete offboarding (I, R)

| Attribute | Value |
|---|---|
| **Threat** | Customer data remains accessible after offboarding |
| **Impact** | Data breach, contractual and compliance violation |
| **Likelihood** | Medium without state machine |
| **Controls** | Offboarding state machine with validated transitions (ADR-001), Suspended OU SCP (deny-all-workload), KMS scheduled deletion with 30-day wait, legal hold capability, evidence archive for each step, post-offboarding verification |
| **Residual risk** | Medium — requires operational discipline and verification |
| **Test** | Suspended account workload access → DENIED; KMS key deletion without waiting period → DENIED; Data access after ARCHIVED status → DENIED; Offboarding without evidence for each step → BLOCKED |
| **Owner** | Platform operations + legal |

#### T7.3 — Failed upgrade without rollback (D)

| Attribute | Value |
|---|---|
| **Threat** | Release upgrade fails and cannot be reversed |
| **Impact** | Customer downtime, potential data corruption |
| **Likelihood** | Medium |
| **Controls** | Saved plans (plan digest verification). Rollback = **forward apply** with previous release configuration (ADR-003 rev3, ADR-010 rev3 §9). ECS circuit breaker for task failures → reconciliation procedure (ADR-010 rev3 §8): detect DEPLOYMENT_FAILED → confirm active revision → forward apply previous release config. **Wave-based service deployment** (ADR-010 rev3 §6.1): Wave 1 (ingest) → Wave 2 (classifier) → Wave 3 (domain workers) → Wave 4 (supporting). Wave failure stops subsequent waves. Terraform sole owner of task definitions. Rolling deployments. Pre-apply state snapshot in evidence bucket |
| **Residual risk** | Medium until rollback testing is operational per release |
| **Test** | Upgrade → failure → reconciliation → service restored; ECS circuit breaker triggers → reconciliation aligns TF state; Wave N failure → Waves N+1..4 NOT executed |
| **Owner** | Platform operations |

#### T7.4 — Centralized observability PII leakage (I)

| Attribute | Value |
|---|---|
| **Threat** | Sanitization fails and PII flows to centralized metrics/logs |
| **Impact** | PII exposure outside customer boundary |
| **Likelihood** | Medium |
| **Controls** | Export schema with field-level allowlist, sentinel tests per release (inject known PII → verify absent), unknown field rejection, `deployment_id` as primary dimension, no `document_id`/`batch_id` as metric dimensions, encrypted and retention-controlled central store |
| **Residual risk** | Medium until sentinel tests are operational |
| **Test** | PII sentinel injection → NOT present in central store; Unknown field in export → REJECTED; document content in metric label → masked or absent |
| **Owner** | Application security |

#### T7.5 — Insider threat (S, T, I, E)

| Attribute | Value |
|---|---|
| **Threat** | Authorized team member with privileged access acts maliciously or negligently |
| **Impact** | Data breach, infrastructure sabotage, credential theft |
| **Likelihood** | Low (but high impact) |
| **Controls** | Least-privilege roles (6 scoped per ADR-004 rev3), separation of duties (build ≠ sign ≠ deploy ≠ approve), dual approval for destructive actions, CloudTrail for all actions, immutable audit logs in evidence bucket, break-glass alarm, no single person can build+sign+deploy, code review mandatory, SourceIdentity provides non-repudiation |
| **Residual risk** | Medium — insider threats are inherently difficult to prevent |
| **Test** | Single identity cannot complete full release→deploy cycle; All privileged actions in CloudTrail; Break-glass alarm fires on unauthorized use |
| **Owner** | Platform security + management |

---

### Domain 8: Data Residency and Sovereignty

#### T8.1 — Data residency violation (I)

| Attribute | Value |
|---|---|
| **Threat** | Customer data stored or processed in a region that violates data residency requirements |
| **Impact** | Compliance violation, contractual breach, potential legal consequences |
| **Likelihood** | Low with controls |
| **Controls** | SCP region-deny (with global service exceptions), deployment request specifies region, preflight validates region against capability matrix (ADR-008 rev3 §15), no cross-region replication without explicit customer consent, DR profiles document data replication scope, deployment record documents all regions where data resides (ADR-008 rev3 §12) |
| **Residual risk** | Low |
| **Test** | Create resource in non-approved region → DENIED by SCP; Cross-region replication without consent → BLOCKED |
| **Owner** | Platform security + compliance |

---

### Domain 9: Migration and Rollout

> [!IMPORTANT]
> This domain covers threats introduced by the brownfield → greenfield migration (ADR-010 rev3) and the wave-based service deployment model. These threats are transient (migration period) but high-impact because they involve live customer data.

#### T9.1 — Migration overwrite via unconditional BatchWriteItem (T)

| Attribute | Value |
|---|---|
| **Threat** | Unconditional `BatchWriteItem` replaces existing items in greenfield DynamoDB, silently overwriting data that was created after the initial migration baseline |
| **Impact** | Data loss — greenfield writes silently replaced by older migration data |
| **Likelihood** | Medium if migration utility uses BatchWriteItem for delta loads |
| **Controls** | **Baseline load**: `BatchWriteItem` ONLY when destination table is confirmed empty and greenfield writes are disabled. All `UnprocessedItems` must be retried. Checkpoint advances only after entire source page acknowledged. **Delta load**: `PutItem`/`UpdateItem` with `ConditionExpression` (`attribute_not_exists(PK) OR version < :incoming_version`). **Never** use `BatchWriteItem` for incremental deltas. Post-load integrity verification mandatory (ADR-010 rev3 §M1) |
| **Residual risk** | Low with correct strategy separation |
| **Test** | Delta load with BatchWriteItem → REJECTED by migration utility; Conditional write on existing item with higher version → write REJECTED; Baseline load on non-empty table → ABORTED |
| **Owner** | Platform operations |

#### T9.2 — Incomplete UnprocessedItems retry (T)

| Attribute | Value |
|---|---|
| **Threat** | `BatchWriteItem` returns `UnprocessedItems` that are not retried, resulting in missing data in greenfield |
| **Impact** | Data loss — items silently not migrated |
| **Likelihood** | Medium (DynamoDB throttling is common during bulk writes) |
| **Controls** | Migration utility retries all `UnprocessedItems` with exponential backoff. Checkpoint does NOT advance until all items in batch are confirmed written. Dead-letter queue for items that fail after max retries. Post-migration integrity verification: source key count == destination key count. Sample hash verification (5% random) |
| **Residual risk** | Low with retry + DLQ + verification |
| **Test** | Simulated throttling → all items eventually written; DLQ non-empty → migration reports partial failure; Item count mismatch → migration FAILS |
| **Owner** | Platform operations |

#### T9.3 — Migration checkpoint advanced before durable completion (T)

| Attribute | Value |
|---|---|
| **Threat** | Checkpoint marks a batch as completed before all writes are durably committed. Crash after checkpoint → items lost |
| **Impact** | Data loss — skipped items on resume |
| **Likelihood** | Medium |
| **Controls** | Checkpoint advances only after: (a) all items in batch confirmed written (no UnprocessedItems), (b) checkpoint write itself is durable (conditional write to checkpoint table). Resume from last durable checkpoint. Checkpoint includes: export segment ID, offset, items_written count, items_skipped count, batch_digest. Post-resume verification: re-verify items from last checkpoint batch |
| **Residual risk** | Low with write-after-confirm model |
| **Test** | Simulated crash after write, before checkpoint → items re-migrated on resume; Checkpoint without confirmation → REJECTED |
| **Owner** | Platform operations |

#### T9.4 — Producer deployed before compatible consumers (T, D)

| Attribute | Value |
|---|---|
| **Threat** | New ingest-api version produces messages in schema v2 that current workers (still on v1) cannot parse. Messages go to DLQ or are silently misprocessed |
| **Impact** | Processing failures, DLQ accumulation, data corruption from misparse |
| **Likelihood** | Medium (wave ordering may not match schema compatibility) |
| **Controls** | Wave rollout order derived from producer/consumer compatibility matrix (ADR-010 rev3 corrections). General pattern: deploy consumers first (accepting old + new schema) → deploy producers (emitting new schema) → confirm no old-schema messages → retire legacy support in later release. Message schema version included in every SQS message. Workers reject unknown schema versions (fail-closed, route to DLQ). Schema compatibility matrix reviewed per release |
| **Residual risk** | Medium until compatibility matrix is enforced per release |
| **Test** | New producer message → old consumer → DLQ (not silent discard); Unknown schema version → DLQ; Compatibility matrix missing for changed schema → release BLOCKED |
| **Owner** | Application + platform operations |

#### T9.5 — Partial release across service waves (T, D)

| Attribute | Value |
|---|---|
| **Threat** | Wave 2 fails, leaving deployment in partially updated state: some services on release N+1, others on release N. No Terraform reconciliation performed |
| **Impact** | Version mismatch between services, undefined behavior, difficult rollback |
| **Likelihood** | Medium |
| **Controls** | Deployment record tracks per-service: desired_release, observed_release, image_digest, task_definition_arn, rollout_status, validation_status, wave_id. Wave failure → stop subsequent waves → trigger reconciliation (ADR-010 rev3 §8). All 7 services remain declared in every `terraform plan` — wave variable controls only which digest changes, never resource existence. Partial state is explicit and recoverable |
| **Residual risk** | Low with reconciliation procedure |
| **Test** | Wave 2 failure → Waves 3-4 NOT executed; Deployment record shows mixed versions; Reconciliation restores all services to release N; deploy_wave change does NOT destroy other services |
| **Owner** | Platform operations |

#### T9.6 — Outstanding presigned uploads after maintenance begins (T)

| Attribute | Value |
|---|---|
| **Threat** | Presigned S3 upload URLs issued before maintenance window are used to upload documents after brownfield is supposed to be write-fenced. These uploads bypass the ingest API 503 |
| **Impact** | Accepted writes after migration cutoff → data loss if greenfield does not include these documents |
| **Likelihood** | Medium (presigned URLs have configurable expiry, default up to 7 days) |
| **Controls** | Before maintenance: stop issuing new presigned URLs. Track maximum presigned URL expiry. Wait for all outstanding presigned URLs to expire before final sync. Alternatively: revoke upload capability via S3 bucket policy update (deny PutObject from application path). Block direct S3 PutObject paths. Record `last_accepted_write_at` and `write_fence_confirmed_at`. Also close: scheduled producers, integration retries (M2M), webhook receivers, outbox dispatchers |
| **Residual risk** | Low with comprehensive write path closure |
| **Test** | Presigned URL used after bucket policy deny → REJECTED; S3 PutObject after maintenance → DENIED; Scheduled producer fires after maintenance → no-op or REJECTED |
| **Owner** | Platform operations |

#### T9.7 — Accepted write after final migration cutoff (T)

| Attribute | Value |
|---|---|
| **Threat** | A write is accepted by brownfield after the final delta sync cutoff but before DNS switch. This write exists only in brownfield and is lost |
| **Impact** | **Data loss of an accepted write** — the single most critical migration threat |
| **Likelihood** | Low with proper drain and fence |
| **Controls** | Strict sequence (ADR-010 rev3 §M2): brownfield 503 for writes → full async drain → all write paths closed (§T9.6 controls) → final delta sync → integrity verification → DNS switch → greenfield accepts writes. `final_delta_cutoff` timestamp recorded. No write path remains open after 503 + write fence. After first greenfield write: forward-only, no rollback to brownfield without data reconciliation |
| **Residual risk** | Very low with strict fence verification |
| **Test** | Write attempt after 503 → REJECTED; Write via presigned URL after fence → DENIED; DynamoDB write after maintenance flag → REJECTED; Delta sync captures all items with updated_at < cutoff |
| **Owner** | Platform operations |

#### T9.8 — ECS automatic rollback without Terraform reconciliation (T, D)

| Attribute | Value |
|---|---|
| **Threat** | ECS circuit breaker reverts to previous task definition revision, but Terraform state still records the new revision. Subsequent `terraform plan` shows no drift (TF thinks the new revision is active). Next apply may or may not trigger a new deployment depending on ECS service state |
| **Impact** | TF state / ECS runtime divergence, unpredictable subsequent deployments, false sense of "applied successfully" |
| **Likelihood** | Medium (circuit breaker is an expected control) |
| **Controls** | Orchestrator monitors ECS deployment events (ADR-010 rev3 §8). On DEPLOYMENT_FAILED: (1) halt remaining waves, (2) confirm active ECS revision + digest via `ecs:DescribeServices`, (3) compare with TF state expectation, (4) record drift, (5) forward-apply with previous release config to reconcile, (6) mandatory plan review for reconciliation apply, (7) mark failed release as blocked |
| **Residual risk** | Low with reconciliation procedure |
| **Test** | Circuit breaker fires → orchestrator detects DEPLOYMENT_FAILED within 5 minutes; TF state after reconciliation matches ECS active revision; Subsequent plan shows zero drift |
| **Owner** | Platform operations |

#### T9.9 — Stale or conflicting migration version attributes (T)

| Attribute | Value |
|---|---|
| **Threat** | Migration utility writes items with incorrect version attributes (stale, duplicated, or missing `_migration_id`). Subsequent conditional writes may overwrite newer data or fail unexpectedly |
| **Impact** | Data corruption, failed delta loads |
| **Likelihood** | Low |
| **Controls** | Version attribute set from source record version, not from migration utility's own counter. `_migration_id` set per migration run (unique). Conditional writes verify version monotonicity. Items dead-lettered if version conflict is unresolvable. Post-migration audit: verify no items have `_migration_id` from a different run |
| **Residual risk** | Low |
| **Test** | Item with higher version in destination → migration write SKIPPED (not overwritten); Missing version attribute → handled as version=0 (insertable); Duplicate _migration_id from old run → flagged in audit |
| **Owner** | Platform operations |

#### T9.10 — Delta migration missing updates or tombstones (T)

| Attribute | Value |
|---|---|
| **Threat** | Incremental DynamoDB export omits updates or deletes that occurred between the baseline and the final sync. Items in greenfield are stale or include items that were deleted in brownfield |
| **Impact** | Data inconsistency — stale data served, deleted items resurrected |
| **Likelihood** | Medium — **DynamoDB incremental exports are NOT transactionally consistent** |
| **Controls** | Incremental exports may observe items in inconsistent states. Final sync (during maintenance window) resolves this: brownfield is read-only, no new writes, final export captures stable state. Deletes handled via tombstone markers or explicit delete list. Post-sync verification: sample comparison of items between brownfield and greenfield. Items present in greenfield but deleted in brownfield → flagged |
| **Residual risk** | Low with maintenance window final sync |
| **Test** | Deleted item in brownfield → not present in greenfield after final sync; Updated item → greenfield has latest version; Stale incremental export item → overwritten by final sync |
| **Owner** | Platform operations |

---

### Domain 10: Economic and Availability

#### T10.1 — Economic DoS via Textract/Bedrock (D)

| Attribute | Value |
|---|---|
| **Threat** | Attacker submits large volumes of documents to trigger expensive Textract/Bedrock API calls, causing excessive AWS costs |
| **Impact** | Financial damage, potential service disruption if budget alarms trigger shutdowns |
| **Likelihood** | Medium |
| **Controls** | Rate limiting at API Gateway (per-deployment throttle), per-deployment cost budgets with alarms, SQS-based backpressure (max queue depth alarms), per-deployment document volume tracking, Textract/Bedrock call counting per deployment_id, alert on >2× normal volume, circuit breaker on cost threshold |
| **Residual risk** | Medium — cost controls limit but don't eliminate |
| **Test** | Burst submission beyond rate limit → throttled; Cost alarm fires on threshold; Volume anomaly → alert |
| **Owner** | Platform operations |

#### T10.2 — Deployment registry tampering (T, E)

| Attribute | Value |
|---|---|
| **Threat** | Attacker modifies the deployment registry (mapping deployment_id → account_id → customer) to redirect deployments to wrong accounts or inject rogue deployments |
| **Impact** | Cross-customer deployment, data in wrong account, unauthorized infrastructure |
| **Likelihood** | Low |
| **Controls** | Registry stored in Shared Services account with strict IAM, versioned (DynamoDB or versioned S3), change audit via CloudTrail, changes require PR + approval, registry read by orchestrator is authoritative, deployment_id validated against registry before every AssumeRole |
| **Residual risk** | Low |
| **Test** | Modify registry without approval → DENIED; Deploy to account not matching registry → BLOCKED; Registry change → CloudTrail event |
| **Owner** | Platform security |

#### T10.3 — SSM contract tampering or replay (T)

| Attribute | Value |
|---|---|
| **Threat** | Attacker modifies an SSM contract parameter or replays a previous version's contract to feed stale/malicious data to consumer layers |
| **Impact** | Consumer layer builds on incorrect or stale data — incorrect resource references, wrong security group IDs, etc. |
| **Likelihood** | Low |
| **Controls** | Contract includes `contract_digest` validated by consumer precondition (ADR-006 rev3). Apply role session policy restricts `ssm:PutParameter` to producer's layer prefix only. SSM parameter version tracked in deployment record. Contract includes `producer_release`, `producer_module_digest`, `release_manifest_digest`. Consumer validates all fields. Replay of old contract → digest mismatch → precondition FAILS → plan ABORTED |
| **Residual risk** | Low |
| **Test** | Modified contract → digest mismatch → precondition fails; Old contract replayed → version/release mismatch → precondition fails; Non-owner role writes contract → DENIED by session policy |
| **Owner** | Platform security |

#### T10.4 — Saved-plan substitution (T, E)

| Attribute | Value |
|---|---|
| **Threat** | Attacker substitutes the saved plan file between `terraform plan` and `terraform apply`, causing apply to execute different changes than were reviewed |
| **Impact** | Unauthorized infrastructure changes, privilege escalation |
| **Likelihood** | Low |
| **Controls** | Saved plan stored in plan-execution zone (ADR-003 rev3) with short retention. Plan file content-addressed: digest recorded by orchestrator at plan time, verified before apply. Plan and apply executed in same pipeline execution context with same `change_id` session tag. Separate Plan and Apply roles ensure the plan cannot be generated by the Apply identity. CloudTrail records both operations |
| **Residual risk** | Low |
| **Test** | Modified plan file → digest mismatch → apply ABORTED; Plan generated by Apply role → DENIED; Plan from different change_id → REJECTED |
| **Owner** | Platform security |

---

## Risk Summary Matrix

| ID | Threat | STRIDE | Current | Target | Priority | Blocker | Owner |
|---|---|---|---|---|---|---|---|
| T1.4 | IAM user persistence | S,R | **HIGH** | Low | **P0** | SEC-PLATFORM-001 | Ops |
| T6.3 | Dual ownership | T | **HIGH** | Low | **P0** | Track A recovery | Ops |
| T1.1 | Orchestrator compromise | S,E | Medium | Low | P1 | ADR-004 controls | Security |
| T2.1 | PII leakage (logs) | I | Medium | Low | P1 | Sentinel tests | App Security |
| T2.5 | Prompt injection | T,I | Medium | Medium | P1 | Bedrock guardrails | App Security |
| T5.1 | Compromised image | T | Medium | Low | P1 | ADR-007 pipeline | Security |
| T6.4 | State drift | T,I | Medium | Low | P1 | Drift detection | Ops |
| T9.4 | Producer before consumers | T,D | Medium | Low | P1 | Compatibility matrix | Ops+App |
| T9.7 | Write after cutoff | T | Medium | Very Low | P1 | Write fence | Ops |
| T10.1 | Economic DoS | D | Medium | Low | P1 | Cost controls | Ops |
| T7.2 | Incomplete offboarding | I,R | Medium | Low | P2 | State machine | Ops |
| T7.3 | Failed upgrade | D | Medium | Low | P2 | Rollback+reconciliation | Ops |
| T7.4 | Observability PII | I | Medium | Low | P2 | Export schema | App Security |
| T7.5 | Insider threat | S,T,I,E | Medium | Medium | P2 | Separation of duties | Security |
| T3.1 | Egress exfiltration | I | Medium | Low | P2 | Network Firewall | Security |
| T3.4 | DNS exfiltration | I | Medium | Low | P2 | DNS Firewall | Security |
| T9.1 | Migration overwrite | T | Medium | Low | P2 | Strategy separation | Ops |
| T9.5 | Partial release | T,D | Medium | Low | P2 | Reconciliation | Ops |
| T9.6 | Presigned after fence | T | Medium | Low | P2 | Write path closure | Ops |
| T9.8 | ECS rollback no reconcile | T,D | Medium | Low | P2 | Reconciliation | Ops |
| T9.10 | Delta missing updates | T | Medium | Low | P2 | Maintenance window | Ops |
| All others | (Low/Very Low) | — | Low | Low | P3 | Controls deployed | Various |

---

## Security Testing Requirements

| Category | Tests | Frequency | Automated |
|---|---|---|---|
| **IAM** | Cross-account denied, wrong principal denied, missing session tags denied, break-glass alarm fires, confused deputy blocked, SourceIdentity override denied, TagSession unauthorized tag denied | Per release + quarterly | Yes |
| **Data** | Public S3 denied, cross-domain access denied, KMS deletion denied, PII sentinel tests (CURP/RFC/CLABE/NSS), multi-region key operations restricted | Per release | Yes |
| **Network** | No VPC peering, no TGW, flow logs enabled, DNS firewall rules active, default execute-api disabled, VPC endpoints configured | Per deployment + quarterly | Yes |
| **Supply chain** | Unsigned image rejected, digest mismatch rejected, critical CVE blocks, dependency lock verified, DSSE envelope validated, missing SBOM → promotion aborted, proxy-only egress | Per build | Yes |
| **State** | Non-authorized access denied, versioning works, ownership CI passes, drift detection runs, plan-execution zone TTL, three-bucket separation | Per apply + scheduled | Yes |
| **Operations** | Invalid request rejected, preflight blocks, offboarding denies, rollback succeeds, wave failure stops, reconciliation aligns TF+ECS | Per release | Yes |
| **Prompt injection** | Known injection patterns, output schema validation, length limits, Bedrock guardrail triggers | Per release | Yes |
| **Insider** | No single identity completes full cycle, audit log completeness, SourceIdentity non-repudiation | Quarterly | Semi |
| **Migration** | Conditional writes enforced for deltas, UnprocessedItems retried, checkpoint durability, write fence verified, presigned URL block, item count match, sample hash verification, schema compatibility matrix | Per migration run | Yes |
| **Economic** | Rate limit enforced, cost alarm fires, volume anomaly detected, registry tamper denied, SSM contract digest verified, saved plan substitution detected | Per release + scheduled | Yes |

---

## Observability Hardening

| Rule | Implementation |
|---|---|
| Primary dimension | `deployment_id` (not `customer_id` on every metric) |
| Forbidden dimensions | `document_id`, `batch_id`, `invocation_id` as CloudWatch metric dimensions |
| No raw content | Document text, OCR output, LLM responses never in centralized logs |
| No raw stack traces | Even within customer account, stack traces are sanitized |
| Unknown fields | Rejected by export schema (`additionalProperties: false`) |
| Retention | Mandatory minimum per tier, encrypted at rest |
| Sentinel tests | Inject known PII patterns → verify absence in central store |
| Customer-local logs | Full debug logs remain within customer account, encrypted, retention-controlled |
| Migration logs | Migration utility logs to customer account only, masked PII, item counts/hashes logged (not item content) |

---

## Compliance Mapping (placeholder)

| Requirement | Threats addressed | Controls |
|---|---|---|
| Data encryption at rest | T2.3, T4.3, T6.2 | KMS per-account, per-domain, per-bucket |
| Data encryption in transit | T3.1, T4.1 | TLS everywhere, VPC endpoints |
| Access control | T1.1–T1.6 | IAM, SCPs, permissions boundaries |
| Audit logging | T1.5, T7.5 | CloudTrail, immutable logs |
| Data residency | T8.1 | SCP region-deny, deployment region validation |
| Vulnerability management | T5.1, T5.4, T5.5 | Scanning, SBOM, gate policy |
| Data migration integrity | T9.1–T9.10 | Conditional writes, checksums, fence |
| Cost control | T10.1 | Rate limits, budgets, alarms |

> Full compliance matrix deferred until regulatory requirements are confirmed per customer.

---

## Threat Model Lifecycle

| Trigger | Action |
|---|---|
| Initial creation | This document (before implementation) |
| ADR accepted | Update affected threat entries with specific control references |
| New service added | Add threat entries for new attack surface |
| Security incident | Add/update threat entry, conduct root cause analysis |
| Release preparation | Review risk matrix, verify controls are deployed |
| Quarterly review | Review all HIGH and Medium threats, update residual risk |
| Architecture change | Full threat model review |
| New customer tier | Review tier-specific controls (HA, DR, region) |
| Migration execution | Review Domain 9 threats, verify all controls active |
| **ADR-009 rev3** | Final reconciliation — all rev3 ADRs cross-referenced |

---

## Appendix: WS8 Focused Consistency Patches

> Applied: 2026-06-28  
> Full patch details: `reports/ws8-adr009-patches.md`

### Focused Consistency Controls Added (not new threats — maturity updates)

> The following 4 controls were identified during the WS8 focused consistency patch.
> They are documented as **maturity annotations** on existing threat domains, NOT as
> new threats, to preserve the 10-domain / 48-threat structure.

#### Control: Economic DoS via Textract/Bedrock — maturity update for Domain 9 (Availability)

- **Applies to**: Existing availability threats (service degradation, resource exhaustion)
- **Added controls**: Per-deployment rate limits on ingest-api, SQS-based backpressure, Textract/Bedrock request budgets per hour/day, CloudWatch billing alarms with auto-disable at threshold, WAF rate rules at API Gateway, dead-letter for rejected items
- **control_status**: designed
- **Test**: Burst 1000 uploads in 1 minute → rate limited at API Gateway; Monthly billing exceeds 2x baseline → alarm fires

#### Control: Deployment Registry Integrity — maturity update for Domain 4/5 (Orchestration/Deployment)

- **Applies to**: Existing orchestrator threats (T-series in deployment domain)
- **Added controls**: DynamoDB table policy restricts write to orchestrator role only, deployment_id is immutable key, registry writes logged in CloudTrail, registry reads verify account_id against ACCOUNT_READY, conditional writes (version attribute)
- **control_status**: designed
- **Test**: Non-orchestrator role PutItem → DENIED; Modify deployment_id → condition expression fails; Registry entry for wrong account_id → orchestrator rejects

#### Control: SSM Contract Integrity — maturity update for Domain 6 (Contract Layer)

- **Applies to**: Existing contract validation threats
- **Added controls**: Contract digest verification in consumer precondition, SSM parameter version tracking, content-addressed contract payloads in S3 (digest as key suffix), Apply role SSM write restricted to producer layer prefix only, contract freshness verified against deployment record
- **control_status**: fixture_exists
- **evidence_id**: tooling/validate_digest.py, schemas/contract-envelope.v1.schema.json
- **Test**: Old digest in precondition → plan exit 1; Modified payload → digest mismatch → plan exit 1; Wrong layer writing contract → SSM IAM DENIED

#### Control: Saved Plan Substitution Prevention — maturity update for Domain 7 (State Management)

- **Applies to**: Existing state management threats
- **Added controls**: Plan binary stored with SHA-256 digest in plan-execution zone, Apply role verifies digest before `terraform apply <plan>`, plan-execution zone is ephemeral (24-72h TTL), Plan role write + Apply role read isolation, plan digest recorded in apply evidence
- **control_status**: fixture_exists
- **evidence_id**: policies/s3/evidence-bucket.json (plan-execution prefix isolation)
- **Test**: Modified plan binary → digest mismatch → apply rejected; Plan-execution zone expired → apply cannot proceed

### Inline Corrections Applied

| Patch | Section | Change |
|---|---|---|
| 8.2 | T6.3 | Confirmed: residual risk already says LOW for Track B (not NONE) ✓ |
| 8.3 | T1.2 | JWKS is public by design (RFC 7517). Threat is issuer/JWKS misvalidation, not leakage. Added domain pinning control. |
| 8.4 | T2.5 | Added specific prompt injection controls: input length limits, output schema validation, Bedrock guardrails, no raw LLM output |
| 8.5 | Multiple | "No internet access" → "controlled egress via NAT Gateway, restricted by SG rules and SCP" |
| 8.6 | Consistency controls | 4 focused consistency controls added as maturity annotations (not new threats, count remains 48) |

---

## References

- ADR-001: Tenancy Model (JWT verification, data plane isolation, lifecycle invariants)
- ADR-002: Organization (SCPs, delegated security, OUs)
- ADR-003 rev3: State Backend (three-bucket model, plan-execution zone, regional state keys, ownership manifest)
- ADR-004 rev3: Cross-Account Identity (6 scoped roles, separated STS statements, SourceIdentity, transitive tags, AccountVendingProvider bootstrap)
- ADR-005: Schemas (export allowlist, release attestation, sentinel tests, region capability matrix)
- ADR-006 rev3: Modules & Contracts (fail-closed preconditions, content-addressed contracts, session policy per layer, 8-layer dependency graph)
- ADR-007 rev3: Supply Chain (full OCI artifact graph, AWS Signer + KMS DSSE signing, controlled proxy egress, release-based retention, pre-services policy gate)
- ADR-008 rev3: Region/HA/DR (Lambda authorizer for multi-issuer, strong write fencing, outbox pattern, DDB consistency modes, regional state model, multi-region resource ownership)
- ADR-010 rev3: Testing/Rollout/Migration (zero write loss, BatchWriteItem baseline + PutItem delta, wave-based rollout, ECS reconciliation, full async drain, Cognito lazy vs bulk)
- ARCHITECTURE_OWNERSHIP_MATRIX rev2: Resource → layer → role → state → contract mapping
- OWASP Threat Modeling
- AWS Well-Architected Security Pillar
- AWS SaaS Lens: Tenant Isolation
- STRIDE threat classification (Microsoft)
- SLSA Supply Chain Security Framework

