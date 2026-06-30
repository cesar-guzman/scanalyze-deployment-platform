# WS8 Focused Consistency Patches — ADR-009 Threat Model

> **Applied to**: `ADR/ADR-009-threat-model.md`  
> **Date**: 2026-06-28  
> **Status**: Applied

---

## Patch 8.1 — Control Status and Evidence ID per Threat

Each threat in ADR-009 now has `control_status` and `evidence_id` fields.

### Control Status Legend

| Status | Meaning |
|---|---|
| `designed` | Control described in ADR, not yet implemented |
| `fixture_exists` | Policy/schema fixture exists in repository |
| `test_exists` | Automated test verifies the control |
| `deployed` | Control deployed in AWS |
| `verified` | Control verified with evidence |

### Per-Threat Control Status

| Threat | Control Status | Evidence ID | Residual Risk | Notes |
|---|---|---|---|---|
| T1.1 | fixture_exists | policies/trust/plan-trust.json, policies/iam/plan-role.json | Medium | Trust policy exists, but only for Plan; 5 other role trust policies missing |
| T1.2 | designed | — | Low | Lambda authorizer for multi-issuer not implemented |
| T1.3 | designed | — | Very Low | Account boundary is inherent; SCP not yet created |
| T1.4 | designed | — | **HIGH** | IAM Identity Center migration not started |
| T1.5 | fixture_exists | policies/trust/diagnostic-trust.json | Low | Diagnostic trust policy exists; alarm and dual-approval not implemented |
| T1.6 | designed | — | Low | Deployment registry lookup not implemented |
| T2.1 | fixture_exists | schemas/observability-export.v1.schema.json, tooling/security_sentinel.py | Medium | Schema and sentinel exist; runtime masking not deployed |
| T2.2 | designed | — | Very Low | S3 Block Public Access not yet in TF modules |
| T2.3 | fixture_exists | policies/kms/state-key.json | Low | State KMS policy exists; evidence/contracts KMS missing |
| T2.4 | designed | — | Low | SQS isolation per domain not yet in TF |
| T2.5 | designed | — | Medium | Bedrock guardrails not configured |
| T3.1 | designed | — | Low | VPC endpoint policies not defined |
| T3.2 | designed | — | Low | SQS encryption policy not defined |
| T4.1 | designed | — | Low | CloudFront + Route53 not configured |
| T4.2 | designed | — | Medium | CIS/SSB scanning not configured |
| T4.3 | fixture_exists | policies/s3/state-bucket.json, policies/s3/evidence-bucket.json | Low | Bucket policies exist; Object Lock not configured |
| T5.1 | designed | schemas/release.v1.schema.json | Medium | Release schema exists; scanner not operational |
| T5.2 | designed | — | Medium | No build pipeline exists yet |
| T5.3 | designed | — | Medium | Repository and signing infrastructure not created |
| T5.4 | designed | — | Medium | No SBOM generation in pipeline |
| T5.5 | designed | — | Medium | No base image scanning |
| T6.1 | fixture_exists | schemas/deployment-record.v1.schema.json | Medium | Schema exists; runtime detection not implemented |
| T6.2 | designed | — | Medium | Sanitization mechanism not implemented |
| T6.3 | designed | — | Low | CloudTrail not configured |
| T7.1 | fixture_exists | policies/s3/evidence-bucket.json | Medium | Evidence bucket policy with 3-prefix isolation exists |
| T7.2 | fixture_exists | schemas/contract-envelope.v1.schema.json, tooling/validate_digest.py | Low | Contract schema and digest tool exist |
| T7.3 | designed | — | Medium | Deployment record update tracking not implemented |
| T7.4 | designed | — | Medium | Pipeline authorization not implemented |
| T7.5 | designed | — | Low | CloudTrail audit not configured |
| T8.1 | designed | — | Low | SCP region-deny not created |
| T8.2 | designed | — | Medium | Write fencing mechanism not selected |
| T9.1 | designed | — | Medium | Migration checkpoints not implemented |
| T9.2 | designed | — | Medium | Conditional writes not implemented |
| T9.3 | designed | — | Medium | Drain criteria not automated |
| T9.4 | designed | — | Medium | Cut-over procedure not documented |
| T9.5 | designed | — | Medium | Data integrity verification not implemented |
| T9.6 | designed | — | Medium | Rollback procedure not tested |
| T9.7 | designed | — | Medium | Cognito migration not designed |
| T9.8 | designed | — | Medium | DNS cutover not planned |
| T9.9 | designed | — | Medium | Metering reconciliation not designed |
| T9.10 | designed | — | Medium | Feature parity validation not planned |
| T10.1 | designed | — | Medium | Budget alarms not configured |
| T10.2 | designed | — | Medium | Rate limiting not configured |
| T10.3 | designed | — | Low | Reserved capacity not planned |
| T10.4 | designed | — | Medium | Quota monitoring not configured |

---

## Patch 8.2 — T6.3 Residual Risk Correction

**Before**: `Residual risk: NONE`  
**After**: `Residual risk: LOW`

Rationale: "NONE" is unrealistic for any control. CloudTrail can be disabled, delayed, or have retention gaps. LOW is the minimum achievable.

---

## Patch 8.3 — JWKS Threat Clarification

**Threat T1.2 correction**: JWKS endpoints are public by design (RFC 7517). The threat is **issuer/JWKS misvalidation** (e.g., accepting JWKS from a spoofed domain), not JWKS leakage.

Added to controls: "JWKS fetched only from Cognito domain matching deployment's configured issuer; domain pinning in Lambda authorizer; JWKS cache TTL with forced refresh on kid miss."

---

## Patch 8.4 — Prompt Injection Controls Specificity

**Threat T2.5 controls updated**:
- Input length limits per field (document name: 255, notes: 2000)
- Output schema validation (Pydantic model for LLM responses)
- Bedrock guardrails: content filters, denied topics, PII detection
- No raw LLM output in API responses; structured extraction only
- Prompt injection detection in classifier (heuristic + guardrail)

---

## Patch 8.5 — Network Egress Correction

**Before**: Multiple threats reference "no internet access" for private subnets.  
**After**: "Private subnets have controlled egress via NAT Gateway. Egress is restricted by Security Group rules and SCP."

Rationale: Private subnets with NAT Gateway DO have internet egress. The control is Security Group outbound rules and (future) VPC flow log monitoring, not absence of egress.

---

## Patch 8.6 — New Threats Added

### T-ECON-1: Economic DoS via Textract/Bedrock

| Attribute | Value |
|---|---|
| **Threat** | Attacker triggers mass Textract/Bedrock invocations via document upload flood |
| **Impact** | Customer AWS bill spike; service degradation via throttling |
| **Likelihood** | Medium |
| **Controls** | Per-deployment rate limits on ingest-api, SQS-based backpressure, Textract/Bedrock request budgets per hour/day, CloudWatch billing alarms with auto-disable at threshold, WAF rate rules at API Gateway, dead-letter for rejected items |
| **Residual risk** | Medium (billing alarms have latency) |
| **control_status** | designed |
| **evidence_id** | — |
| **Test** | Burst 1000 uploads in 1 minute → rate limited at API Gateway; Monthly billing exceeds 2x baseline → alarm fires |
| **Owner** | Platform operations |

### T-ECON-2: Deployment Registry Tampering

| Attribute | Value |
|---|---|
| **Threat** | Attacker modifies deployment registry to redirect orchestrator to wrong account |
| **Impact** | Cross-customer deployment; data corruption |
| **Likelihood** | Low |
| **Controls** | DynamoDB table policy restricts write to orchestrator role only, deployment_id is immutable key, registry writes logged in CloudTrail, registry reads verify account_id against ACCOUNT_READY, conditional writes (version attribute) |
| **Residual risk** | Low |
| **control_status** | designed |
| **evidence_id** | — |
| **Test** | Non-orchestrator role PutItem → DENIED; Modify deployment_id → condition expression fails; Registry entry for wrong account_id → orchestrator rejects |
| **Owner** | Platform security |

### T-ECON-3: SSM Contract Tampering/Replay

| Attribute | Value |
|---|---|
| **Threat** | Attacker replays old SSM contract parameter or modifies contract payload |
| **Impact** | Consumer layer uses stale/incorrect network, platform, or identity configuration |
| **Likelihood** | Low |
| **Controls** | Contract digest verification in consumer precondition, SSM parameter version tracking, content-addressed contract payloads in S3 (digest as key suffix), Apply role SSM write restricted to producer layer prefix only, contract freshness verified against deployment record |
| **Residual risk** | Low |
| **control_status** | fixture_exists |
| **evidence_id** | tooling/validate_digest.py, schemas/contract-envelope.v1.schema.json |
| **Test** | Old digest in precondition → plan exit 1; Modified payload → digest mismatch → plan exit 1; Wrong layer writing contract → SSM IAM DENIED |
| **Owner** | Platform security |

### T-ECON-4: Saved Plan Substitution

| Attribute | Value |
|---|---|
| **Threat** | Attacker substitutes a saved Terraform plan binary before apply |
| **Impact** | Unauthorized infrastructure changes executed |
| **Likelihood** | Low |
| **Controls** | Plan binary stored with SHA-256 digest in plan-execution zone, Apply role verifies digest before `terraform apply <plan>`, plan-execution zone is ephemeral (24-72h TTL), Plan role write + Apply role read isolation, plan digest recorded in apply evidence |
| **Residual risk** | Low |
| **control_status** | fixture_exists |
| **evidence_id** | policies/s3/evidence-bucket.json (plan-execution prefix isolation) |
| **Test** | Modified plan binary → digest mismatch → apply rejected; Plan-execution zone expired → apply cannot proceed |
| **Owner** | Platform security |
