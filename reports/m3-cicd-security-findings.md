# M3-CICD — Security Findings

## Credential Exposure

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| SEC-001 | 🔴 CRITICAL | Cognito user `sandbox-test@scanalyze.cloud` password exposed in chat history | **PENDING ROTATION** |
| SEC-002 | ⚠️ HIGH | AWS session tokens (sandbox + management) shared in chat | Expired / session-scoped |

### SEC-001 — Cognito Credential Rotation

- **User Pool ID:** `us-east-1_BKi9gCO6T` (sandbox account)
- **Username UUID:** `94981458-9001-706c-8e41-388b9a4ffc95`
- **Email:** `sandbox-test@scanalyze.cloud`
- **Action Required:** `AdminDeleteUser` o `AdminDisableUser`
- **Attempted:** Delete failed due to expired session token
- **Constraint:** Must use SSO/approved session, no long-lived keys

### SEC-002 — Session Token Exposure

- Tokens were STS temporary credentials (session-scoped)
- Both tokens have expired naturally
- No long-lived access keys were created
- **Recommendation:** Verify no IAM users with permanent keys exist in sandbox

---

## IAM Policy Findings (ci-cd-micros brownfield)

| ID | Severity | Rule | File | Line | Finding |
|----|----------|------|------|------|---------|
| CICD-004 | 🔴 BLOCKER | ecs:* wildcard | main.tf | 667 | Allows register-task-definition, update-service |
| CICD-001 | 🔴 BLOCKER | ECS deploy provider | main.tf | 851 | Pipeline mutates task definitions |
| CICD-003 | 🔴 BLOCKER | imagedefinitions deploy | main.tf | 841,858 | Enables implicit register-task-def |
| CICD-005 | 🔴 BLOCKER | PassRole "*" | main.tf | ~670 | iam:PassRole fallback to wildcard |

### Resolution in v2 Module

All blockers resolved in `modules/cicd/main.tf`:

- `ecs:*` → **Removed entirely**. CodeBuild/Pipeline have zero ECS permissions
- ECS deploy stage → **Removed**. Pipeline ends at Build
- imagedefinitions deploy → **Removed**. Build writes digest to SSM
- PassRole → **Removed from pipeline**. Pipeline doesn't need PassRole (no ECS deploy)

---

## ECR Security Findings

| ID | Severity | Finding | v2 Resolution |
|----|----------|---------|---------------|
| ECR-001 | ⚠️ HIGH | ECR repos not created by any v2 layer | cicd module now creates ECR repos |
| ECR-002 | ⚠️ HIGH | Tag mutability not enforced | v2 sets `image_tag_mutability = "IMMUTABLE"` |
| ECR-003 | ⚠️ MEDIUM | No scan-on-push | v2 enables `scan_on_push = true` |
| ECR-004 | ⚠️ MEDIUM | No KMS encryption on ECR | v2 uses KMS encryption |

---

## Supply Chain Findings

| ID | Severity | Finding | v2 Status |
|----|----------|---------|-----------|
| SC-001 | ⚠️ HIGH | No SBOM generation | Not yet addressed |
| SC-002 | ⚠️ HIGH | No image signing/provenance | Not yet addressed |
| SC-003 | ⚠️ MEDIUM | No release manifest | Partially addressed (SSM metadata) |
| SC-004 | ⚠️ MEDIUM | Build-per-customer (no build-once/deploy-many) | Classified as sandbox exception |
| SC-005 | ⚠️ LOW | No vulnerability scan gate | scan_on_push enabled but no gate |

---

## Lint Results (automated)

```
Scanned: 3 root(s) (cicd v2 + brownfield + services)
Blockers: 8 (all in brownfield, 0 in v2)
Warnings: 1 (image digest validation in services variables)
```

**v2 module passes lint with 0 blockers.**

---

## Recommendations Priority

1. 🔴 **Immediate:** Delete Cognito user SEC-001
2. 🔴 **Immediate:** Verify no permanent IAM users in sandbox
3. ⚠️ **Phase 2:** Add SBOM generation to buildspec
4. ⚠️ **Phase 2:** Add image signing (cosign or AWS Signer)
5. ⚠️ **Phase 3:** Add vulnerability scan gate before release
6. ⚠️ **Phase 3:** Implement formal release manifest (not just SSM)
