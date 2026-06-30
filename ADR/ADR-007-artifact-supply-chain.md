# ADR-007: Artifact Supply Chain — Build, Sign, Scan, Attest, Promote

> **Status**: `DRAFT rev3`  
> **Date**: 2026-06-23  
> **Decision makers**: César Guzmán  
> **Scope**: Scanalyze Dedicated Deployment Platform  
> **Depends on**: ADR-001, ADR-004 rev3, ADR-005, ADR-009  
> **Rev3 changes**: P1 supply chain — controlled egress, explicit signing mechanisms, copy+verify promotion, flexible referrer validation, release-based retention

---

## Context

Scanalyze deploys container images, Terraform modules, and frontend bundles into customer accounts containing regulated data. A compromised artifact executing in a customer account is a critical threat (T5.1). The supply chain must provide end-to-end integrity from source commit to running workload.

---

## Decision

### 1. SLSA Compliance Target

| Level | Target | Status |
|---|---|---|
| SLSA Build L1 | Build process documented | ✅ This ADR |
| SLSA Build L2 | Hosted, authenticated build; signed provenance | ✅ Target for v1 |
| SLSA Build L3 | Hardened build platform; non-falsifiable provenance | 🎯 Future target |

### 2. Supply Chain Pipeline

```
Source Code (GitHub)
    │
    ├── Branch protection (required reviews, signed commits)
    ├── CODEOWNERS enforced
    └── Pre-merge CI (lint, test, ownership check)
    │
    ▼
Build Stage (Shared Services CodeBuild — ephemeral, isolated, controlled egress)
    ├── docker build (pinned base image by digest)
    ├── Image tagged: {service}:{git-sha-short}
    ├── Pushed to Central ECR (Shared Services)
    ├── Build provenance metadata (build ID, git SHA, timestamp, builder identity)
    ├── SBOM generated (Syft → SPDX JSON)
    └── SBOM pushed as OCI artifact alongside image
    │
    ▼
Dependency Scan Stage
    ├── pip-audit (Python backend dependencies)
    ├── npm audit (Frontend dependencies)
    ├── License compliance check (reject GPL in runtime deps)
    └── Dependency scan report stored as artifact
    │
    ▼
Container Scan Stage
    ├── ECR Enhanced Scanning (Inspector)
    ├── Scan report stored as artifact
    ├── Gate policy evaluated (§13)
    └── Scan evidence digest computed
    │
    ▼
Sign Stage
    ├── AWS Signer signs image manifest digest (OCI images)
    ├── Signature stored as OCI artifact in ECR (referrers API)
    └── Signature reference recorded in release data
    │
    ▼
Provenance Stage
    ├── Build provenance attestation generated (in-toto/DSSE format)
    ├── Provenance pushed as OCI artifact alongside image
    └── Provenance digest recorded in release manifest
    │
    ▼
Release Stage
    ├── Release manifest generated (scanalyze.release.v1)
    ├── Manifest signed (KMS asymmetric ECDSA_SHA_256 + DSSE envelope)
    ├── Release attestation generated (scanalyze.release-attestation.v1)
    ├── Attestation signed (KMS asymmetric ECDSA_SHA_256 + DSSE envelope)
    └── Release tagged: {release_version}
    │
    ▼
Promotion Stage (per customer account — see §9)
    ├── Full OCI artifact graph promoted (copy + verify)
    ├── Post-promotion integrity verification against central trust roots
    ├── Customer ECR Enhanced Scanning
    └── Promotion recorded in deployment record
```

### 3. Source Code Provenance

Branch protection, signed commits, CODEOWNERS, pre-merge CI. Unchanged from rev1.

### 4. Build Environment — Controlled Egress

> [!IMPORTANT]
> **Build environment uses controlled egress, NOT "no internet."** Fully air-gapped builds require local mirrors for all build dependencies (base images, Python packages, npm packages, OS packages). Until mirrors exist, builds use a controlled proxy with allowlisted destinations.

#### Current state: Controlled egress proxy

```
CodeBuild (VPC-attached, private subnets)
  → NAT Gateway → Internet
  → Egress restricted by:
     - Security Group: outbound HTTPS only (port 443)
     - VPC endpoint for ECR, S3, STS, CloudWatch, KMS
     - Proxy allowlist (squid or AWS Network Firewall):
         *.docker.io          (base images — until mirrored)
         pypi.org              (pip install — until CodeArtifact)
         registry.npmjs.org    (npm ci — until CodeArtifact)
         github.com            (git clone — until mirrored)
```

#### Roadmap: Full air-gap

| Dependency | Mirror solution | Priority |
|---|---|---|
| Base images | ECR pull-through cache → pin by digest | P0 (before production) |
| Python packages | CodeArtifact upstream proxy | P1 |
| npm packages | CodeArtifact upstream proxy | P1 |
| OS packages (apt/yum) | ECR or S3-hosted mirror | P2 |
| Git source | CodeCommit mirror or S3 bundle | P2 |

#### Builder image

```
scanalyze/build-environment@sha256:{digest}
  ├── Base: amazonlinux:2023 (pinned digest, monthly review)
  ├── Installed: docker, python3.11, node20, terraform, syft, pip-audit
  ├── Built by: dedicated builder-image pipeline (same signing chain)
  └── Updated: monthly or on CVE
```

### 5. Base Image Provenance

Digest-pinned, monthly review cycle. Unchanged from rev1.

### 6. Signing Mechanisms

Two distinct signing mechanisms for two artifact types:

#### OCI container images — AWS Signer

| Property | Value |
|---|---|
| Service | AWS Signer |
| Profile | `scanalyze-release-signing` |
| Algorithm | ECDSA (Signer-managed) |
| What is signed | Image manifest digest (not tag) |
| Who signs | `ScanalyzeReleaseSigningRole` (dedicated, ADR-004) |
| Storage | OCI artifact in ECR (referrers API) |
| Verification | Signer SDK verification against signing profile |
| Revocation | Signer supports revoking signing jobs |
| Key rotation | Signer manages key lifecycle |

#### JSON artifacts (release manifest, attestation) — KMS + DSSE

| Property | Value |
|---|---|
| Service | AWS KMS asymmetric key |
| Algorithm | `ECDSA_SHA_256` (`ECC_NIST_P256`) |
| Envelope | DSSE (Dead Simple Signing Envelope) with in-toto Statement |
| What is signed | SHA-256 digest of canonical JSON payload |
| Who signs | `ScanalyzeReleaseSigningRole` (same role, `kms:Sign` permission) |
| Storage | S3 alongside the manifest (`.sig.dsse` extension) |
| Verification | `kms:Verify` with public key, or offline with exported public key |
| Key rotation | Manual rotation with grace period; old key retained for verification |

> [!IMPORTANT]
> **The central signing identity is authoritative.** A release is trusted because the central release pipeline signed it with the central KMS key. Customer accounts verify against the central public key. No local re-signing replaces or supplements the central signature — local attestation is optional, additional evidence of promotion, not a replacement of the origin signature.

#### Trust roots

| Trust root | Purpose | Location |
|---|---|---|
| Signer signing profile ARN | Verify OCI image signatures | Shared Services, referenced in deployment record |
| KMS public key ARN | Verify release manifest and attestation signatures | Shared Services, public key exportable |
| Builder identity | Verify provenance subject matches (CodeBuild project ARN) | Recorded in provenance attestation |
| SBOM tool identity | Verify SBOM was generated by approved tooling | Recorded in SBOM metadata |

### 7. Central ECR (Shared Services)

| Property | Value |
|---|---|
| Location | Shared Services account |
| Naming | `scanalyze/{service}` (namespaced) |
| Tags | `{git-sha-short}`, `{release_version}` |
| Immutability | Tag immutability **enabled** |
| Scanning | Enhanced (Inspector) |
| Encryption | KMS (Shared Services account key) |
| Access | PipelineExecution role for push; Orchestrator role for pull/promote |
| **OCI artifacts** | SBOM, signature, and provenance stored as referrers to image manifest |

### 8. Customer Account ECR

| Property | Value |
|---|---|
| Location | Customer account |
| Naming | Same namespace: `scanalyze/{service}` |
| Scanning | Enhanced (Inspector) — post-promotion rescan |
| Immutability | Tag immutability enabled |
| Access | ECS task execution role for pull; **Promotion role** for push (ADR-004 rev3) |
| **OCI artifacts** | SBOM, signature, and provenance must exist alongside image after promotion |

### 9. Promotion: Copy + Verify (Not Re-Sign)

> [!IMPORTANT]
> **Promotion copies the full OCI artifact graph and verifies against central trust roots.** It does NOT re-sign. AWS Signer signatures reference immutable digests — as long as the digest is unchanged after copy, the signature remains valid. The central signing profile must be accessible for verification from the customer account (cross-account Signer profile access or exported public key).

#### OCI artifact graph per image

```
Container Image Manifest (sha256:abc123)
    ├── Image layers (actual container content)
    ├── [referrer] AWS Signer Signature (application/vnd.aws.signer.v1+json)
    ├── [referrer] SBOM (application/spdx+json)
    └── [referrer] Build Provenance (application/vnd.in-toto+json)
```

#### Promotion procedure

```
For each service image in the release manifest:

  PREPARE (using Orchestrator role in Shared Services):
    1. Resolve image digest from release manifest
    2. Verify signature on image manifest (AWS Signer, central profile)
    3. Verify SBOM artifact exists and digest matches release manifest
    4. Verify provenance artifact exists and digest matches release manifest

  TRANSFER (using Promotion role — ADR-004 rev3 — in customer account):
    5. Pull image manifest from Central ECR (by digest)
    6. Push image manifest to Customer ECR (by digest)
    7. Verify: destination image digest == source image digest

    8. Pull signature artifact from Central ECR
    9. Push signature artifact to Customer ECR (as OCI referrer)
       (Copy — not re-sign. Digest-based reference is stable.)
    10. Verify: destination signature digest == source signature digest

    11. Pull SBOM artifact from Central ECR
    12. Push SBOM artifact to Customer ECR (as OCI referrer)
    13. Verify: destination SBOM digest == source SBOM digest

    14. Pull provenance artifact from Central ECR
    15. Push provenance artifact to Customer ECR (as OCI referrer)
    16. Verify: destination provenance digest == source provenance digest

  POST-PROMOTION VERIFICATION:
    17. List all referrers to customer image digest
    18. Verify: at least one approved referrer per required type
        (signature, SBOM, provenance) — see §10
    19. Verify: no prohibited referrer types exist
    20. Trigger customer ECR Enhanced Scanning on promoted image
    21. Wait for scan completion (timeout: 10 minutes)
    22. Evaluate scan results against gate policy (§13)
    23. Record promotion evidence in deployment record:
        - source_digest, destination_digest (must match)
        - signature_digest, sbom_digest, provenance_digest
        - scan_status, scan_findings_summary
        - promotion_timestamp, change_id

  OPTIONAL — Promotion attestation:
    24. Generate promotion attestation (in-toto Statement):
        - Subject: customer image digest
        - Predicate: source image digest, source ECR, promotion time, change_id
    25. Sign with KMS (same DSSE envelope mechanism as release manifest)
    26. Push as additional OCI referrer in customer ECR
```

> [!NOTE]
> **Promotion attestation (steps 24-26) is optional additional evidence** — it records WHO promoted WHAT from WHERE. It does NOT replace the central signature. The deployment record is the authoritative promotion record; the OCI attestation provides in-band verification.

#### Promotion failure modes

| Failure | Action |
|---|---|
| Image digest mismatch after push | ABORT — possible corruption in transit |
| Signature verification fails | ABORT — image integrity compromised |
| SBOM missing from central ECR | ABORT — supply chain incomplete |
| Provenance missing from central ECR | ABORT — supply chain incomplete |
| SBOM/provenance digest mismatch after push | ABORT — artifact corruption |
| Customer ECR scan finds critical/high | ABORT — image vulnerable |
| Scan timeout (>10 min) | RETRY once, then ABORT with alert |
| No approved referrer for a required type | ABORT — incomplete artifact graph |
| Prohibited referrer type detected | ABORT — unexpected artifact |

### 10. Referrer Validation — Flexible, Not Count-Based

> [!IMPORTANT]
> Validation checks for **at least one approved referrer per required type**, not an exact count. This accommodates optional attestations (promotion attestation, scan attestation) without breaking validation.

| Required type | Media type pattern | Minimum | Source |
|---|---|---|---|
| Signature | `application/vnd.aws.signer.*` | 1 | Release pipeline (central) |
| SBOM | `application/spdx+json` | 1 | Build pipeline (Syft) |
| Provenance | `application/vnd.in-toto+json` | 1 | Build pipeline |

| Optional type | Media type pattern | When present |
|---|---|---|
| Promotion attestation | `application/vnd.scanalyze.promotion+json` | If promotion attestation is enabled |
| Scan attestation | `application/vnd.scanalyze.scan+json` | Future: Inspector scan result attestation |

| Prohibited type | Why |
|---|---|
| Unknown media types | Could indicate tampering or unauthorized tooling |

Validation logic:
```
for each required_type in [signature, sbom, provenance]:
  if count(referrers matching required_type.media_type) < 1:
    ABORT "Missing required referrer: {required_type}"

for each referrer in all_referrers:
  if referrer.media_type not in (required_types ∪ optional_types):
    ABORT "Prohibited referrer type: {referrer.media_type}"

for each required_type in [signature, sbom, provenance]:
  if referrer.digest != release_manifest.expected_digest[required_type]:
    ABORT "Referrer digest mismatch for {required_type}"
```

### 11. SBOM

| Property | Value |
|---|---|
| Tool | Syft |
| Format | SPDX JSON (2.3+) |
| Storage | OCI artifact alongside image in ECR (both central and customer) |
| Digest | Recorded in release manifest |
| Content | OS packages, Python packages, Node packages, base image layers |
| Purpose | Vulnerability tracking, license compliance, incident response |
| **Promotion** | Copied as part of full OCI artifact graph |

### 12. Frontend Artifact Pipeline

```
Frontend build (npm ci + vite build)
    ├── Output: dist/ directory (HTML, JS, CSS, assets)
    ├── Compute SHA-256 of each output file
    ├── Generate asset manifest with content-addressed keys
    ├── Upload to customer S3 with content-addressed paths:
    │     assets/{hash}.js, assets/{hash}.css
    ├── Generate index.html with SRI hashes:
    │     <script src="assets/{hash}.js"
    │            integrity="sha256-{base64}" crossorigin="anonymous">
    ├── Upload index.html (not content-addressed — overwritten each deploy)
    ├── CloudFront invalidation: /* (or specific paths)
    └── Promotion evidence:
          - asset manifest digest
          - index.html digest
          - CloudFront invalidation ID
```

> [!NOTE]
> Frontend bundles are promoted by the **Promotion role** (ADR-004 rev3). The role has `s3:PutObject` on the frontend prefix and `cloudfront:CreateInvalidation`. It does NOT have infrastructure write permissions.

### 13. Vulnerability Scan Gate Policy

| Severity | Action |
|---|---|
| Critical | BLOCK — cannot deploy |
| High | BLOCK — requires security team waiver with expiration |
| Medium | RECORD — deploy with advisory in deployment record |
| Low | RECORD — deploy normally |

Waivers:
- Require: justification, approver, expiration date, affected CVE(s)
- Stored: S3 (waiver document) + DynamoDB (waiver registry)
- Monitored: expired waivers block subsequent deployments
- Audit: monthly review of active waivers

### 14. Dependency Scanning

pip-audit (Python), npm audit (Node), license compliance. Unchanged from rev1.

### 15. Terraform Module Versioning

Internal modules referenced by relative path. Module digest computed per release. Unchanged from rev1.

### 16. Build Determinism

Pinned base images, lockfiles committed, no `latest` tags. Unchanged from rev1.

### 17. Release Versioning

Calendar versioning: `YYYY.MM.patch` (e.g., `2026.06.0`). Unchanged from rev1.

### 18. Artifact Retention — Release-Based

> [!IMPORTANT]
> Retention is **release-based**, not "last N images." Artifacts are retained as long as their release has an active retention reason.

#### Retention reasons

| Reason | Duration | Who sets |
|---|---|---|
| **Active release** | Until superseded | Deployment pipeline |
| **Previous supported** | Until N+2 is active | Deployment pipeline |
| **Last known-good** | Until next successful deploy | Validation pipeline |
| **Rollback candidate** | 30 days after superseded | Deployment pipeline |
| **Security/legal hold** | Indefinite | Security team (manual) |

#### Retention by artifact type

| Artifact | Location | Retention policy |
|---|---|---|
| Container images (central) | ECR Shared Services | All retention reasons above |
| Container images (customer) | ECR customer | Active + previous + rollback + hold |
| OCI referrers (sig/SBOM/prov) | ECR (both) | Same as associated image (cascade delete) |
| Release manifests | S3 Shared Services | 2 years (regulatory) |
| Release attestations | S3 Shared Services | 2 years (regulatory) |
| DSSE signatures | S3 Shared Services | Same as associated manifest |
| Scan reports | S3 Shared Services | 1 year |
| Build logs | CloudWatch | 365 days |
| Waivers | S3 + DynamoDB | 2 years after expiration |
| Frontend bundles (central) | S3 Shared Services | Same as release manifest |
| Frontend bundles (customer) | S3 customer | Active + previous + rollback |

> [!NOTE]
> **ECR cascade-deletes reference artifacts** (OCI referrers) when the subject image manifest is deleted by lifecycle policy. This means OCI signatures, SBOMs, and provenance are automatically cleaned up when the image they reference is removed.

#### ECR lifecycle policy

```json
{
  "rules": [
    {
      "rulePriority": 1,
      "description": "Protect images with active retention tags",
      "selection": {
        "tagStatus": "tagged",
        "tagPrefixList": ["active-", "prev-", "lkg-", "rollback-", "hold-"],
        "countType": "sinceImagePushed",
        "countNumber": 730,
        "countUnit": "days"
      },
      "action": { "type": "expire" }
    },
    {
      "rulePriority": 2,
      "description": "Delete untagged images after 7 days",
      "selection": {
        "tagStatus": "untagged",
        "countType": "sinceImagePushed",
        "countNumber": 7,
        "countUnit": "days"
      },
      "action": { "type": "expire" }
    }
  ]
}
```

### 19. Supply Chain Security Tests

| # | Test | Expected |
|---|---|---|
| 1 | Promote image without signature | ABORT — signature missing |
| 2 | Promote image without SBOM | ABORT — SBOM missing |
| 3 | Promote image without provenance | ABORT — provenance missing |
| 4 | Promote image with tampered digest | ABORT — digest mismatch |
| 5 | Promote revoked image | ABORT — signature revoked |
| 6 | Run customer ECS with unsigned image | FAIL — task def validation rejects |
| 7 | Deploy with expired waiver | BLOCK — waiver expired |
| 8 | Reference `:latest` in Dockerfile | CI REJECT — lint failure |
| 9 | Use unpinned base image | CI REJECT — lint failure |
| 10 | Promote with unknown referrer type | ABORT — prohibited referrer |
| 11 | Verify release manifest with wrong KMS key | FAIL — signature invalid |
| 12 | Verify release manifest after key rotation (old key) | PASS — old key retained |

### 20. Release Flow Summary

```
Developer
  └── PR → main (code review, CI checks, CODEOWNERS)
        │
        ▼
  Release branch cut (release/2026.06)
        │
        ▼
  Release pipeline (automated, Shared Services CodeBuild)
        ├── Build all container images (ephemeral, controlled egress)
        ├── Build frontend bundle (npm ci + vite build)
        ├── Generate SBOMs for all images (Syft → SPDX)
        ├── Push SBOMs as OCI artifacts
        ├── Dependency scan (pip-audit, npm audit, licenses)
        ├── Container scan (ECR Enhanced/Inspector)
        ├── Gate policy evaluation
        ├── Sign all image digests (AWS Signer, ScanalyzeReleaseSigningRole)
        ├── Push signatures as OCI artifacts
        ├── Generate build provenance (in-toto/DSSE)
        ├── Push provenance as OCI artifacts
        ├── Compute module digests
        ├── Generate release manifest (scanalyze.release.v1)
        ├── Sign manifest (KMS ECDSA_SHA_256 + DSSE envelope)
        ├── Generate attestation (scanalyze.release-attestation.v1)
        ├── Sign attestation (KMS ECDSA_SHA_256 + DSSE envelope)
        └── Tag release: 2026.06.0
        │
        ▼
  Deployment pipeline (per customer, per ADR-010 ring strategy)
        ├── Verify release manifest signature (KMS public key)
        ├── Verify release attestation signature
        ├── Promote FULL OCI artifact graph per image:
        │     image + signature + SBOM + provenance (copy + verify)
        ├── Verify all artifacts against central trust roots
        ├── Wait for customer ECR re-scan
        ├── Deploy frontend to customer S3/CloudFront (Promotion role)
        ├── Terraform plan + apply (services layer owns ECS task defs)
        └── Runtime validation suite
```

---

## Consequences

### Positive
- Full evidence chain from source commit to running workload in customer account
- Every artifact (image, signature, SBOM, provenance) exists in customer ECR
- Incomplete artifact graph is rejected before deployment
- SLSA L2 provenance verifiable in customer context
- Two distinct signing mechanisms chosen for the right artifact type
- Central signing identity is authoritative — no local replacement
- Copy+verify avoids re-signing complexity while maintaining integrity
- Flexible referrer validation accommodates future attestation types
- Release-based retention prevents premature deletion of rollback candidates
- Controlled egress with clear roadmap to full air-gap
- Post-promotion scan catches customer-specific environment issues

### Negative
- Controlled egress is not yet fully air-gapped (acceptable until mirrors exist)
- Promotion is complex (4+ artifacts per image × N images)
- Two signing mechanisms (Signer + KMS) add implementation complexity
- ECR lifecycle policy requires tag-based retention management
- Release-based retention is more complex than simple "last N" rules
- KMS key rotation for manifest signing requires grace period management

---

## References

- ADR-001: Tenancy Model (per-account ECR)
- ADR-004 rev3: Cross-Account Identity (Promotion role, signing role, Shared Services principals)
- ADR-005: Schemas (release manifest, attestation)
- ADR-009: Threat Model (T5.1–T5.5)
- ADR-010: Testing/Rollout (ring-based deployment)
- [OCI Distribution Spec: Referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers)
- [AWS Signer User Guide](https://docs.aws.amazon.com/signer/latest/developerguide/Welcome.html)
- [AWS KMS Asymmetric Keys](https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html)
- [DSSE — Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse)
- [in-toto Attestation Framework](https://github.com/in-toto/attestation)
- [AWS ECR Enhanced Scanning (Inspector)](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-enhanced.html)
- [AWS ECR Lifecycle Policies](https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html)
- [Syft SBOM Generator](https://github.com/anchore/syft)
- [SLSA Framework](https://slsa.dev)
- [SPDX Specification](https://spdx.github.io/spdx-spec/)
- [Subresource Integrity (SRI)](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
