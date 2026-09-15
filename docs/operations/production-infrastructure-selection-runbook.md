# Production Infrastructure Selection Runbook

## Purpose

This runbook describes how to prepare, validate, and transport the three
infrastructure selections required for production deployment. These selections
identify existing AWS resources by ARN/ID and bind them to their target
Terraform root variables.

**GUG-396.** The local transport supports three root inputs. Production readiness
still requires independently approved sources and verified resource ownership.

## Prerequisites

- Read-only SSO access to the destination account (`905418363887`).
- The approved deployment target/v2 and its independently retrieved target anchor.
  `production-runtime-selection.json` is a proposed tuple, not registry authority.
- A verified release deployment projection, its signed release manifest/VSA and
  approved trust policy, plus the independently reviewed projection digest.
- An independently reviewed selection digest for each exact requested layer.
- Resource existence must be independently verified; ARN syntax validation does
  not prove existence, ownership, or correct configuration.

## Selections

| Selection | Target Layer | Root Variable | Resource Type |
| --- | --- | --- | --- |
| `internal_certificate_arn` | platform | `internal_certificate_arn` | ACM certificate |
| `api_access_log_group_arn` | edge-identity | `api_access_log_group_arn` | CloudWatch log group |
| `route53_zone_id` | edge | `route53_zone_id` | Route53 hosted zone |

## Step 1: Identify Resources

### ACM Certificate (`internal_certificate_arn`)

```bash
aws acm list-certificates --region us-east-1 \
  --profile 905418363887_AWSReadOnlyAccess \
  --query "CertificateSummaryList[?DomainName=='api.scanalyze.cloud']"
```

Verify:
- Certificate status is `ISSUED`.
- Region matches `us-east-1`.
- Domain covers `api.scanalyze.cloud` (not the frontend domain).

### CloudWatch Log Group (`api_access_log_group_arn`)

```bash
aws logs describe-log-groups --region us-east-1 \
  --profile 905418363887_AWSReadOnlyAccess \
  --log-group-name-prefix "/scanalyze/api-access"
```

Verify:
- Log group exists in the deployment account and region.
- ARN contains no wildcards.

### Route53 Hosted Zone (`route53_zone_id`)

```bash
aws route53 list-hosted-zones-by-name \
  --profile 905418363887_AWSReadOnlyAccess \
  --dns-name "scanalyze.cloud"
```

Verify:
- Zone is a public zone.
- Zone is in the correct account.
- NS delegation is properly configured.

## Step 2: Create Selection Document

Create a separate selection document for each requested layer (`platform`,
`edge-identity`, or `edge`). Every document contains all three selections, but
its `layer` permits emission only for that exact layer. Changing the layer or
any resource requires a newly reviewed selection digest.

The following template is **synthetic and intentionally not executable for
production**. IDs and resource names are illustrative; angle-bracket digests
must be replaced with independently approved values before validation. Do not
use these synthetic resources as production input.

```json
{
  "schema_version": "1",
  "record_type": "deployment_infrastructure_selection",
  "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "account_id": "123456789012",
  "region": "us-east-1",
  "environment": "production",
  "partition": "aws",
  "layer": "platform",
  "target_digest": "sha256:<APPROVED_TARGET_RECORD_DIGEST>",
  "release_digest": "sha256:<APPROVED_RELEASE_PROJECTION_DIGEST>",
  "selections": {
    "internal_certificate_arn": {
      "arn": "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789abc",
      "target_layer": "platform",
      "description": "Synthetic certificate; not a production selection"
    },
    "api_access_log_group_arn": {
      "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/synthetic/api-access",
      "target_layer": "edge-identity",
      "description": "Synthetic log group; not a production selection"
    },
    "route53_zone_id": {
      "zone_id": "ZSYNTHETIC123456789",
      "target_layer": "edge",
      "description": "Synthetic zone; not a production selection"
    }
  },
  "record_digest": "sha256:<APPROVED_SELECTION_RECORD_DIGEST>"
}
```

The three CLI anchors identify different documents:

| CLI flag | Bound document and field |
| --- | --- |
| `--expected-digest` | Selection document digest; must match its `record_digest`. |
| `--expected-target-digest` | Approved target/v2 digest; must match the independent target anchor, target `record_digest`, and selection `target_digest`. |
| `--expected-release-digest` | Digest of the verified release deployment projection supplied through `--release`; must match selection `release_digest` and the reviewed `release_bindings.release_projection_digest`. |

For this materializer path, the third anchor is the **projection digest**.
The projection's `release_manifest_digest` is a separate value: it identifies the
signed manifest and must match the workflow request/claim `release_digest`.
Do not substitute that manifest digest for the projection digest or the selection
digest. The CLI also accepts a `release.v2` document, but production transport
supplies the projection rebuilt by the existing signature/trust-policy verifier.

Selection and target record hashes use canonical JSON excluding their own
`record_digest`. A matching self-hash establishes integrity only; obtain the
expected digests through their independent review/registry authority.

## Step 3: Validate Offline

Use prepared files in an existing private directory outside the repository.
The commands below assume `SCANALYZE_PRIVATE_INPUT_DIR` points to that directory;
they do not create credentials, contact AWS, or authorize deployment.

```bash
python3 -m tooling.deployment_infrastructure_selection \
  --selection "${SCANALYZE_PRIVATE_INPUT_DIR:?}/infrastructure-selection.platform.json" \
  --syntax-check-only
```

Expected output:
```json
{
  "status": "VERIFIED_SYNTAX",
  "layers": ["edge", "edge-identity", "platform"],
  "variables_count": 3
}
```

This checks syntax, tuple consistency within the selection, and its self-digest
when present. It does not emit variables, verify resource existence, or establish
independent target/release authority.

## Step 4: Emit Per-Layer Variables

Set `INFRASTRUCTURE_SELECTION_DIGEST`, `TARGET_RECORD_DIGEST`, and
`RELEASE_PROJECTION_DIGEST` from the three independently reviewed anchors above.
The output must not already exist; the CLI creates it with mode `0600` outside
the repository.

```bash
python3 -m tooling.deployment_infrastructure_selection \
  --selection "${SCANALYZE_PRIVATE_INPUT_DIR:?}/infrastructure-selection.platform.json" \
  --expected-digest "${INFRASTRUCTURE_SELECTION_DIGEST:?}" \
  --target "${SCANALYZE_PRIVATE_INPUT_DIR:?}/target-record.json" \
  --expected-target-digest "${TARGET_RECORD_DIGEST:?}" \
  --release "${SCANALYZE_PRIVATE_INPUT_DIR:?}/release-deployment-projection.json" \
  --expected-release-digest "${RELEASE_PROJECTION_DIGEST:?}" \
  --layer platform \
  --out "${SCANALYZE_PRIVATE_INPUT_DIR:?}/platform-infra-vars.json"
```

Success returns `VERIFIED_AND_BOUND`, `layer: platform`, and
`variables_count: 1`. For another layer, use its separately reviewed selection
document/digest and matching `--layer` and output path.

## Step 5: Transport

The local materializer/controller transport for `platform`, `edge-identity`,
and `edge` requires sealed-request v3/v4 selection sources and independent
release bindings. It verifies the signed release bundle and rebuilds its
projection before binding the selection to the target and exact layer. The
materializer then writes the selection at the fixed private path:
`materialized/sources/infrastructure-selection.json` (mode `0600`)
with its expected digest forwarded as:
`--infrastructure-selection` and `--expected-infrastructure-selection-digest`.

The standalone CLI output does not replace the reviewed claim, registry anchor,
signed release authority, or materializer gates. Local transport support does
not prove a successful GitHub dispatch, plan/apply, or production deployment.

## Rollback

This runbook creates no cloud resources. Removing the selection document
reverses the proposal. If resources were selected in error, correct the
document and re-validate.
