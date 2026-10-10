# GUG-446 checksum custody repair and retained-resource recovery

Status: **LOCAL PREPARATION / NO RECOVERY EXECUTED / PRODUCTION NO-GO**.

Issue: [GUG-446](https://linear.app/guguce/issue/GUG-446/repair-gug-274-checksum-custody-policy-and-prepare-retained-resource).
Repository: `cesar-guzman/scanalyze-deployment-platform`.
Branch: `codex/gug-446-custody-recovery`.
Known integrated base: `6954e63a81657c6fb52aeedba12656836e67d897`.
Target: authority account `042360977644`, Region `us-east-1`.
The owner approved the audit-prefix source correction and isolated local recovery
preparation. That approval does not cover publication or any AWS request that
creates, imports, updates, deletes or activates resources.

## Dated failure checkpoint

On 2026-10-07 the owner submitted the original reviewed CREATE once. Its stack
reached `ROLLBACK_COMPLETE`. The two buckets and two policies reached
`CREATE_COMPLETE`; `CustodyTrail` then failed with `InvalidRequest` and an
incorrect audit bucket policy diagnosis. All five stack records subsequently
showed `DELETE_SKIPPED`.

Exact failed stack:

`arn:aws:cloudformation:us-east-1:042360977644:stack/scanalyze-gug274-checksum-custody/e4536fb0-c233-11f1-8e3a-0eaf936ad8ef`

Exact attempted Change Set:

`arn:aws:cloudformation:us-east-1:042360977644:changeSet/custody-disabled-59de32582c35-v1/05583d51-c4c4-4988-beb7-a3770521049e`

A separate exact `GetTrail` returned `TrailNotFoundException`. The failed
stack's physical trail identifier does not establish trail existence.
Both buckets passed expected-owner reads with versioning Enabled,
BucketOwnerEnforced, all four public-access blocks and default AES256.
Their policies matched the original source structurally. No object contents,
audit logs or credentials were read.

These observations are a checkpoint, not current-state evidence for a future
operation. The shared-entry ManifestWriter permission is usable with the
retained report bucket; no role assumption or upload occurred in this review.
Do not claim empty buckets or a guaranteed final zero bill.

The original source template SHA-256 is
`59de32582c35fa1a283a8d3de7da7eff14fb286658b081abbc91be1e223db6f8`.
The original attempt `gug274-custody-disabled-execute-59de32582c35-v1`
is consumed. Preserve its marker. Never reset it, retry either original runner
version or interpret this local correction as renewed execution approval.

## Approved source difference

The [full target template](../../bootstrap/cfn-platform-authority-gug274-checksum-custody.yaml)
changes only two audit-policy statements and the descriptive Deny Sid:

- `DenyWritesOutsideExactTrailAccountPrefix`: one exact account prefix in
  `NotResource`, replacing the two regional log/digest patterns.
- `ExactTrailLogAndDigestDelivery`: the same prefix in `Resource`.

Resolved resource:

`arn:aws:s3:::scanalyze-gug274-checksum-audit-042360977644-us-east-1/scanalyze/platform-authority/gug-274/checksum/audit/AWSLogs/042360977644/*`

This deliberately allows additional object subpaths, including other Region
folders, inside that account delivery namespace. It retains the exact
`cloudtrail.amazonaws.com` service, exact trail SourceArn in
`us-east-1/042360977644`, owner-full-control ACL, missing-context denies,
TLS/service exception, encryption/SSE-C denies and deletion denies. All other
resources, inputs, rules and event selectors remain unchanged. Capture is still
hardcoded off; multi-region, organization and global-service capture remain off.

AWS documents that account delivery-prefix resource in its
[CloudTrail bucket policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html).
The internal path or context used by the failed CreateTrail validator was not
observed. This is a reviewed compatibility correction, not proof of AWS
acceptance or delivery. Do not relax other conditions to make it pass.

Full corrected template SHA-256:
`f7850f540ceeaf49fbb43af4ab48c12cd52c8b285cc5f580430400a09bbbacff`.
Any byte change requires fresh digest/input reconciliation before publication
or an AWS review.

## Stage A: prepare an unchanged four-resource IMPORT

A failed CREATE in `ROLLBACK_COMPLETE` cannot be repaired by ordinary UPDATE.
[CloudFormation states](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/view-stack-events.html).
Do not submit another CREATE over the retained names.

Prepared source:

- [Import template](../../bootstrap/cfn-platform-authority-gug274-checksum-custody-import.yaml).
- [Four physical identifiers](../../bootstrap/gug274-checksum-custody-import-resources.json).
- [Import parameters](../../bootstrap/gug274-checksum-custody-recovery-import.parameters.json).

The import template contains only the four retained resources, with their
original properties and policies. It creates no trail and grants no new IAM
permission. Each resource retains `DeletionPolicy: Retain` and
`UpdateReplacePolicy: Retain`.

| Logical ID | Type | Identifier | Exact value |
| --- | --- | --- | --- |
| ReportBucket | AWS::S3::Bucket | BucketName | scanalyze-gug274-checksum-reports-042360977644-us-east-1 |
| AuditBucket | AWS::S3::Bucket | BucketName | scanalyze-gug274-checksum-audit-042360977644-us-east-1 |
| ReportBucketPolicy | AWS::S3::BucketPolicy | Bucket | scanalyze-gug274-checksum-reports-042360977644-us-east-1 |
| AuditBucketPolicy | AWS::S3::BucketPolicy | Bucket | scanalyze-gug274-checksum-audit-042360977644-us-east-1 |

The six import bindings are frozen to the reviewed original values.
`TemplateDigest` remains the original `59de…` provenance tag value; it is
not the import template's own file hash. Record the import file's distinct
SHA-256 in the future review packet without changing the retained resource tags.
There is no self-referential template digest.

CloudFormation import can apply stack-level tags. The future request must
explicitly review these writes, including CloudFormation ownership tags, and
avoid introducing unreviewed user stack tags. An unchanged resource template
does not prove that adoption has no tagging effects. Reconcile tags before and
after import; do not attribute changed ownership tags to configuration drift.

Both resource types support import, but import must not simultaneously alter
configuration or create the absent trail. Historical `DELETE_SKIPPED`,
stack tags and physical-ID lookups do not prove that the resources are free of
another stack's ownership. CloudFormation validates import eligibility.
[Supported types](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-supported-resources.html),
[Import rules](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/import-resources-manually.html).

Before any future import preparation:

1. Publish/review the exact source candidate and verify exact-head required CI.
2. Select one exact recovery-stack name and Change Set name with the owner;
   neither a new stack ARN nor import eligibility is known now.
3. With the approved profile and fresh STS, reconcile the failed stack Original
   template, status, retained configuration, ownership and exact trail absence.
   Inspect bounded metadata and policies only, never bucket objects.
4. Review the exact IMPORT request, immutable files, parameters, four identifiers,
   operator/service-role permissions and cost scope. A CreateChangeSet request
   is a cloud mutation and needs separate authorization.
5. Independently inspect the resulting Change Set. Require exactly these four
   Imports with no property changes, resource creation, deletion or replacement.
   CloudFormation import does not prove that properties match live configuration.
6. Obtain separate exact ExecuteChangeSet approval. Require terminal
   `IMPORT_COMPLETE`, then compare both policies and bucket metadata directly.
   Bucket-policy drift detection is unsupported; do not substitute an empty
   drift report for a policy readback.

Stop with **HUMAN_DECISION_REQUIRED** on mismatch or ambiguous ownership.
If failed-stack ownership blocks import, prepare a separate proposal to delete
only the exact failed stack after fresh Original/Retain checks and owner review.
No stack deletion is authorized. Do not use `FORCE_DELETE_STACK`.
`DeleteStack --retain-resources` is documented for `DELETE_FAILED`; it is not
a protection to promise for this `ROLLBACK_COMPLETE` state.
[Retention](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-deletionpolicy.html),
[DeleteStack](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DeleteStack.html).

## Stage B: separate UPDATE for corrected policy and stopped trail

Only after Stage A is independently confirmed may the full corrected template
be reviewed against that exact recovery stack.

Use the [UPDATE parameters](../../bootstrap/gug274-checksum-custody-recovery-update.parameters.json).
Names and role bindings remain unchanged. `TemplateDigest` becomes the
corrected full-template SHA-256 `f785…`; this changes the
`template_sha256` tag on both retained buckets. The import-stage tag recorded
historical source provenance; the UPDATE-stage tag records target-template
provenance. Review these two tag changes explicitly.

The intended semantic difference is:

| Resource | Intended difference |
| --- | --- |
| ReportBucket | template_sha256 tag only; no replacement |
| AuditBucket | template_sha256 tag only; no replacement |
| ReportBucketPolicy | None |
| AuditBucketPolicy | Only the two approved account-prefix statements and Deny Sid |
| CustodyTrail | Add the previously absent trail, stopped, exact single-region selector |

A service may report an unchanged policy as Modify because the template's
parameter values changed. Require a semantic comparison of resolved properties;
do not approve an unexplained policy change. Reject replacement, deletion,
new actor grants, logging activation or other expanded scope.

Creating and executing this UPDATE Change Set each require their own reviewed
request and approval. No execution command is included in this local package.
After a future authorized execution, independently verify:

- terminal `UPDATE_COMPLETE` and exact stack/Change Set identity;
- exact bucket metadata, tags and both policies;
- exact trail exists with `IsLogging: false`, log validation enabled,
  single-region/non-organization scope and the expected S3 data-write selector;
- no IAM expansion or unexpected resource difference.

A stopped trail proves neither delivery nor custody. A failed repair must stop
without policy experimentation or automatic retry.

## Local checks and rollback

Focused tests check the corrected policy boundaries, unchanged retained
resource fingerprints, identifier/input bindings and separate import/update
semantics. They neither execute AWS nor prove effective IAM, import eligibility,
CreateTrail acceptance, log delivery or production readiness.

Reconcile the tracked diff and each prepared file before publication.
Only local source changes are reversible through repository review.
Reverting a later PR does not undo a cloud import, policy update or retained
resources. Every later rollback needs its own exact review. Never delete
buckets, versions, policies, the historical candidate or the consumed marker
as automatic cleanup.

No new cloud action, object read/upload, logging activation, paid Batch job,
authority installation or production deployment was performed by this local
repair. The earlier USD1 operational allowance applied to the single failed
execution; it is not a hard AWS cap or a reusable recovery authorization.

## Remaining production gates

Preserve native receipt v1 and the Batch `NOT_CONFIGURED` stop. GUG-431
remains staging-only and GUG-432 authority-non-production. Later work still
requires a real producer/digest verifier and receipt integration, canonical
artifact acceptance, reviewed authority installation, application deployment,
public DNS/HTTPS, identity and an authenticated synthetic journey.
The [custody design](gug274-checksum-custody-design.md) retains those distinct
activation, canary, identity and cost reviews.
