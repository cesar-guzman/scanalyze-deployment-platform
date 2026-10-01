# GUG-274 dedicated checksum custody design

Status: **LOCAL DESIGN / NOT PROVISIONED / CAPTURE DISABLED**.

Owner-selected scope: account `042360977644`, Region `us-east-1`. This is
artifact-authority preparation, not application production deployment. No
resource availability, effective permission, service delivery or historical
producer identity has been verified by this design.

## Problem and decision

An AWS Signer output may have CRC64NVME/FULL_OBJECT metadata without native
SHA256. S3 Batch Compute checksum is a possible independent SHA256 source, but
a matching report does not authenticate its writer. The collector continues
to reject this route before provider access; native receipt v1 is unchanged.

The owner's supplied metadata for the Control Tower organization trail shows
logging enabled, one basic selector, no advanced selectors and no S3 object
data resources. That returned configuration does not capture S3 object data
events. It says nothing about other trails, historical configurations or
cryptographic validation of delivered logs. This design leaves that baseline
under its owning account's management.

Prepare a separate member-account destination and a prospective write-event
trail. The template is
[`cfn-platform-authority-gug274-checksum-custody.yaml`](../../bootstrap/cfn-platform-authority-gug274-checksum-custody.yaml).
It deliberately hardcodes `IsLogging: false`; it has no activation parameter.
Provisioning and capture activation require separate reviewed actions.

## Proposed resource boundary

These names are proposals, not existing-resource claims. Global S3 name
availability and stack-name ownership remain unverified.

| Resource | Proposed name / boundary | Purpose |
|---|---|---|
| Report bucket | `scanalyze-gug274-checksum-reports-042360977644-us-east-1` | Manual input manifests and Batch completion outputs |
| Audit bucket | `scanalyze-gug274-checksum-audit-042360977644-us-east-1` | Dedicated trail logs and signed digests |
| Trail | `scanalyze-gug274-checksum-custody` | Single Region, member account, report-prefix write data events only |
| Manifest prefix | `scanalyze/platform-authority/gug-274/checksum/manifests/` | Separately approved manifest writer |
| Report prefix | `scanalyze/platform-authority/gug-274/checksum/reports/` | Separately approved Batch writer |
| Audit prefix | `scanalyze/platform-authority/gug-274/checksum/audit/` | Only direct delivery by the dedicated CloudTrail service |

The local template creates exactly two buckets, two bucket policies and one
trail. Account/Region assertions and fixed allowed names prevent an accidental
retarget. A required `TemplateDigest` records the reviewed file digest; a
supplied digest alone does not establish provenance. Two required writer-role
ARNs are policy comparison inputs, not grants or proof of effective access.
The roles must be distinct. A separate
[local dedicated-role proposal](gug274-checksum-role-proposal.md) provides
names and permission boundaries. The owner selected the shared human entry
ARN, including its assigned group, in the linked ManifestOnly review packet;
deployed writer identities, effective access and session controls remain
unverified. Distinct names do not prove independent trust.

Both buckets use versioning, BucketOwnerEnforced ownership, all public-access
blocks and default SSE-S3/AES256. Explicit non-AES256 writes and SSE-C are
denied; a missing encryption header uses the AES256 default. Manually created
CSV manifests and Batch completion reports have encryption constraints that
motivate this separate destination. The existing KMS artifact bucket and key
remain unchanged. [S3 Batch manifest/report constraints](https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops-create-job.html)

CloudTrail can deliver logs and digests with SSE-S3. The audit policy permits
its service principal to check the bucket ACL and write only the account/Region
log and digest paths, bound to the new trail's exact SourceArn. Owner-full-control
delivery remains compatible with BucketOwnerEnforced. Direct IAM writers,
wrong/absent service context and wrong/absent SourceArn are denied separately.
The HTTPS deny applies to non-service identities; direct service calls are
exempt from that condition because AWS can redact transport context. The
separate service, SourceArn and prefix restrictions still apply. These contexts
require a delivery canary after provisioning.
[CloudTrail bucket policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html),
[service-principal context](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principalservicename),
[CloudTrail encryption](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html)

The transport condition follows the documented service-call exception.
[S3 network-condition policy guidance](https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html#example-bucket-policies-tls-version)

The report policy denies writes outside the two prefixes and denies each
prefix's writes by any principal other than its approved role. It supplies no
Allow for either role: source-owned identity policies must later supply the
reviewed permissions. The audit policy grants only the CloudTrail delivery
actions. Neither policy grants authority installation or artifact acceptance.

## Event selection and retention limits

The advanced selector is the conjunction of `eventCategory=Data`,
`resources.type=AWS::S3::Object`, `readOnly=false` and an ARN prefix for this
report bucket's exact `checksum/reports/` namespace. It does not filter to
`PutObject`: multipart completion and other write operations must remain
observable. It captures no reads, manifests, artifact objects, management
events, organization events, Insights or CloudWatch Logs delivery.
[CloudTrail S3 data-event selection](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)

Buckets and the trail are retained on stack deletion/replacement. Object and
object-version deletion is denied. There is no lifecycle expiry, cleanup
automation, Object Lock or claim of WORM retention. Versioning, Retain and
delete denies reduce accidental loss; an authorized administrator can change
configuration, and lifecycle expiration is not prevented by a bucket policy.
No fixed regulatory retention period is asserted. A retention requirement,
operational owner and ongoing storage budget must be settled before activation.
[S3 lifecycle and bucket policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-and-other-bucket-config.html),
[bucket-policy owner limits](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html)

## Permission work still required

No IAM role, trust policy, permission set, assignment, KMS grant or PassRole
binding is created here. The following are proposed capabilities for a later
least-privilege review, not deployable permission policies:

| Identity / service | Intended capability | Required restriction |
|---|---|---|
| Manifest writer | Write the reviewed input CSV and observe its exact version | Only `manifests/`; no report/audit writes or deletion |
| Batch writer role | Read the exact manifest/source version, compute the checksum, write completion outputs | Only the approved artifact version and report job namespace; exact KMS decrypt scope if needed |
| Batch job operator | Create/describe the approved one-object checksum job; pass its role | Account/Region, exact role, separately confirmed PassRole context and guarded reviewed request; no grant here |
| Metadata reader | Inspect dedicated buckets, policies, versioning, trail status/selectors and job metadata | Exact resources and bounded projections; no content/log reads by default |
| Future custody verifier | Read exact report/log/digest versions and regional validation keys | Bounded separately reviewed reads, in-memory processing and sanitized evidence only |
| Change Set operator | Prepare/apply this reviewed stack; later separately enable capture | Exact account/Region/stack/template/parameters; no existing Control Tower or artifact mutation |

Resolve the identities through their actual source of truth. Do not edit an
AWSReservedSSO role directly, replace an unknown permission-set inline policy,
or broaden a shared permission set to make a canary pass. Batch role trust,
source-account protections, permissions and PassRole conditions must use
documented supported request contexts; this design invents none. The separate
roles proposal prepares new task roles without changing these five custody
resources or granting operator access.
[S3 Batch role permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops-iam-role-policies.html)

## Reviewed activation sequence

Each cloud mutation below needs its exact request and environment reviewed and
authorized. This document is not that authorization.

1. Assign the checksum iteration its own issue; reconcile the isolated branch,
   reviewed source and exact file digest. Review writer-role ownership,
   separation, effective policies, retention and cost. Verify name availability
   through separately approved reads.
2. Follow the [roles proposal's staged sequence](gug274-checksum-role-proposal.md#inputs-provisioning-order-and-stop-conditions):
   review and separately provision `ManifestOnly` first. Its write policy can
   reference the proposed report bucket before that bucket exists. Bind its
   actual ARN and the proposed Batch role ARN in this custody template; these
   Deny-only bindings do not create or grant access to a future role.
   With an explicitly selected profile, pass STS for `042360977644/us-east-1`.
   Prepare a Change Set limited to these new resources and policies. Stop on
   name collision, imports, replacements or changes to existing resources.
   Apply only the reviewed Change Set; read back both buckets/policies and the
   disabled trail. The template contains no service role or IAM capabilities.
3. Review a separate source change and Change Set to enable this dedicated
   trail. After explicit approval, verify effective selectors, logging and
   delivery before the first report write. Do not manually toggle logging and
   leave CloudFormation drift. Historical unrecorded writes cannot be backfilled.
4. Prepare and separately approve a synthetic manifest upload. Use its actual
   VersionId and the remaining reviewed bindings to provision `BatchBound`
   in the same roles stack. Review operator access independently; a roles
   stage change grants no CreateJob or PassRole permissions. Prepare a new
   synthetic one-object canary with an exact input version,
   SHA256/FULL_OBJECT operation, AllTasks report and reviewed job namespace.
   Approve its cost, manifest write, job request and role independently. It is
   not the canonical artifact job and cannot produce an installation receipt.
5. Through a separately approved bounded verifier, bind every completion
   manifest/CSV object's exact VersionId to successful authenticated write
   events. Verify the original CloudTrail log hashes, digest signature, chain
   and S3 location. Resolve actual event identity and report dialect from this
   canary. Reject absent or ambiguous evidence rather than relax the policies.
6. Implement/review the real custody verifier and receipt v2 across collector,
   schema, validators, refresh and consumers, with causal negative tests. Keep
   the current Batch contract `NOT_CONFIGURED` until that work is complete.
   A configuration toggle, copied projection or local checksum is insufficient.
7. Review/merge the corrected source and its CI. Build a fresh canonical ZIP
   from that exact source; separately approve its upload, signing and checksum
   job. Preserve the existing e04 artifact, versions and signing job. Collect
   and refresh the private receipt only after the real custody checks pass.
8. Separately review authority installation, identity bootstrap and the
   application deployment. DNS, HTTPS, identity and an authenticated synthetic
   application journey remain required before a production-ready claim.

## Custody verifier acceptance contract

The infrastructure does not implement the verifier. Its required properties
are deliberately stricter than policy/readback consistency:

- Capture demonstrably active before each report write; exact target account,
  Region, bucket, key and VersionId for every report object, including outputs
  created through multipart operations.
- Terminal one-task job counts, exact role/source/manifest/output bindings and
  positive evidence of the intended AWS Batch service producer. A role ARN,
  sessionIssuer, object owner or optional invokedBy field alone is insufficient.
  The real canary must establish supported positive identity/version evidence;
  if unavailable, stop and review a different method.
- Cryptographically validated digest/log bytes and chain, including original
  locations and log hashes. Delivery timestamps and enabled validation flags
  alone do not validate those bytes. Use the regional public validation key
  according to the documented CloudTrail algorithm.
- Separate report-object versions from the artifact VersionId contained in CSV
  rows. Bind actual report schema/column order; do not guess from row values.
- Keep MD5/ETag as consistency tokens and distinguish native CRC, provider
  SHA256 and the locally recomputed SHA256 of every signed byte.
- Process sensitive audit material only with a reviewed bounded verifier;
  persist no raw logs, sessions, credentials or customer content. A sanitized
  operator projection is review context, never the verifier's authority input.

Missing any property means **HUMAN_DECISION_REQUIRED**. This draft does not
claim a viable real producer-proof implementation until the canary confirms
the required evidence. [CloudTrail custom validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-custom-validation.html),
[CloudTrail identity fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html),
[Batch report format](https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops-examples-reports.html)

## Cost review

Pricing checked against AWS public pages on 2026-09-30; recheck before any job
or activation. USD, excluding taxes, credits and negotiated rates:

- Trail data-event delivery: `write_events / 100000 * $0.10`.
  For example, 1,000 events cost $0.001 for this component only. The selected
  writes can include retries/multipart operations; one report is not one event.
  [CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/)
- A Batch checksum job adds `$0.25/job + $1/million processed objects +
  $0.004/GB processed` in the published us-east-1 example. Manifest generation,
  S3 requests, storage and transfer can add charges. [S3 pricing](https://aws.amazon.com/s3/pricing/)
- Retained report, manifest, audit and digest versions accumulate S3 storage
  costs; source reads may have storage-class-specific costs. There is no
  automatic expiry or total cost ceiling in this template.

Use the published billed units and explicitly review the byte conversion in
the exact job estimate. Agree a finite canary/job count, byte volume, retention
horizon and ongoing budget before approval. No budget resource, alarms or paid job is created by
the local design. Disabled capture does not establish a zero-cost deployment:
provisioning and stored objects have their own effects.

## Validation and rollback

Focused local template tests check scope, policy restrictions, versioning,
retention, encryption, selector bounds and the disabled activation boundary.
They are structural/contract tests, not AWS policy simulation or proof of
service delivery. No AWS template validation, Change Set, deployed readback,
Batch job, digest verification, real CSV fixture or production test is part of
this local iteration.

Before provisioning, rollback means reverting only this isolated local source
change through the reviewed repository process. After any future provisioning,
review a specific rollback request; preserve buckets, trail and evidence.
Stack deletion will retain them, and an activated retained trail can continue
logging and charging. Do not delete the stack as an automatic cost-control or
cleanup step. A reviewed stop-logging/retention plan must precede such cleanup.
Misconfigured delivery can be retried for up to 30 days with charges; a logging
stop alone is not proof that redelivery or billing has ended. Resolve that
condition through a separately reviewed decision while preserving evidence.
[CloudTrail delivery retries](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html)
