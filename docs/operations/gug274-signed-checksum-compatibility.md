# GUG-274 signed checksum compatibility preparation

Status: **local preparation; Batch acceptance NOT_CONFIGURED**. This iteration
does not emit a Batch-derived signed-artifact receipt, configure custody,
create an S3 Batch job, install authority, or deploy the application. The native
SHA256 receipt v1 remains the only accepted handoff.

## Trigger and resulting behavior

AWS Signer can produce a signed ZIP whose native S3 checksum is CRC64NVME with
FULL_OBJECT coverage and no ChecksumSHA256. FULL_OBJECT describes coverage, not
the checksum algorithm. The original collector stops at
`S3_OBJECT_CHECKSUM_MISSING`; a local ZIP hash cannot be presented as native
provider SHA256. Signer's StartSigningJob request has no selector for the signed
output's checksum algorithm.

S3 Batch Compute checksum can calculate SHA256/FULL_OBJECT for an existing
exact object version without copying or re-uploading it. Its completion report
is a separate evidence source. Syntax, job configuration and matching hashes
do not authenticate who wrote a report object. Current IAM/bucket policies,
RoleId, owner, ETag, version history and MD5 cannot by themselves prove
historical producer identity.

The collector now offers the explicit `--signed-checksum-source` selection:

| Selection | Behavior |
|---|---|
| `native-sha256` (default) | Original source/SDK/Signer/S3 verification and closed receipt v1. No automatic fallback. |
| `s3-batch-sha256` | Validates the fixed public preparation contract, then stops before SDK/source/provider collection with `HUMAN_DECISION_REQUIRED:REPORT_PRODUCER_PROVENANCE_UNPROVEN:REPORT_DIALECT_NOT_REVIEWED`. Writes no receipt. |

The public library applies the same gate before accessing supplied clients.
The CLI applies it before importing the authenticated AWS SDK or creating any
client. Unknown selectors fail closed. A JSON flag, operator boolean, local
digest, role name, or self-consistent report cannot enable the route.

## Implemented offline parser

`tooling/platform_authority_bootstrap_batch_checksum.py` performs no I/O and
returns **syntax and content consistency only**, never verified custody or CFN
parameters. Its binding must ultimately come from a reviewed policy and direct
provider reads. It checks:

- Exact account 042360977644/us-east-1, job ARN/ID/role, source version,
  one-task CSV manifest, AllTasks report and terminal counts 1/1/0.
- Separate exact versions for the input manifest, completion manifest and CSV;
  exact job namespace, one referenced success file and one success row.
- Explicit CSV schema; UTF-8/CSV/JSON shape and bounds, duplicate JSON keys,
  non-finite numbers, unknown fields and extra rows rejected.
- SHA256/FULL_OBJECT only; canonical 32-byte base64, coherent 64-digit hex and
  SHA256 of every supplied signed byte. CRC and COMPOSITE are rejected.
- Result ETag equal to the observed signed version's ETag as an opaque token.
  Only HEAD's documented outer ASCII quotes are removed; case, spaces and the
  report token are never heuristically normalized. ETag is not a digest.
- Report CSV MD5 only for consistency with the completion manifest. MD5 is not
  an artifact-integrity or producer-authentication substitute.

Both currently supported column orders are **synthetic syntax dialects**.
AWS's published ReportSchema orders ErrorCode before HTTPStatusCode, while its
Compute checksum example shows `succeeded,200,,...`. The collector enables
neither interpretation until a real, reviewed fixture resolves the discrepancy.
It never guesses column order from the contents.

## Source contract and future v2 boundary

The fixed public file
`bootstrap/platform-authority-bootstrap-checksum-evidence-contract.json` is a
versioned preparation contract, not receipt v2. It records NOT_CONFIGURED, null
producer verifier/dialect and the two blocking requirements. Its closed schema
and semantic validator reject activation, unknown fields and type lookalikes.
The parser and contract belong to the package's exact source-provenance paths;
changing them invalidates the reviewed-source package boundary.

**Receipt v2 has not been enabled or implemented.** A subsequent reviewed
implementation must version the collector, closed schema, semantic validator,
refresh and every consumer together. It must keep these separate:

| Evidence block | Required content |
|---|---|
| Native metadata | Actual HEAD/GET algorithm, coverage and values; CRC stays identified as CRC. |
| Provider SHA256 | Authenticated Batch report SHA256/FULL_OBJECT and exact signed version, job, role, manifest and report bindings. |
| Local bytes | Bound size and SHA256 of the exact signed ZIP; equal to the provider SHA256. |
| Custody | Source-owned real producer verifier and authenticated evidence for every report version; no operator-authenticated booleans. |

Preserve unsigned native SHA256 and canonical-byte equality; exact signing
profile/version, job/source/destination, expiry/revocation, source/CI, SDK pins,
private identity custody, expected owner, encryption, unique version history,
no delete markers, bounded reads and freshness. Signed payload entries must
match the canonical package and include the expected Signer metadata suffix.
Metadata presence does not verify the cryptographic signature; Lambda's later
CodeSigningConfig Enforce deployment check remains a distinct gate.

The receipt digest must cover all evidence under a new v2 domain. Refresh must
re-read the actual job, object versions, histories and producer proof, rather
than trust stored CSV bytes or rehash local facts. Existing v1 fixtures and
consumers must preserve their original meaning. No checksum is synthesized in
the native `ChecksumSHA256` field.

## Decisions and work still required

1. Assign this iteration a separately authorized Linear issue; preserve the
   existing GUG-432 branch, PR129 and exact-source artifact packet.
2. Select and review the report-producer evidence method. A possible method is
   S3 write data events authenticated by existing CloudTrail log digests and
   chain validation, matching the exact report VersionIds and positively
   identifying the service. The owner's returned organization-trail settings
   select no S3 object data resources; historical report custody remains
   unverified. The separately authorized
   [dedicated account-42 custody design](gug274-checksum-custody-design.md)
   proposes new resources with capture disabled, not existing producer proof.
   A role session alone is insufficient. Any sensitive log processing requires
   a separately approved, bounded in-memory verifier; this implementation does
   not read logs or accept operator-supplied event projections as authority.
3. Obtain and review the actual report dialect, then implement the real
   custody/collector/receipt v2 path and focused causal negative tests. Merely
   changing NOT_CONFIGURED to CONFIGURED_REVIEWED is deliberately rejected.
4. Review the exact report destination and role permissions. Manual CSV
   manifests do not support SSE-KMS, and completion reports use SSE-S3. Use a
   separately reviewed custody destination; do not relax the KMS artifact
   bucket to accommodate reports. The linked local design proposes separate
   buckets; effective writer roles, provisioning and activation remain pending.
5. Review/merge corrected source and verify its CI before rebuilding the
   canonical ZIP. Upload, sign and checksum calculation each need separate
   exact reviewed requests. Preserve all existing versions/jobs; do not label
   an old artifact as a new reviewed source.
6. Collect and refresh the original private receipt only after custody
   approval. Then review the authority installation Change Set and exact
   installation command. Identity bootstrap, backend authority and production
   runtime are distinct later steps; HTTPS, identity and the authenticated
   application journey remain required production evidence.

The wrapper cannot correct an immutable e04 source packet. No old candidate,
version, job, retained resource or historical attempt should be deleted, reset,
re-signed or adopted automatically. Roll back this local preparation by
reverting its isolated source changes through the reviewed repository process.
The parser/collector preparation itself has no cloud effects. The separate
[ManifestOnly role review packet](gug274-checksum-manifestonly-change-set-review.md)
records the authorized Change Set and stack review record that now exist;
their cleanup requires its own reviewed exact-target request. No IAM role or
custody resource was provisioned by that request.

## Primary references

- [Signer StartSigningJob request](https://docs.aws.amazon.com/signer/latest/api/API_StartSigningJob.html)
- [Compute checksum at rest](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-at-rest.html)
- [Completion report format and examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops-examples-reports.html)
- [Terminal job states and completion reports](https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops-job-status.html)
- [Manifest/report encryption constraints](https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops-create-job.html)
- [Batch role permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops-iam-role-policies.html)
- [CloudTrail S3 events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)
- [Custom CloudTrail log/digest validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-custom-validation.html)
- [Lambda code signing](https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html)
