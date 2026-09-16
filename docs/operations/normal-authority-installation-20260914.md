# Normal authority installation — 2026-09-14

**The coordinator created and read back the GUG-274 AWS Signer profile, the
separate release-VSA KMS key, an account instance of IAM Identity Center and its
DISABLED custom OAuth application
in `042360977644/us-east-1`. The local candidate now
pins the actual Signer version; the authority service and backend are not yet
installed.** The owner authorized the necessary creation work. The coordinator
owns identity verification and cloud effects; this subtask changed local source,
tests and documentation and independently checked the saved public metadata.
No installation, release signature or production-readiness claim follows from
these foundation resource creations.

**PKCE launcher status: `OFFLINE_VALIDATED_PROVIDER_BLOCKED`.** The real custom
application rejected the attempted authorization-code grant. Its locally tested
callback and source-custody controls do not make that provider configuration
viable; the application remains DISABLED and the execution procedure is suspended.

The separate release-VSA trust root is one P-256 KMS signing key. Its concrete
creation request and completed readback are recorded below. It does not replace the Lambda Signer
profile, and neither signing resource by itself installs the backend or grants
deployment authority.

## Exact local packet

The private, owner-only review directory is:

`/private/tmp/scanalyze-normal-authority-review-5jneu3jb`

It contains these concrete candidates:

| File | Purpose and current status |
| --- | --- |
| `signer-put-request.json` | Exact canonical profile name/platform, 12-month signature validity and three installation tags; created by coordinator and matched to readback |
| `signer-read-request.json` | Exact canonical profile and owner account for before/after readback |
| `signer-put-response.json`, `signer-readback.json` | Actual version `fo5PB1XOji`; Active status and exact creation fields verified locally |
| `signer-installer-policy-candidate.json` | Proposed bounded creation/read/tag permissions; not installed or effectively simulated |
| `bootstrap-approval-policy.json` | Successfully rendered by the real isolated normal CLI for authority 042, Region us-east-1 and owner-confirmed destination 905418363887 |
| `release-vsa-create-key-request.json` | Exact P-256 signing-key create request; created by coordinator; key policy grants administration/public-key reads only |
| `release-vsa-key-policy-candidate.json` | Readable copy of the proposed initial key policy; no signing grant |
| `release-vsa-create-key-response.json`, `release-vsa-key-readback.json`, `release-vsa-public-key.json`, `release-vsa-key-policy-readback.json` | Actual key metadata/public SPKI and exact policy readback; no private key material |
| `source/` and `public-source-inventory.json` | Fourteen public-source snapshots taken before this Signer pin change, with measured local hashes; integrity inventory only, not the final source commit |
| `sdk-runtime-path.txt` | Path of the separately authenticated private SDK runtime described below |
| `identity-instance-readback.json` | Actual account instance: ACTIVE, owner 042 and expected name; NoEcho-compatible technical identifiers remain private |
| `identity-application-stage1/` | Reviewed local requests for exact provider lookup, application collision lookup and creation of a DISABLED app; no grant, callback or user assignment emitted |
| `identity-application-stage2/` | Assignment-required readback is already true; proposed `sts:identity_context` access-scope Put/Get withdrawn after live preflight rejection; no stage-2 mutations |
| `identity-application-stage3/` | Exact grant request attempted once by coordinator: CLI exit 254; matching CloudTrail event reports `ValidationException: Grant type: authorization_code not supported`. Subsequent `Grants=[]`, app still DISABLED; no retry. Contains PKCE binding and before/after custody records; no token/login material |

Directories are mode 0700 and files 0600. This review packet is **not** the
protected GUG-274 Lambda package, a signed artifact, an approval, or publication
evidence. No service ZIP was emitted. Its source HEAD is
`16dec52b2522e80f2a85ad9551ee3a0cdafbb4a8`; the shared implementation worktree is
dirty and has not been relabeled as a clean reviewed release. The temporary
packet must be retained under controlled custody if needed after this session.

## Step 1: establish the bootstrap code-signing root

The fixed [trust contract](../../bootstrap/platform-authority-bootstrap-artifact-signing-trust-root.json)
already supplies the intended resource name and algorithm:

```json
{
  "profileName": "scanalyze_gug274_bootstrap_artifact_authority",
  "platformId": "AWSLambda-SHA384-ECDSA",
  "signatureValidityPeriod": {"value": 12, "type": "MONTHS"},
  "tags": {
    "managed_by": "scanalyze-reviewed-installation",
    "service": "scanalyze-platform-authority",
    "work_package": "GUG-274"
  }
}
```

The 12-month period was an explicit installation setting, patterned on
the repository's artifact foundation, and now matches the actual readback. It
is not an immutable field fixed by the GUG-274 verifier. AWS Signer manages the Lambda
signing material for this platform. Creating this profile requires no Terraform
state backend, release-VSA key, deployment target or running Plan/Approval/Apply
Lambda. That makes it the first useful creation that can precede the locked
service deployment. [AWS profile creation](https://docs.aws.amazon.com/signer/latest/developerguide/signing-profiles.html)
and [PutSigningProfile](https://docs.aws.amazon.com/signer/latest/api/API_PutSigningProfile.html)
define this API and its returned version.

**The following create sequence is historical: the coordinator completed it.
Do not rerun PutSigningProfile for this installation.** The actual version ARN is
`arn:aws:signer:us-east-1:042360977644:/signing-profiles/scanalyze_gug274_bootstrap_artifact_authority/fo5PB1XOji`.
The locally inspected response and readback agree on version and ARN; readback
also matches the exact name, platform, Active status, period and tags.

For a separately reviewed future installation, bind `SCANALYZE_SIGNER_INSTALLER_PROFILE` to the explicitly
reviewed installation session and check STS account 042 before the following
commands. The candidate friendly name
`042360977644_ScanalyzePlatformAuthorityBootstrap` currently resolves to
AdministratorAccess; it is **not** the canonical normal Apply identity. It must
never be substituted into the protected normal CLI. Root-trust creation is a
separate reviewed installation effect, not execution through that CLI.

Read the exact profile immediately before creation. Proceed only on an
authenticated `ResourceNotFoundException`; access denial, network failure or an
existing profile requires reconciliation. The earlier empty list is context,
not action-time proof of absence.

```bash
: "${SCANALYZE_SIGNER_INSTALLER_PROFILE:?reviewed installation session required}"
aws --profile "$SCANALYZE_SIGNER_INSTALLER_PROFILE" --region us-east-1 \
  sts get-caller-identity
aws --profile "$SCANALYZE_SIGNER_INSTALLER_PROFILE" --region us-east-1 \
  signer get-signing-profile \
  --cli-input-json file:///private/tmp/scanalyze-normal-authority-review-5jneu3jb/signer-read-request.json
```

The reviewed write is one request. Run it once after the preceding result and
identity have been checked; preserve the private response with no-clobber
semantics. No caller-generated version, speculative ARN suffix or request hash
can replace the service response.

```bash
umask 077
set -o noclobber
AWS_MAX_ATTEMPTS=1 aws --profile "$SCANALYZE_SIGNER_INSTALLER_PROFILE" \
  --region us-east-1 signer put-signing-profile \
  --cli-input-json file:///private/tmp/scanalyze-normal-authority-review-5jneu3jb/signer-put-request.json \
  --output json \
  > /private/tmp/scanalyze-normal-authority-review-5jneu3jb/signer-put-response.json
```

Then repeat the exact `get-signing-profile`, preserving its response privately.
Require the profile name, owner ARN, platform, Active status, signature period,
tags and `profileVersion`/`profileVersionArn` to agree with the single creation
response. AWS supplies a ten-character alphanumeric version. A timeout or
ambiguous result is a stop: this API has no request idempotency token or CAS
condition in its documented input, so do not repeat the creation blindly.
[GetSigningProfile](https://docs.aws.amazon.com/signer/latest/api/API_GetSigningProfile.html)
provides the required metadata and current version.

The candidate creator IAM permission is `signer:PutSigningProfile` on `*`,
restricted by `aws:PrincipalAccount=042360977644`, `aws:RequestedRegion=us-east-1`
and the exact request tags. AWS does **not** expose resource-level authorization
or a profile-name/platform condition for this creation action. The exact request
and controlled single operation therefore remain part of the authority boundary;
the policy alone cannot limit creation to that name. The packet separately
scopes `GetSigningProfile`, `ListTagsForResource` and the tag permission to
`arn:aws:signer:us-east-1:042360977644:/signing-profiles/scanalyze_gug274_bootstrap_artifact_authority`.
No `StartSigningJob`, profile permission, revocation or cancellation is included.
This limitation follows the current
[Signer authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_signer.html).
Attaching this Allow policy to an already administrative role would not reduce
that role's effective permissions.

## Step 2: pin, build, sign and install the existing normal authority

The local change updates only the trust contract, template pin fields and their
existing test file. The contract now records `CONFIGURED_REVIEWED`, exact version
`fo5PB1XOji` and its AWS-returned ARN. Its domain-separated contract digest is
`sha256:2909fb75ecb695b9891062ac4dafcba664128658d2351690557e0708c2de4bef`.
The
[CFN template](../../bootstrap/cfn-platform-authority-bootstrap-artifact-authority.yaml)
requires exact closed allowlists for that version and the domain-separated
contract digest before its activation lock changes. Do not remove the Rule,
accept arbitrary strings, change signing enforcement to Warn, or generate the
version locally. `activation_authorized=false` and `production_status=NO-GO`
remain fixed evidence labels in the current signer contract/verifier; they are
not flags to flip as a shortcut.

Both CFN allowlists contain only the actual version and that contract digest.
`AuthoritySigningTrustRootConfigured` is locked to `true`, including its default:
the existing receipt-to-parameter producer omits that parameter, so leaving a
false default would make the real deployment input inadmissible. The Rule and
`Enforce` policy remain intact. The existing template description mentions a
non-production installation; this is historical scope text, not a reason to
relabel the source's fixed evidence fields. Backend installation in the
authority account remains distinct from activating production workloads.

The intended service installation reuses the existing template's **17 declared
resources**: one enforced CodeSigningConfig, three log groups, three identity
proof roles, three execution roles, one CAS table, three functions and three
published versions. The immutable service interfaces are:

| Function, always version `:1` | Execution role | Separate identity proof role |
| --- | --- | --- |
| `scanalyze-platform-authority-bootstrap-plan-authority` | `ScanalyzeGug274BootstrapPlanAuthority` | `ScanalyzeGug274BootstrapPlanIdentityProof` |
| `scanalyze-platform-authority-bootstrap-approval-authority` | `ScanalyzeGug274BootstrapApprovalAuthority` | `ScanalyzeGug274BootstrapApprovalIdentityProof` |
| `scanalyze-platform-authority-bootstrap-apply-executor` | `ScanalyzeGug274BootstrapApplyExecutor` | `ScanalyzeGug274BootstrapApplyIdentityProof` |

The table is `scanalyze-platform-authority-bootstrap-artifacts`, keyed by
`trust_root_id` and `authority_record_id`; generation 1 fixes the partition to
the exact table ARN plus `#generation/1`. Installation must preserve its deny-only
resource policy, per-service SourceFunctionArn conditions and exact versioned
invocation. This is not the deployment registry installed later by Terraform.

Build from a clean, exact reviewed commit using the existing producer:

```bash
: "${SCANALYZE_REVIEWED_SOURCE_COMMIT:?exact reviewed clean commit required}"
env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap-artifact-package.py \
  --source-commit "$SCANALYZE_REVIEWED_SOURCE_COMMIT" \
  --expected-boto3-version 1.42.57 --expected-botocore-version 1.42.97 \
  --output-directory /private/tmp/scanalyze-normal-authority-review-5jneu3jb/canonical-unsigned-package
```

The initial invocation from the shared candidate stopped at `SOURCE_TREE_DIRTY`
and created no output directory. The next admissible step is the coordinator's
reviewed selective commit and a clean worktree of that exact commit. Do not create
a synthetic Git commit or alternate packager to bypass provenance. Signing must
then use the reviewed profile version, exact versioned unsigned object and
approved versioned destination. Source keys are fixed to
`scanalyze/platform-authority/gug-274/unsigned/<reviewed-commit>/scanalyze-gug274-bootstrap-artifact-authority.zip`;
signed keys are `scanalyze/platform-authority/gug-274/signed/<real-job-uuid>.zip`.
No actual artifact bucket, object version or job ID is established by this packet.
The GUG-376 foundation template cannot be submitted as a GUG-274 substitute: it
has different profile names, bucket constraints, prefixes and cross-account lane.

The existing read-only collector is the next exact entrypoint after signing:

```bash
: "${SCANALYZE_SIGNING_JOB_ID:?actual completed Signer job required}"
: "${SCANALYZE_GUG274_SDK_RUNTIME_ROOT:?approved external runtime closure required}"
export SCANALYZE_GUG274_SDK_RUNTIME_ROOT
env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap-signed-artifact.py \
  --profile 042360977644_ReadOnlyAccess --region us-east-1 \
  --source-commit "$SCANALYZE_REVIEWED_SOURCE_COMMIT" \
  --expected-boto3-version 1.42.57 --expected-botocore-version 1.42.97 \
  --job-id "$SCANALYZE_SIGNING_JOB_ID" \
  --output-receipt /private/tmp/scanalyze-normal-authority-review-5jneu3jb/signed-authority-receipt.json
```

That **exact local profile string** is currently source-enforced, while the STS
role must match `AWSReservedSSO_AWSReadOnlyAccess_<16-hex>`. The inventory's
`042360977644_AWSReadOnlyAccess` spelling cannot silently replace it. Configure a
proper reviewed alias to the same canonical permission set if needed; do not
alias AdministratorAccess to it. No alias was configured here. The collector
also requires the commit merged to protected main, required checks green,
trusted host executables, pinned external SDK closure and live source/destination
readbacks. Its receipt lasts at most 15 minutes and must be refreshed from the
same authorities immediately before CFN parameter consumption.

A concrete CFN invocation is intentionally not emitted with fake values for the
missing identity application/instance/store, private user-A/user-B IDs,
redirect URI, signed S3 tuple or hashes. These are actual required template
parameters. User A and user B must differ according to both the current template
Rule and `BootstrapIdentityProofBinding`; CODEOWNERS review does not synthesize
that runtime evidence. The canonical source already implements the services;
what is missing is their real configuration and authorized installation.

### Submit rendered JSON, with valid transaction denies

The coordinator's actual AWS `ValidateTemplate` rejected the YAML source with
`Template error: YAML aliases are not allowed in CloudFormation templates`.
Do not submit that YAML directly. The local
[renderer](../../scripts/deployment/render-bootstrap-authority-template.py)
loads only the fixed GUG-274 template, requires its independently reviewed byte
digest, rejects duplicate keys and unrecognized intrinsic tags, expands aliases
and writes deterministic JSON with full `Fn::` names. Its output directory must
be canonical, caller-owned and private; an existing output cannot be overwritten.
It prints the measured JSON digest, with status `LOCAL_RENDER_ONLY`.

The current reviewed candidate values, before any subsequent source edit, are:

- YAML source SHA-256: `70916cdd8300626ea4d61bea62c24dcd644d55bdff77029e0378dd42d36dea72`.
- Rendered JSON SHA-256: `bbbdaff8ccd18c7cc40e965a797767e87a9d6987883ad6f774e99ca492dbff12`.
- Existing private output: `/private/tmp/scanalyze-normal-authority-review-5jneu3jb/cfn-bootstrap-authority.rendered.json`.

To render another copy for review, select a **new** output path in an existing
private directory and run from the reviewed worktree:

```bash
: "${SCANALYZE_AUTHORITY_TEMPLATE_JSON:?new private output file required}"
python3 -I scripts/deployment/render-bootstrap-authority-template.py \
  --expected-source-sha256 70916cdd8300626ea4d61bea62c24dcd644d55bdff77029e0378dd42d36dea72 \
  --output "$SCANALYZE_AUTHORITY_TEMPLATE_JSON"
```

Use these exact JSON bytes for subsequent AWS validation and reviewed change-set
preparation. Any source edit requires new review of its source and rendered
digests; computing a hash of an incoming file alone does not grant authority.
The JSON transform does not mint a signing receipt, extend its 15-minute lifetime
or bypass the eventual parameter and source-commit gates.

The coordinator subsequently verified this JSON with AWS `ValidateTemplate`
(exit 0). Its `cfn-lint 1.56.3` run reported no errors, no alias warning W1101
and no invalid-action warning W3037. Eight W3005 warnings remain for redundant
`DependsOn` entries (exit 4); no rule was ignored. Validation is not stack
creation or service installation.

The same review found `dynamodb:TransactGetItems` and
`dynamodb:TransactWriteItems` in IAM Action fields. These name APIs, not valid IAM
actions. Both the table resource policy and Apply executor now explicitly deny
the five underlying item actions when `dynamodb:EnclosingOperation` contains
either transaction name, using `ForAnyValue:StringEquals`. Existing unconditional
denies and all Allows remain unchanged, including the nontransactional
`Null: dynamodb:EnclosingOperation=true` condition. This follows AWS's
[transaction IAM model](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis-iam.html).
Fifteen policy-context cases failed before the fix and passed afterwards;
single-item create-only/read/CAS adapter behavior remains covered by its real
local test. These checks are not a live IAM simulation.

## Concrete identity installation for the 17-resource stack

The current template declares **28 parameters, including six NoEcho identity
parameters**. Post-merge of `#117` (`6e08a144`), the public surface also includes
`IdentityGrantVersion`, `OperatorPolicyMode`, `SingleOwnerAuthorizedAt`,
`SingleOwnerExpiresAt`, `JwtTrustedTokenIssuerArn`, `JwtIssuerUrl`, and
`JwtAudience`. Searching the public bootstrap templates, IAM policies and
deployment/operations documentation still finds no installable concrete GUG-274
JWT trusted-issuer ARN, audience, or owner UserId values for activation.
Fixtures and synthetic examples were excluded as authority sources. The GUG-376
application contract is a different management-account, single-operator
application with different actors; it cannot supply the normal GUG-274 binding.
For César's reviewed `single_owner_v1` path, see
`docs/deployment/gug274-jwt-bearer-operator.md` and the offline placeholder draft
`docs/deployment/gug274-single-owner-cfn-parameters-offline-draft.md` (placeholders
only; no invented UserIds/TTI).

The initial STS-verified management and 042 discovery reads showed only the
organization instance owned by `839393571433`. The coordinator subsequently
created the separate 042 account instance and verified it ACTIVE with name
`ScanalyzeGug274Authority`, owner 042 and creation time
`2026-09-14T05:59:26.367Z`. Its actual ARN uses the already supported `ssoins-`
prefix. This subtask independently compared the saved technical readback with
the coordinator's returned ARN, owner, name and status without displaying the
store ID. No user or application existed in the new instance at that readback.
The actual identity ARNs remain private, and no user attributes were requested.

| Exact CFN parameter | Source required and current disposition |
| --- | --- |
| `IdentityCenterApplicationArn` | Coordinator created the exact reviewed v2 application and matched DescribeApplication/Tags readbacks: DISABLED, owner 042, exact instance/provider/name. Preserve ARN privately. |
| `IdentityCenterInstanceArn` | Coordinator's new account-instance create response and exact ACTIVE/owner-042 DescribeInstance readback. The separate organization instance still supplies AWS-account permission sets. Preserve ARN privately. |
| `IdentityStoreArn` | Actual application metadata when available, corroborated by the instance's `IdentityStoreId` and `OwnerAccountId`. Never prepend 042 to an unverified store ID. Preserve privately. |
| `IdentityRedirectUri` | Operation explicitly selects `http://127.0.0.1:38271/callback`; the local receiver accepts only this URI. The single stage-3 Put attempt failed at the CLI and no grant was observed afterward, so this URI is not verified as installed configuration. |
| `PlanIdentityStoreUserId` | Directory administrator's independently approved opaque ID for the real owner (human A / César in `single_owner_v1`) in that exact store; no username/email search by this agent. Exact private application/account assignment readbacks corroborate access. Never invent or paste a UserId into Git. |
| `SecondPartyIdentityStoreUserId` | **independent mode:** independently approved opaque ID for a different real human B in the same store; B performs Approval and Apply with separate roles and fresh grants. A second login or newly created alias for A does not prove B. **`single_owner_v1`:** must be the empty string; CFN Rules + Approval/Apply proof roles bind `PlanIdentityStoreUserId` via `Fn::If`. |
| `IdentityGrantVersion` | `1` (legacy authorization_code path; historically rejected by the custom app) or `2` (JWT/TTI bearer). `single_owner_v1` requires `2`. |
| `OperatorPolicyMode` | `independent` (default) or `single_owner_v1`. Owner-selected sole-operator mode is `single_owner_v1` for authority `042360977644` / destination `905418363887` only after connected acceptance. |
| `SingleOwnerAuthorizedAt` / `SingleOwnerExpiresAt` | Reviewed UTC `YYYY-MM-DDTHH:MM:SSZ` window; empty in independent mode; required and ≤24h in `single_owner_v1`. Do not invent activation timestamps in public drafts. |
| `JwtTrustedTokenIssuerArn` / `JwtIssuerUrl` / `JwtAudience` | Required nonempty under `IdentityGrantVersion=2`; empty under version `1`. App `apl-722313749a62e03b` remains DISABLED with historically empty Grants/TTI — do not enable/create issuer values without reviewed connected acceptance. |
| `AuthorityArtifactBucket`, `AuthorityArtifactKey`, `AuthorityArtifactVersion` | Actual versioned Signer destination from the live signed-artifact receipt; the bucket must agree with the separately installed GUG-274 artifact foundation. Neither a template name nor a local ZIP establishes a VersionId. |
| `SignedAuthorityArtifactCodeSha256`, `AuthoritySigningReceiptDigest` | Real collector output after exact job and versioned S3 byte readbacks; signed ZIP hash and domain-separated receipt digest, with action-time freshness intact. |
| `AuthorityAccountId`, `DestinationAccountIds` | Owner-selected `042360977644` and `905418363887`; verify caller account before stack operations. |
| `BootstrapChangeSetName` | Exact newly reviewed normal backend change-set name, shared by all three functions. The unrelated old July change set is not this binding. |
| `AuthoritySigningTrustRootContractDigest`, `AuthoritySigningProfileName`, `AuthoritySigningProfileVersionId`, `AuthoritySigningTrustRootConfigured` | Fixed reviewed source values recorded above, including actual Signer version and `true` configuration lock. |
| `SourceCommit`, `ExpectedBoto3Version`, `ExpectedBotocoreVersion` | Actual reviewed clean package commit and the unchanged `1.42.57` / `1.42.97` pins; never substitute the current dirty worktree hash. |

### Metadata reads for the coordinator

Run only with an explicitly reviewed profile and `us-east-1`, after STS identity
verification. Keep all six NoEcho values in private request/response files;
emit only compatibility classifications, counts and checked digests in public
reports. Do not use `ListUsers`, `DescribeUser`, user-name/email filters or token
exchange for inventory. `--query` is output projection, not server-side redaction
or a grant to read PII.

| API / exact input selection | Metadata to verify | Minimum action/resource boundary |
| --- | --- | --- |
| `sso-admin ListInstances` (complete pagination) | Visible instance ARNs, owner, store ID, status and Region metadata; select exactly the reviewed instance | `sso:ListInstances`, Resource `*`; region/time-bound discovery |
| `DescribeInstance(InstanceArn)` | Same instance/owner/store ID, ACTIVE; encryption fields only as received | `sso:DescribeInstance` on exact instance ARN |
| `DescribeApplicationProvider(ApplicationProviderArn=arn:aws:sso::aws:applicationProvider/custom)` | Actual provider exists and supports OAUTH | `sso:DescribeApplicationProvider` on that exact AWS provider ARN |
| `ListApplications(InstanceArn, Filter.ApplicationAccount)` (complete pagination) | Candidate app collision/presence in the reviewed account; do not choose the first name match | `sso:ListApplications`, Resource `*`; explicitly restricted discovery session |
| `DescribeApplication(ApplicationArn)` | Exact app account, provider, instance, status, callback portal configuration and, if returned, IdentityStoreArn | `sso:DescribeApplication` on exact app ARN |
| `ListApplicationGrants(ApplicationArn)` (complete pagination) | Current exact-app inventory; post-attempt result is `Grants=[]`. The attempted authorization-code grant was rejected; no Get/Put retry follows from this inventory | `sso:ListApplicationGrants` on exact app |
| `ListApplicationAccessScopes(ApplicationArn, MaxResults=10)` (complete pagination) | Current additional access scopes; observed `Scopes=[]`. The implicit token scope `sts:identity_context` is not a supported Get/Put application-access-scope proposal for this lane | `sso:ListApplicationAccessScopes` on exact app; the earlier `GetApplicationAccessScope(sts:identity_context)` recommendation is withdrawn |
| `GetApplicationAuthenticationMethod(ApplicationArn, AuthenticationMethodType=IAM)` plus `ListApplicationAuthenticationMethods` | One IAM method with the rendered GUG-274 three-service actor policy | Corresponding Get/List actions on exact app |
| `GetApplicationAssignmentConfiguration(ApplicationArn)` | `AssignmentRequired=true` | `sso:GetApplicationAssignmentConfiguration` on exact app |
| `DescribeApplicationAssignment(ApplicationArn, PrincipalType=USER, PrincipalId)` for A and B; complete `ListApplicationAssignments` | Exactly the approved opaque IDs, no group/foreign assignments; no directory attributes | Corresponding Describe/List assignment actions on exact app |
| `ListPermissionSets` / `DescribePermissionSet`; `GetInlinePolicyForPermissionSet`, policy-attachment and boundary lists | Exact canonical normal Plan/Approve/Apply names, inline policy and no substituted administrator policy | Exact organization instance and selected permission-set ARNs; discovery only where AWS requires it |
| `ListAccountAssignments(InstanceArn, AccountId=042360977644, PermissionSetArn)` and provisioning status reads | A has Plan; B has the separate Approve/Apply assignments; provisioning succeeded | Exact account, organization instance and permission-set resources |

The current official [DescribeApplication](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_DescribeApplication.html)
and [CreateApplication](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_CreateApplication.html)
documentation includes `IdentityStoreArn`; the pinned Botocore `1.42.97` service
model does **not** contain that response member. A missing field in that model's
parsed output is not evidence of a missing store. Use a separately reviewed
metadata reader that exposes the received field, or the official ARN format
constructed from the **observed** store owner and store ID with that derivation
explicitly recorded. Do not alter the protected runtime SDK pins for inventory.

Concrete CLI shapes use private files to avoid putting NoEcho inputs into the
command text. These are examples for the coordinator to populate from verified
metadata, not ready-made request authority:

```bash
: "${SCANALYZE_IDENTITY_METADATA_PROFILE:?reviewed identity metadata profile required}"
: "${SCANALYZE_IDENTITY_REQUEST_DIR:?canonical private request directory required}"
aws --profile "$SCANALYZE_IDENTITY_METADATA_PROFILE" --region us-east-1 \
  sts get-caller-identity
aws --profile "$SCANALYZE_IDENTITY_METADATA_PROFILE" --region us-east-1 \
  sso-admin describe-instance \
  --cli-input-json "file://$SCANALYZE_IDENTITY_REQUEST_DIR/describe-instance.json" \
  --query '{InstanceArn:InstanceArn,IdentityStoreId:IdentityStoreId,OwnerAccountId:OwnerAccountId,Status:Status,EncryptionConfigurationDetails:EncryptionConfigurationDetails}' \
  --output json > "$SCANALYZE_IDENTITY_REQUEST_DIR/instance-readback.json"
aws --profile "$SCANALYZE_IDENTITY_METADATA_PROFILE" --region us-east-1 \
  sso-admin describe-application \
  --cli-input-json "file://$SCANALYZE_IDENTITY_REQUEST_DIR/describe-application.json" \
  --query '{ApplicationArn:ApplicationArn,ApplicationAccount:ApplicationAccount,ApplicationProviderArn:ApplicationProviderArn,InstanceArn:InstanceArn,IdentityStoreArn:IdentityStoreArn,Status:Status}' \
  --output json > "$SCANALYZE_IDENTITY_REQUEST_DIR/application-readback.json"
```

Before output creation, use private permissions and no-clobber as in the earlier
steps. A later projected field that the local CLI does not understand must be
reported unavailable, never filled from expectation.

### Account-instance option and exact contract compatibility

Current AWS documentation explicitly supports **OIDC customer-managed
applications in account instances**; an older claim that only AWS-managed apps
are supported is no longer a valid blocker. Account instances have no permission
sets or AWS-account access, use an isolated user population, and cannot be merged
into the organization instance. Their creation requires organization permission,
no blocking SCP, no other instance owned by that account in any Region and a
supported Region. [AWS capability comparison](https://docs.aws.amazon.com/singlesignon/latest/userguide/identity-center-instances.html)
and [account-instance constraints](https://docs.aws.amazon.com/singlesignon/latest/userguide/account-instances-identity-center.html).

The coordinator has now created that empty 042 instance and verified ACTIVE.
Do not repeat `CreateInstance` for this installation. Instance creation also
creates its Identity Store and any required service-linked role; it creates no
users, assignments or human proof. For a future separate installation,
`CreateInstance` accepts `Name`, `ClientToken` and `Tags`: preserve one reviewed
request token and reconcile an ambiguous result before any retry. This subtask
performed no cloud effect.
[CreateInstance](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_CreateInstance.html).

There are two distinct source compatibility questions:

1. The existing binding requires application-account and store-account to equal
   authority account 042. Using an app/store owned by the observed management
   account 839 fails the real constructor with `Identity Center topology is not
   exact`. A synthetic shape probe reproduced this; no actual user ID was read.
2. AWS's current ARN models accept both `ssoins-` and `ins-`; GUG-274's two CFN
   identity ARN patterns and Python constructor accept only `ssoins-`. A synthetic
   `ins-` pair fails with `Identity Center topology is invalid`. If the actual new
   account-instance readback were to use `ins-`, the minimum reviewed compatibility fix
   is to admit the two closed prefixes, compare the **complete prefix plus ID**
   between application and instance, retain both owner checks at 042, and preserve
   all six exact role ARNs and the two-distinct-human gate. Do not normalize away
   a prefix or accept a mixed `ins-`/`ssoins-` pair. The actual new instance uses
   `ssoins-`, so no such change is needed or authorized for this installation.

The alternative is a separately reviewed organizational-topology change: add an
explicit immutable identity owner distinct from the 042 execution account, bind
it to the observed 839-owned application/store/instance, include that field in the
runtime environment and binding digest, and retain exact 042 execution/proof
roles, app actor policy, two real users and STS context conditions. Cross-account
application actor admission must be verified for that exact tuple before use;
this is a proposed contract change, not an already connected path. Do not simply
delete the current account equality checks.

### Application creation and subsequent configuration

The coordinator executed this exact reviewed request from the private packet:

`identity-application-stage1/create-application-request.v2.json`

Its exact byte SHA-256 is
`94885ecd445ba1c234474724cf7e6a5bee1d5707a502fe6182b66995782b2437`.
It binds the ACTIVE instance from the verified saved readback, AWS provider
`arn:aws:sso::aws:applicationProvider/custom`, name
`ScanalyzeGug274Authority`, description
`GUG-274 normal bootstrap identity proof application`, `Status=DISABLED`, one
persisted UUID client token and these four installation tags:
`managed_by=scanalyze-reviewed-installation`,
`service=scanalyze-platform-authority`, `work_package=GUG-274`, and
`purpose=bootstrap-identity-proof`. These are explicit new installation choices,
not fields of an existing GUG-274 application tag contract. The initial unexecuted
request copied `managed_by=identity-center` from the GUG-376 pattern and the
non-production labels used on the separate 17-resource CFN template. It was
superseded before any create call; the v2 request describes the actual installer
and purpose without assigning a workload environment. The original request is
retained for review and **must not execute**. The CFN tags and signer
false/NO-GO fields remain unchanged. This application name is also an explicit
new installation choice. The
optional `PortalOptions` field was omitted because no callback receiver had been
selected at creation time; the later stage-3 URI choice did not invent a grant
to obtain that creation success.

`describe-provider-request.json` and `list-applications-request.json` in the same
directory are the two preceding read shapes. The latter uses the exact instance,
account-042 filter and page size 100; the coordinator must consume any remaining
pages before concluding absence. All three input shapes passed the actual
source-pinned Botocore model without a network client. Their byte hashes and the
source instance-readback hash are recorded in `request-review-manifest.json`;
`request-review-v2.json` records the superseding create request and its changed
tags/token. These inventories are not installation authority.

After exact STS, provider-OAUTH and complete empty collision-inventory review,
the coordinator executed the following creation operation. It is recorded for
reproduction in a new environment, **not for another create in this instance**:

```bash
umask 077
set -o noclobber
AWS_MAX_ATTEMPTS=1 aws \
  --profile 042360977644_ScanalyzePlatformAuthorityBootstrap --region us-east-1 \
  sso-admin create-application \
  --cli-input-json file:///private/tmp/scanalyze-normal-authority-review-5jneu3jb/identity-application-stage1/create-application-request.v2.json \
  --output json \
  > /private/tmp/scanalyze-normal-authority-review-5jneu3jb/identity-application-stage1/create-application-response.json
```

The profile's administrator permissions are used only for this explicitly
reviewed installation effect, never as a replacement for normal Plan/Approve/
Apply identities. Reconcile any uncertain creation with its original request
and token. `DescribeApplication` must return the exact new ARN, instance,
application account 042, custom provider, expected name/description and DISABLED
status; `ListTagsForResource` must match the request. Those checks passed in
`application-readback.v2.json` and `application-tags-readback.v2.json`; their
byte hashes are respectively
`9fece9f8d6926cc284ccf78272e81f3afe9cf4cee51b5540a803ca17fdf36769` and
`cab1fd37e2e6f3f84292a75a6ec67d0cc2e148dbf9857591c6c2dc55e325c2d4`.
This subtask independently repeated their exact saved-response comparisons
without displaying NoEcho identifiers. The CLI-parsed application response did
not contain `IdentityStoreArn`; that observation does not establish store absence.
The returned app ARN can populate `AssignmentRequired=true` without any user
or broker role prerequisite. The initial access-scope proposal is withdrawn as
described below. The grant
still requires the real selected loopback callback; the actor method waits for
the three exact broker roles created by the 17-resource stack. No substitute
human/admin principal is needed to break that dependency.

The following dependency sequence records the original installation proposal.
**Its authorization-code step failed provider admission, so this is not an
executable installation procedure.** Resolving that provider contract requires
separate review before any grant substitution, app enablement or login.

1. `CreateApplication` for the verified instance and AWS `custom` OAUTH provider,
   a reviewed GUG-274-specific name/description/tags, one preserved `ClientToken`
   and initially `Status=DISABLED`; record and read back the returned ARN. No
   canonical current GUG-274 application name was found, so that name is an
   installation choice, not an existing source pin.
2. Require `GetApplicationAssignmentConfiguration.AssignmentRequired=true`;
   the coordinator confirmed it already, so no Put is necessary. The proposed
   `PutApplicationGrant` with `GrantType=authorization_code` and
   `Grant={AuthorizationCode:{RedirectUris:[reviewed_callback]}}` was attempted
   once after the callback producer passed local tests. AWS rejected that grant
   type; do not repeat it or substitute a different grant automatically.
   Do not configure the implicit `sts:identity_context` token scope through
   `PutApplicationAccessScope`; the live preflight correction below supersedes
   that initial proposal. Inventory additional application access scopes with
   `ListApplicationAccessScopes` and require no additional scopes for this lane.
   The [grant shape](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_AuthorizationCodeGrant.html)
   does not establish support for this custom application; the
   [assignment](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_PutApplicationAssignmentConfiguration.html)
   API documents the separate assignment control without a client secret.
3. Obtain two real, independently approved directory UserIds privately. Configure
   exactly two `CreateApplicationAssignment` requests with `PrincipalType=USER`.
   A new account instance requires genuine enrollment in its own store; users
   from the organizational store cannot be copied as if they existed locally.
   [Application assignments](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_CreateApplicationAssignment.html)
   verify access to the application, not that two opaque IDs represent two humans.
4. Install the reviewed 17-resource template with that fixed private binding and
   the real signed artifact. The disabled application can supply its ARN before
   the broker roles exist; no successful identity exchange is claimed at this
   stage. After exact role/function readbacks, render
   [the existing actor policy](../../policies/iam/platform-authority-bootstrap-artifact-identity-application-actor-policy.json)
   for 042 and use `PutApplicationAuthenticationMethod` with
   `AuthenticationMethodType=IAM`, `AuthenticationMethod={Iam:{ActorPolicy:...}}`.
   Only the three canonical service execution roles may exchange codes, not the
   installer or human SSO roles. Read back that policy before enabling the app.
5. Provision the missing normal Approve and Apply permission sets **in the
   organization instance**, with exact policies from the existing normal CLI,
   and assign them to real human B for account 042. Plan remains with A. Use
   `CreatePermissionSet`, `PutInlinePolicyToPermissionSet`,
   `CreateAccountAssignment` and `ProvisionPermissionSet` with exact returned
   resource IDs and status readbacks. A genuine Plan is still needed for the
   action-specific Apply policy; an empty permission set is not Apply authority.
6. Enable the application only after exact metadata and assignments pass. A
   fresh authorization code and PKCE verifier must be created in memory by each
   real user and passed through the existing nonpersistent descriptor. No token,
   assertion or credential belongs in this inventory. The existing runtime
   rejects refresh tokens, extra scopes and lifetimes outside 60–900 seconds;
   the session-configuration API controls background-session status, not that
   access-token lifetime. Actual exchange compatibility remains to be observed;
   do not invent a duration setting or relax the check.

The installation permission boundary should be split into discovery, one create
and exact-object configuration. For `CreateApplication`, AWS requires resources
for the verified instance, exact provider and the future application ARN pattern
under the selected account/instance; after readback, remove that creation scope
and allow only the exact app ARN for the named Put/CreateAssignment/Update/Get/List
operations. `CreateInstance` has the service-linked-role, directory and
organization-read dependencies noted above. Permission-set creation requires the
exact organization instance and narrowly scoped future permission-set resource;
subsequent policy/provision/assignment operations bind exact returned permission
set and target account resources. Keep Region/time/tag restrictions wherever the
action supports them. `kms:Decrypt` is a documented dependency for applicable
Identity Center operations only when the actual encryption configuration requires
it; never substitute either newly created signing key or an invented key ARN.
AWS does not expose a `PrincipalId` condition for these application assignment
actions, so the two exact request bodies and controlled operation remain part
of the boundary. [Current IAM action/resource reference](https://docs.aws.amazon.com/es_es/service-authorization/latest/reference/list_awsiamidentitycenter.html).

### Stage 2 readback correction: token scope versus configurable target scope

The private stage-2 packet contains five request shapes checked against the
source-pinned Botocore model without creating a network client. Its assignment
Put has byte SHA-256
`625cc75fd96675a7de1c842e439b0a5e1cc2619f20b28efe426c7e112a2c10d7`.
The coordinator confirmed `AssignmentRequired=true` in the current readback,
so this Put is unnecessary. **No stage-2 mutation occurred.**

The initially proposed scope Put has SHA-256
`7bb25ae8423897f885a0d1ca520f09042e27f2715957477a13b82b019c880953`
and **must not execute**. Its paired Get is withdrawn from required configuration
checks. Before any Put, the coordinator verified STS 042 and the DISABLED app,
then `GetApplicationAccessScope(Scope=sts:identity_context)` returned
`ValidationException: Invalid access scope for type sts:identity_context`.
That is not a successful absence result: the API documents
`ResourceNotFoundException` separately. It also does not establish that account
instances lack OAuth support. [GetApplicationAccessScope](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_GetApplicationAccessScope.html).

The proposal conflated two contracts. AWS explicitly lists `sts:identity_context`
among the default token scopes in
[CreateTokenWithIAM](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateTokenWithIAM.html).
Its S3 setup configures only `s3:access_grants:read_write` through the access-scope
API and subsequently receives `sts:identity_context` in the token response.
[S3 directory-identity setup](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-grants-directory-ids.html).
This supports withdrawing our unsupported configuration step; it does not prove
a successful exchange for the new application. The actual GUG-274 verifier
requires `scope=["sts:identity_context"]` on the IAM token request and an identical
response scope. It does not call the access-scope Get/Put API. Its immutable
application/instance/store/user tuple, exact three actor roles, STS context
conditions and two-person boundary remain unchanged.

`ListApplicationAccessScopes` still inventories additional target scopes. The
initial request's `MaxResults=100` passed the local model but AWS rejected it
with a service limit of 10. The coordinator's v2 request with `MaxResults=10`
succeeded and returned `Scopes=[]`. Model-shape validation did not establish
service admission. The original request files remain intact for custody;
`scope-request-withdrawal.json` records these corrections and their status.

### Implemented local PKCE producer — provider blocked

The CLI now has a local browser/loopback producer feeding its existing
pipe/socket grant contract. The candidate browser endpoint is
`https://oidc.us-east-1.amazonaws.com/authorize`. AWS documents
authorization with `client_id` equal to the application ARN followed by
`CreateTokenWithIAM` in an Amazon Q integration. That example does not establish
authorization-code support for the custom application created here, which
subsequently rejected that grant type.
[AWS application-ARN authorization example](https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/isv.html).
The maintained AWS CLI implementation corroborates PKCE S256 and the browser
query key `scopes` (plural); the token API separately uses `scope` (singular).
[AWS CLI authorization URI implementation](https://github.com/aws/aws-cli/blob/v2/awscli/botocore/utils.py).

The implemented closed query contains `response_type=code`, exact reviewed app ARN,
exact registered loopback redirect, random one-operation `state`,
`code_challenge_method=S256`, `scopes=sts:identity_context`, and SHA-256 base64url
challenge without padding. This combines two official examples, but provider
admission of this app's grant failed. It is an offline candidate only.
No `RegisterClient`, client secret
or token exchange belongs in the local producer. The existing IAM exchange stays
in the canonical service role. `aws sso login` registers a different public
client and caches tokens; it does not produce this app-ARN grant.

The implementation consists of
[the local receiver](../../tooling/platform_authority_bootstrap_identity_grant.py),
[the isolated launcher](../../scripts/deployment/platform-authority-bootstrap-identity-grant.py),
[focused tests](../../tests/test_deployment/test_gug274_identity_grant.py) and an
opt-in readiness hook in the existing bootstrap CLI. Both new source paths are
part of `PROVENANCE_PATHS`. Before executing the helper, the launcher requires
the independently reviewed exact clean source commit and compiles its bytes
from that Git object. The child receives a frozen copy of the verified public
Python source blobs over a separate anonymous pipe, checks transport integrity,
and executes both the CLI and its closed `tooling` imports from RAM. That
transport hash preserves custody of already verified Git bytes; it does not
create new source authority. Direct CLI use without the launcher retains the
existing source-only loader. Source verification repeats before child launch
and before browser navigation. The separate binding file must be a private regular
file, with an independently supplied exact SHA-256; its hash is not self-issued
installation authority.

Before browser navigation, bind exclusively to the exact reviewed
`127.0.0.1:38271/callback`; fail if occupied, without a fallback port. Port 38271
is an explicit installation choice approved for this work, not a fixture-derived
default. The same URI must be installed in the grant and immutable Lambda binding.
The listener reuses only closed TCP TIME_WAIT addresses, never an active listener;
this permits separate Plan/Approval/Apply operations on the fixed port. Keep state/verifier/code
only in process memory. Require exact path/Host, one unambiguous code/state pair,
constant-time state comparison, bounded request size/time and one successful
callback. Suppress HTTP request/exception logging; send a generic no-store,
no-referrer completion page and close the listener after use.

Pass exactly the existing four-field grant JSON through an anonymous pipe to
`--identity-grant-fd`, close its writer to provide EOF, and inherit that descriptor
only into the exact normal CLI under `python3 -I -S`. Keep the grant out of argv,
environment, files, stdout and logs. The launcher must preserve current source,
SDK and profile admission and execute no generic shell command. Each operation
gets a new grant; Plan/Approve/Apply permission sets and fixed human bindings
remain separate. Two real, independently approved human bindings are still
missing; two IDs or two sessions created for one person would not satisfy them.

Plan currently creates and checks its CFN change set before consuming the
descriptor. Obtaining the code before that work can age it prematurely. A
private readiness pipe now emits just before the three existing grant reads,
after their prechecks, letting the launcher open the browser at the right
time. Its descriptors are also validated before the CLI handler can have an
effect. This signal is local synchronization, not authority: it binds the chosen
operation/process, enforce timeouts and child-exit handling, and never skip a
precheck or retry a failed Plan automatically. Do not infer readiness from stdout.

Tests exercise the real pipe reader and one-shot grant class, PKCE encoding,
wrong state/Host/path, duplicate/extra query fields, replay, occupied port,
timeout/child exit and absence of grant data from captured output. No
registration/token client/cache is used. The real isolated launcher rejects
hidden helper drift even under Git's `assume-unchanged` flag, before importing
that helper. The callback-to-child test uses real sockets/pipes and the actual
CLI readiness/reader functions; only dispatch to the external AWS operation is
replaced with an offline consumer. A separate real-Git regression mutates the
on-disk CLI or one dependency immediately after source verification: neither
unreviewed sentinel executes. This closes the P2 found independently when the
initial launcher still ran the child from disk between its two source checks.
First connected validation still requires a real assigned user and
installed canonical role. The existing 60–900-second token lifetime, no-refresh
requirement and exact response scope remain mandatory. AWS documentation does
not establish that the new app already emits that profile; do not mark it PASS
from request shapes or synthetic provider responses.

Local validation for this inventory read the pinned Botocore service models
without creating any client and reproduced both topology rejections using
synthetic shapes. It did not discover, create or assign users; perform a token
exchange; change IAM, CFN or runtime gates; or create an application/instance.
The coordinator's separate creations and failed scope preflight are distinguished
above. After the SDK owner's stable checkpoint and the independent P2 correction,
all **186 tests passed in 30.24 seconds**, including **55 PKCE cases** and the existing GUG-274/vendored-SDK
regressions. The earlier concurrent-import collection failure was resolved by
that checkpoint, with no bypass or suppressed test.
Independent review reproduced all 55 PKCE tests in 4.52 seconds and confirmed
the P2 closure, with no further P1/P2 identified in the snapshot/importer/pipe
scope. Local callback success does not establish AWS grant-configuration success.
The coordinator independently reproduced all 186 cases in 30.60 seconds.

Run this checkpoint serially: its callback tests exclusively bind port 38271.
It uses only synthetic callback/grant values, real local sockets/pipes and
scratch Git repositories; it opens no browser or AWS client for a live operation.

```bash
PYTHONDONTWRITEBYTECODE=1 \
SCANALYZE_GUG274_SDK_RUNTIME_ROOT=/private/tmp/scanalyze-gug274-sdk-spr0_cwc \
python3 - <<'PY'
import sys
sys.path.insert(0, '/private/tmp/scanalyze-gug274-sdk-spr0_cwc/site-packages')
import pytest
raise SystemExit(pytest.main([
    '-q', '-p', 'no:cacheprovider',
    'tests/test_deployment/test_gug274_bootstrap_artifact_trust_root.py',
    'tests/test_deployment/test_gug274_vendored_sdk.py',
    'tests/test_deployment/test_gug274_identity_grant.py', '--tb=short']))
PY
```

### Stage 3 failed grant request — execution suspended

The private `identity-application-stage3/put-authorization-code-grant-request.json`
has byte SHA-256
`127632f87f1e7be8c79ce90335bbe68b91c9c8bf67f3d0d78b8dd2df4fdaf276`.
It contains the exact previously read-back app ARN, `GrantType=authorization_code`
and only `Grant.AuthorizationCode.RedirectUris=["http://127.0.0.1:38271/callback"]`.
Get and List request files accompany it. `ListApplicationGrants` accepts
`ApplicationArn` and `NextToken`, without `MaxResults`; its original attempted
page-size parameter was rejected locally before any packet was emitted. All
three final shapes passed the pinned service model without an API client.

The coordinator revalidated STS 042 under the installation administrator profile,
the exact DISABLED app, complete `Grants=[]` inventory and request hash, then
attempted the exact Put **once**. The CLI returned exit code **254**. Its helper
did not retain stderr. The subsequent List returned `Grants=[]` and the app
remained DISABLED. The immediate CloudTrail lookup returned no matching event;
the coordinator's second metadata lookup did match the attempt:

- Event time: `2026-09-14T06:52:54Z`.
- Event ID: `7a6d3f47-32db-4e8d-bfc2-b3d5ab82a0d2`.
- Error code: `ValidationException`.
- Error message: `Grant type: authorization_code not supported`.
- Private evidence: `identity-application-stage3/put-event-metadata-lookup.v2.json`.

These are observed service facts. They do not establish that toggling DISABLED
or moving the app to an organization instance would change grant support.
The documented customer-managed OAuth setup instead requires an external
trusted token issuer and an audience; the Amazon Q custom-provider example
configures `JwtBearer` explicitly.
[Customer-managed application setup](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-using-customermanagedapps-setup.html),
[OAuth application setup, step 3](https://docs.aws.amazon.com/singlesignon/latest/userguide/customermanagedapps-trusted-identity-propagation-set-up-your-own-app-OAuth2.html),
[Amazon Q custom-provider JWT bearer example](https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/making-sigv4-authenticated-api-calls.html).
These sources provide no documented custom-provider authorization-code/PKCE
installation path matching the present contract. They are not authorization to
add a trusted issuer or switch grants; that would require a separate reviewed
compatibility design preserving the service actors and two-human controls.

**Stage 3 failed its installation checkpoint: no grant is verified installed,
and this request is not ready for another execution.** Do not retry from this
document or treat the local tests/model check as service acceptance. Preserve
`*before-execution`, `*after-attempt`, `put-execution-attempt` and
`put-execution-outcome` records in the private stage-3 packet. The original local
request-review manifest predates this attempt; its original NOT_EXECUTED label
is historical, superseded by those operation records and the matching CloudTrail
metadata. The provider compatibility investigation is read-only. A later corrected
request requires an independently reviewed supported provider contract and current
readbacks; neither the API enum nor the local SDK model establishes that support.
No administrator token-exchange actor, assignment or enabled method is inferred.

`identity-application-stage3/pkce-binding.json` has byte SHA-256
`7b9c155c69cd66f02fb7183682b438808e4611a30ff387fbcf19ffb82d68f670`.
The coordinator must independently compare its app/instance/owner/Region/URI
against authenticated installation readbacks before adopting that pin. The
manifest is an integrity inventory only. No authorization code, verifier, state,
token, assertion, human identifier or credential is persisted in this packet.

The previously proposed Plan operator command is withdrawn as an execution
instruction. The launcher remains `OFFLINE_VALIDATED_PROVIDER_BLOCKED`; no live
browser or protected Plan invocation is prescribed until the provider contract
is resolved. The retained binding pin identifies a reviewed local candidate,
not a registered callback or permission to run it. A supported design still
needs exact normal profiles, reviewed source and two genuine human bindings.

The launcher supports only Plan/Approve/Apply and their closed option sets.
Approval/Apply need their separately provisioned profiles and operation-specific
inputs; they are not silently mapped to the Plan or installer profile. Readiness
waits at most 900 seconds, public-source pipe transport 30 seconds, grant pipe
transport 10 seconds, browser callback 300 seconds, and child completion
1800 seconds. Pipe writes are nonblocking and detect child exit. Any timeout or ambiguous child failure stops without retry and
requires the existing read-only reconciliation procedure. A timed-out Plan can
already have created change-set metadata before the readiness signal; terminating
the local child does not roll back that service effect. No browser login or
cloud action has been run by this local implementation.

### Token-lifetime compatibility risk remains open

The actual token request model has no TTL/duration parameter. The current
[application session configuration API](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_PutApplicationSessionConfiguration.html)
configures background-session status, not access-token expiration. AWS's
[S3 Identity Center example](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-grants-directory-ids.html)
shows an exchange returning `expiresIn=3600` and a refresh token; that example
uses another grant/configuration and does not prove this new app's exact result.
It does show that the current service contract is not documented to always meet
GUG-274's 60–900-second/no-refresh response requirements.

No primary source found in this bounded review establishes a supported setting
that forces this IAM-authenticated authorization-code app to emit the required
profile. Do not use a permission-set session duration or a background-session
toggle as an assumed token-TTL control. First connected proof must evaluate the
actual response entirely in memory with sanitized failure codes. If it emits
3600 seconds or a refresh token, the real verifier must deny. That would require
a separate evidence-backed provider-compatibility decision; this producer does
not relax the guard, clamp a received value, discard a forbidden field to obtain
PASS, or substitute synthetic token evidence.
Two additional local negative probes called the real response validator and
confirmed that 3600 seconds and refresh-token presence each reject with the
expected sanitized error. These probes establish rejection behavior only;
they provide no observation of this application's live token response.

## Step 3: normal human identities and state backend

Provision `ScanalyzeAuthorityBootApprove` and
`ScanalyzeAuthorityBootstrapApply` through the governed Identity Center process;
do not create manual `AWSReservedSSO_*` IAM roles. Only normal Plan was observed.
The existing Approval policy is now concretely rendered in the packet with this
successful no-cloud command:

```bash
env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap.py render-approval-policy \
  --authority-account-id 042360977644 --region us-east-1 \
  --destination-account-id 905418363887 \
  --policy-out /private/tmp/scanalyze-normal-authority-review-5jneu3jb/bootstrap-approval-policy.json
```

The file now exists and the renderer refuses overwrite; this records the
completed command, not an instruction to run it again. The initial attempt
using `/tmp` was rejected because macOS aliases it through a symlink. The
successful attempt used the canonical `/private/tmp` path without weakening the
path gate. Plan rendering additionally needs the exact new change-set name.
Apply rendering deliberately needs a real, unexpired Plan; no fake Plan was
manufactured to obtain an operational Apply policy.

The backend remains the unchanged
[four-resource template](../../bootstrap/cfn-platform-authority-state-backend.yaml):
one retained symmetric KMS key, alias `alias/scanalyze-platform-authority-state`,
bucket `scanalyze-platform-authority-042360977644-us-east-1-state` and bucket
policy; key `platform-authority/terraform.tfstate`, noncurrent retention 365.
The Apply executor owns the separate all-true account S3 public-access-block
effect. The existing symmetric AWS-managed key observed by inventory is not
this proposed customer-managed backend key or either signing authority.

The July `CREATE_COMPLETE/AVAILABLE` change set remains unexecuted. Its
retirement is a separate reviewed lane. The recovery preflight actually checks
an empty review stack **and no active change sets**; source confirms this is a
live precondition, not stale guidance. After retirement and service/identity
installation, the normal sequence is the existing `preflight-recovery`,
`render-plan-policy`, `plan`, independent `approve`, `render-apply-policy`,
`apply`, and exact `verify` flow. Keep canonical permission-set STS checks,
nonpersistent identity-grant descriptor, service-owned CAS and single attempt.
Neither a broad administrator nor a founder exception substitutes for it.

## Separate minimum release-VSA key installation

The new [VSA producer](../../tooling/release_vsa_producer.py) requires
`ECDSA_P256_SHA256` over canonical release-wide statement bytes. The Lambda
Signer platform is `AWSLambda-SHA384-ECDSA`, which signs deployment ZIPs and
cannot satisfy this release statement contract. The minimum compatible AWS
resource is a separate `ECC_NIST_P256`, `SIGN_VERIFY`, single-Region KMS key with
AWS-generated material. The exact request is
`release-vsa-create-key-request.json`; no alias or speculative key ARN is needed
to create it. Its initial key policy enables account administration and public
key readback but grants **no `kms:Sign`**, grants or deletion action.

**The coordinator completed this creation; do not rerun CreateKey.** The actual
key ARN is
`arn:aws:kms:us-east-1:042360977644:key/4d1420e0-ab6f-4d24-a31b-090ba4144427`.
Local comparison of the saved creation, DescribeKey, GetPublicKey and policy
responses confirmed the same ARN, `ECC_NIST_P256`, `SIGN_VERIFY`, Enabled state,
AWS_KMS origin, single-Region status and `ECDSA_SHA_256` support. The returned
policy exactly equals the request policy and contains no signing grant.

The reviewed creation command, after the coordinator checked its KMS installer
session, was one non-retried request with private output:

```bash
: "${SCANALYZE_VSA_KEY_INSTALLER_PROFILE:?reviewed key installation session required}"
umask 077
set -o noclobber
AWS_MAX_ATTEMPTS=1 aws --profile "$SCANALYZE_VSA_KEY_INSTALLER_PROFILE" \
  --region us-east-1 kms create-key \
  --cli-input-json file:///private/tmp/scanalyze-normal-authority-review-5jneu3jb/release-vsa-create-key-request.json \
  --output json \
  > /private/tmp/scanalyze-normal-authority-review-5jneu3jb/release-vsa-create-key-response.json
```

`kms:CreateKey` needs creator IAM permission and `kms:TagResource` for the request
tags. Creation has no existing key ARN to scope; keep account/Region/request
boundaries and the exact reviewed key policy. Its safety check remains false
for `BypassPolicyLockoutSafetyCheck`: the caller must retain permitted policy
administration. Do not add `kms:*` or bypass lockout protection to force it
through. An ambiguous CreateKey outcome must be reconciled, not retried to create
another key. [CreateKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html)
defines the immutable key spec/usage and creation permissions.

Read `DescribeKey` and `GetPublicKey` against the exact ARN returned by that
creation, comparing account/Region, Enabled status, `ECC_NIST_P256`,
`SIGN_VERIFY` and supported `ECDSA_SHA_256`. Convert only the public SPKI output
to JWK `kty=EC`, `crv=P-256`, with real base64url x/y coordinates. The readback
supplies the key; it does not approve the issuer/workflow identity. Those values,
the real key ARN, external trust-policy pin, source commit and verifier identity
must be independently approved in the release trust policy. No fixture signer,
fake JWK or locally invented verifier digest can be promoted into it.
[GetPublicKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html)
returns the public key and algorithm metadata.

To activate signing later, bind one actual reviewed signer principal in both
IAM and the exact key policy, with `kms:Sign` only on that key and
`kms:SigningAlgorithm=ECDSA_SHA_256`. The local
[KMS adapter](../../tooling/release_vsa_kms.py) now implements the producer's
`SigningClient` port; its [documented contract](../deployment/release-vsa-kms-adapter.md)
requires an independently pinned authority, exact signer/JWK, approved IAM role
and observed RoleId. It checks STS identity and fresh KMS metadata/public key,
signs SHA-256(`SigningRequest.statement_bytes`) once using `MessageType=DIGEST`,
matches the response key/algorithm and verifies the DER signature locally before
returning the producer's signature record. The producer still runs its full
post-sign gate. This adapter has not established a connected signing operation
or installed `kms:Sign`; the real signing-role approval, IAM/key-policy grant and
release inputs remain required. Do not sign the manifest's digest instead of the
canonical VSA statement or treat key creation as a produced VSA.
[KMS Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)
defines the digest input and DER signature output.

## Reproducible private SDK runtime

The authenticated runtime is
`/private/tmp/scanalyze-gug274-sdk-spr0_cwc`. Set
`SCANALYZE_GUG274_SDK_RUNTIME_ROOT` to this **root**, not its `site-packages`
child. The production importer appends that child itself. The private directory
contains official wheels, `requirements.lock`, the complete installed closure
and `sdk-runtime-public-manifest.json`. The manifest is an inventory, not a new
authority: the seven existing `SDK_DISTRIBUTION_LOCKS` in
[the package verifier](../../tooling/platform_authority_bootstrap_artifact_package.py)
are the independent source pins. They were not changed.

The exact public wheel manifest used in this checkpoint is:

| Distribution | Version | Wheel SHA-256 |
| --- | --- | --- |
| boto3 | 1.42.57 | `74f47051e3b741a0c1e64d57b891076c2c68f8d7b98aee36b044fab1849b4823` |
| botocore | 1.42.97 | `77d2c8ce1bc592d3fbd7c01c35836f4a5b0cac2ca03ccdf6ffc60faa16b5fadc` |
| s3transfer | 0.16.1 | `61bcd00ccb83b21a0fe7e91a553fff9729d46c83b4e0106e7c314a733891f7c2` |
| jmespath | 1.1.0 | `a5663118de4908c91729bea0acadca56526eb2698e83de10cd116ae0f4e97c64` |
| python-dateutil | 2.9.0.post0 | `a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427` |
| urllib3 | 2.7.0 | `9fb4c81ebbb1ce9531cce37674bbc6f1360472bc18ca9a553ede278ef7276897` |
| six | 1.17.0 | `4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274` |

To reproduce in a new private directory, run from the reviewed source worktree
with its existing pytest tooling available. This installs no global packages:

```bash
umask 077
SCANALYZE_GUG274_SDK_RUNTIME_ROOT="$(mktemp -d /private/tmp/scanalyze-gug274-sdk.XXXXXX)"
export SCANALYZE_GUG274_SDK_RUNTIME_ROOT
PYTHONDONTWRITEBYTECODE=1 python3 - "$SCANALYZE_GUG274_SDK_RUNTIME_ROOT" <<'PY'
from pathlib import Path
import json, sys
from tooling.platform_authority_bootstrap_artifact_package import SDK_DISTRIBUTION_LOCKS
runtime = Path(sys.argv[1])
with (runtime / 'requirements.lock').open('x') as stream:
    for name, lock in SDK_DISTRIBUTION_LOCKS.items():
        stream.write(f"{name}=={lock['version']} --hash=sha256:{lock['wheel_sha256']}\n")
with (runtime / 'sdk-runtime-public-manifest.json').open('x') as stream:
    json.dump({'authority': 'SOURCE_PINNED_WHEEL_DIGESTS_NOT_THIS_MANIFEST',
               'distributions': SDK_DISTRIBUTION_LOCKS}, stream, indent=2, sort_keys=True)
PY
PYTHONDONTWRITEBYTECODE=1 python3 -I -m pip --isolated download \
  --no-deps --only-binary=:all: --require-hashes \
  --index-url https://pypi.org/simple \
  --dest "$SCANALYZE_GUG274_SDK_RUNTIME_ROOT/wheels" \
  --requirement "$SCANALYZE_GUG274_SDK_RUNTIME_ROOT/requirements.lock"
PYTHONDONTWRITEBYTECODE=1 python3 -I -m pip --isolated install \
  --no-index --find-links "$SCANALYZE_GUG274_SDK_RUNTIME_ROOT/wheels" \
  --no-deps --no-compile --ignore-installed --require-hashes \
  --prefix "$SCANALYZE_GUG274_SDK_RUNTIME_ROOT/staging" \
  --requirement "$SCANALYZE_GUG274_SDK_RUNTIME_ROOT/requirements.lock"
PYTHONDONTWRITEBYTECODE=1 python3 - "$SCANALYZE_GUG274_SDK_RUNTIME_ROOT" <<'PY'
from pathlib import Path
import sys
runtime = Path(sys.argv[1])
sites = list((runtime / 'staging/lib').glob('python*/site-packages'))
assert len(sites) == 1
sys.path.insert(0, str(sites[0]))
from tests.test_deployment.test_gug274_bootstrap_artifact_trust_root import _materialize_locked_sdk_runtime
_materialize_locked_sdk_runtime(runtime / 'site-packages')
for path in (runtime, *runtime.rglob('*')):
    assert not path.is_symlink()
    path.chmod(0o700 if path.is_dir() else 0o600)
PY
```

The existing test helper copies every installed RECORD-owned file, omits
bytecode and preserves the one source-reviewed jmespath script exclusion. It
does not authenticate the resulting runtime. The real gate below does that
independently, including every source-pinned installed manifest, closed tree,
permissions and imported module origin. No network client is created:

```bash
env -u PYTHONPATH -u PYTHONHOME python3 -I -S - \
  "$SCANALYZE_GUG274_SDK_RUNTIME_ROOT" <<'PY'
from pathlib import Path
import sys
root = Path.cwd().resolve(strict=True)
isolated = tuple(sys.path)
sys.path.insert(0, str(root))
from tooling.platform_authority_bootstrap_artifact_package import import_reviewed_aws_sdk
boto3, botocore, _ = import_reviewed_aws_sdk(
    source_root=root, isolated_import_paths=isolated,
    sdk_runtime_root=Path(sys.argv[1]))
assert boto3.__version__ == '1.42.57' and botocore.__version__ == '1.42.97'
print('PASS: complete SDK closure authenticated; no client created')
PY
PYTHONDONTWRITEBYTECODE=1 python3 - "$SCANALYZE_GUG274_SDK_RUNTIME_ROOT" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + '/site-packages')
import pytest
raise SystemExit(pytest.main([
    '-q', '-p', 'no:cacheprovider',
    'tests/test_deployment/test_gug274_bootstrap_artifact_trust_root.py', '--tb=short']))
PY
```

The SDK checkpoint passed the isolated gate and **77 tests in 11.17 seconds**.
After the transaction-policy fix and JSON renderer, the same suite passed
**103 tests in 12.06 seconds**, with the same authenticated runtime.
The pytest process adds the authenticated site only to its own `sys.path`;
it does not set `PYTHONPATH` or `PYTHONHOME` for the protected subprocess CLIs.
Their isolation and negative tamper tests remain enabled. The host's botocore,
s3transfer and urllib3 versions differ from the pins; the same three host-runtime
failures were reproduced on the frozen HEAD test before this source change.

An initial private installation using explicit wheel filenames added pip's
`direct_url.json`; the real gate correctly rejected its installed-manifest
mismatch. That attempt is preserved under `staging/` and
`site-packages-direct-wheel-rejected/`; the successful nominal requirements
installation is under `staging-index/`. Reproduction uses nominal requirements
from the local verified wheel directory, so it does not introduce that metadata.
No metadata was silently removed to change a failed manifest into a passing one.

## Current versus historical gates, and validation

The old GUG-125 runbook says the platform-authority Terraform root rejects every
production binding. Current source now accepts an explicit
`production_authority_enabled=true` with the exact production workflow and
account separation; default remains false. That older blanket prohibition is
not the current reason installation is blocked. It does not remove any normal
bootstrap identity, signing, source, CAS or state-backend requirement.

The current signer lock, exact `:1` services, distinct identity users, clean
source requirement, host runtime/tool checks, real signing readback and July
recovery restrictions are source-enforced. Literal `NO-GO` artifact labels
describe evidence status; backend bindings contain no destination workload
environment field. Installing the backend still does not certify production.
Terraform installation then needs its own reviewed saved plan covering the
control key, deployment registry/execution tables, release bucket and exact OIDC
roles; customer ACCOUNT_READY/runtime deployment remain subsequent stages.

Validation performed locally:

- Real Signer `PutSigningProfile`/`GetSigningProfile` and KMS `CreateKey` request
  shapes validated against the installed Botocore models without creating any
  network client.
- Real isolated Approval policy renderer: PASS, no AWS call.
- Real canonical package CLI: expected `SOURCE_TREE_DIRTY` rejection and no ZIP.
- Real signing trust-root verifier: configured actual version and domain-separated
  digest accepted; false/NO-GO evidence preserved. A synthetic unconfigured
  contract still stops before provider access in the real receipt gate.
- All 103 GUG-274 tests: PASS with the authenticated SDK. Actual pinned version
  reaches the real receipt-to-CFN parameter gate; a foreign version is rejected.
- Real JSON renderer CLI: deterministic output, complete template semantic
  equivalence, private output and no-clobber verified. Pin mutation, symlink,
  public directory, duplicate-key, unknown-tag, recursive and non-JSON inputs
  rejected. Transaction deny tests failed before the fix and pass afterwards.
- Exact local Signer and KMS creation/readback comparisons: PASS as described
  above. These are saved-response comparisons, not additional cloud reads.
- Public template resource inventory and private packet permissions verified.

This local implementation subtask made no cloud call, policy attachment,
assignment, signing, upload, CFN execution, Git mutation or Terraform plan/apply.
The coordinator's completed Signer and KMS effects are recorded explicitly above.
To roll back the uncommitted local candidate, restore only the two source pin
files and their test from the reviewed prior versions; retain the evidence packet
under custody. Revoking a Signer version or scheduling KMS deletion requires a
separate reviewed operation and impact analysis. Neither removal of local files
nor a failed later installation undoes those existing cloud resources.
