# Platform-authority retirement entrypoint materialization

## Scope and evidence status

GUG-363 implements the repository contract described by
[ADR-051](../../ADR/ADR-051-direct-retirement-entrypoint-materialization.md)
for materializing the dedicated GUG-357 non-production entrypoint used by the
ADR-050/GUG-215 retirement PEP.

The implementation is not evidence of AWS deployment. Local tests use injected
clients and synthetic identifiers. No repository artifact, successful gate,
plan digest or CLI flag authorizes `CreateStack`. The live path requires a
fresh, exact GUG-357 authorization, external service-role evidence and an exact
pre-existing signed-artifact handoff. Production remains **NO-GO**.

## Component map

| Component | Responsibility | Authority |
|---|---|---|
| `tooling/platform_authority_retirement_entrypoint_materializer.py` | Validate intent, source, signed-artifact contract, plan, execution authorization, ledger and receipt; implement injected-client apply/reconcile state machine | One possible `CreateStack` through injected clients |
| `scripts/deployment/platform-authority-retirement-entrypoint-materializer.py` | Enforce owner-only files, explicit profile/Region, local attempt ledger and sanitized CLI output | `plan` offline; separately authorized `apply`; read-only `reconcile` |
| `tooling/platform_authority_change_set_retirement_package.py` | Build and validate the deterministic unsigned Signer source ZIP | No AWS, upload, signing or deployable artifact |
| `bootstrap/cfn-platform-authority-change-set-retirement-ledger.yaml` | Exact single-operator PEP graph | CloudFormation template only |
| `tests/test_deployment/test_gug363_retirement_entrypoint_materializer.py` | Determinism, binding, negative, one-attempt and readback contracts | Synthetic/injected clients only |
| `tests/test_deployment/test_gug215_retained_change_set_retirement.py` | Broker/template regression contract, including logging boundary | Offline only |

The materializer never uploads/copies a broker artifact, starts/cancels a Signer
job, changes a signing profile or Code Signing Config, creates the external
CloudFormation service role, changes an operator policy, grants `iam:PassRole`,
invokes the broker or mutates the GUG-215 retirement ledger.

## Fixed target and authority boundary

The target tuple is code-owned:

```text
stack       scanalyze-platform-authority-gug357-retirement-entrypoint
region      us-east-1
mode        SINGLE_OPERATOR_NONPROD_EXCEPTION
production  false / NO-GO
```

It is intentionally different from the retained review shell
`scanalyze-platform-authority-state-backend`. A request, private intent, profile
name or environment variable cannot select another stack, account, Region,
mode or service role.

The `CreateStack` request carries the fixed pre-existing CloudFormation role
`scanalyze-platform-authority-gug363-cfn-materializer` in the authority account.
CloudFormation, rather than the operator, uses that role to create the reviewed
IAM, DynamoDB, Lambda and Logs resources. GUG-363 neither materializes nor
repairs the role. GUG-357 must first establish fresh read-only
evidence for its exact trust, effective policies, boundary, tags and the
operator's one-role-only `iam:PassRole` grant. Readback of the resulting stack
must return the same exact `RoleARN`.

The current GUG-357 audit permission-set package does not include the IAM reads
needed for that proof. Until a separate approved read-only evidence path closes
the gap, live materialization is blocked.

## Offline plan contract

`plan` accepts three existing owner-only inputs outside the repository:

1. a closed materialization intent;
2. the deterministic GUG-215 unsigned Signer-source manifest; and
3. the exact unsigned source ZIP represented by that manifest.

It fails unless the repository is clean, `HEAD` and tree equal the intent, the
template worktree bytes equal the bytes at that Git object, and every package
and artifact binding is exact. It does not read an AWS profile or construct an
AWS client.

The resulting private plan binds:

- GUG-363 as implementation issue and GUG-357 as live authorization issue;
- the dedicated stack, fixed account, Region and CloudFormation service role;
- exact template bytes and digest;
- the exact unsigned source manifest/archive and their source-byte digests;
- distinct exact versioned Signer source and signed-destination S3 identities,
  byte digests, sizes, optional provider checksums and KMS-encryption bindings;
- completed Signer-job and exact historical signing-profile-version bindings,
  plus an active current profile with the same name and platform;
- Code Signing Config policy `Enforce` and an exact
  `AllowedPublishers.SigningProfileVersionArns` set;
- only the signed destination `CodeSha256` and S3 coordinates in the
  CloudFormation parameter projection, plus the manually pinned runtime;
- exact ADR-050 exception, owner authorization and Identity Center bindings;
- the ordered CloudFormation parameter projection and its visible
  `PrivateParameterProjectionSha256` commitment for values masked by `NoEcho`;
- the exact expected resource set and its digest;
- the retained log-group contract; and
- the complete `CreateStack` request and deterministic client-request token.

The plan states `deployment_authorized = false`. Its `plan_digest` protects
integrity only. A separately supplied expected digest is required so a replaced
plan cannot authorize itself. Both `apply` and `reconcile` also require a
separately supplied expected `artifact_signing_contract_digest`; the value must
match the plan and execution authorization before any AWS client is constructed.

## Signed-artifact handoff

The GUG-215 package ZIP is a deterministic **unsigned input** to an external AWS
Signer workflow. Despite the historical manifest field name,
`lambda_code_sha256` in that source manifest hashes the unsigned ZIP bytes; it
is not the deployable Lambda `CodeSha256` after signing.

The source and destination are a closed pair:

- the source is one exact private, versioned, KMS-encrypted S3 object containing
  bytes identical to the GUG-215 ZIP;
- one already-completed Signer job owned and invoked by the authority account,
  using platform `AWSLambda-SHA384-ECDSA`, binds that source to the exact
  reviewed historical signing-profile version and to one distinct destination
  object, with no overrides or signing parameters; the named profile must
  remain active on the same platform, but its current version may be newer;
- the destination is the exact private, versioned, KMS-encrypted signed ZIP in
  the same bucket and under the same KMS key, but with a distinct key and version
  derived from the Signer job ID; and
- the destination byte digest, size and Lambda `CodeSha256` are independently
  bound and are the only artifact values projected to CloudFormation.

The source and signed ZIP bytes must differ, but safe in-memory ZIP parsing must
produce exactly the same member-name-to-payload mapping. The comparison never
extracts to disk and rejects duplicate or unsafe paths, directories, encrypted
members, symlinks and aggregate/member size overrun. This permits Signer's
signature envelope while preventing a signed destination with altered broker
code or extra semantic content.

The pre-existing Code Signing Config is not trusted by ARN alone. Its live
policy must be `Enforce`, and its allowed publisher set must equal the one
reviewed signing-profile-version ARN with no additional publisher. Any pending,
failed, revoked, mismatched or incompletely evidenced signing job, a signed key
with anything other than one latest version and no delete marker,
source/destination equality, byte-digest drift, a mismatched provider checksum
when AWS supplies one, or policy drift blocks before the
execution ledger is consumed.

## Closed CreateStack projection

The only allowed mutation is `cloudformation:CreateStack`. The request fixes:

- the dedicated stack name;
- complete in-memory `TemplateBody` rather than an unbound URL;
- the exact ordered parameter list;
- `CAPABILITY_NAMED_IAM` only;
- `OnFailure=DO_NOTHING`;
- `EnableTerminationProtection=true`;
- the fixed CloudFormation service-role ARN; and
- a deterministic GUG-363 client-request token derived from the immutable
  materialization binding.

The materializer prohibits `CreateChangeSet`, `ExecuteChangeSet`,
`DeleteChangeSet`, `UpdateStack`, `DeleteStack`, artifact upload/copy, Signer
mutation, signing-profile or Code Signing Config mutation, Lambda invoke,
Terraform apply/import and direct provider mutations. It does not offer a
general CloudFormation adapter.

`OnFailure=DO_NOTHING` is deliberate. Automatic rollback could remove evidence
or create an ambiguous destructive path. A failed or partial stack is retained
for read-only reconciliation and a separately reviewed recovery package.

The request omits `DisableRollback` because CloudFormation forbids sending it
with `OnFailure`. Stack readback must nevertheless report rollback disabled,
which is the service representation of `DO_NOTHING`; a false or absent value is
treated as drift.

## Exact single-operator resource graph

The expected stack has twenty-one resources:

- one deletion-protected, retained DynamoDB retirement ledger;
- one retained CloudWatch Logs group;
- five exact IAM roles: broker execution, two invokers and two deny-all proof
  roles;
- one Lambda function sourced only from the exact signed destination and one
  published version pinned to that signed `CodeSha256`;
- only the three `single-classify`, `single-retire` and `single-reconcile`
  aliases;
- only their three `AWS_IAM` Function URLs; and
- six exact URL/function invocation permissions for the two invoker roles.

The normal `classify`, `retire` and `reconcile` alias family must be absent.
`$LATEST`, weighted aliases, public URL permissions, extra resources and an
unqualified invocation path fail readback.

## Logging boundary

The stack creates the fixed log group
`/aws/lambda/scanalyze-platform-authority-gug215-retirement` before the Lambda.
It has 365-day retention, `DeletionPolicy: Retain`,
`UpdateReplacePolicy: Retain` and AWS-owned encryption at rest.

The function fixes:

```yaml
LoggingConfig:
  ApplicationLogLevel: ERROR
  LogFormat: JSON
  LogGroup: <the exact retained group>
  SystemLogLevel: WARN
```

The broker source has no application `print` or logging call. The execution
role can only `logs:CreateLogStream` and `logs:PutLogEvents` on streams under
that group. It explicitly denies log-group creation/deletion, retention changes,
KMS association changes and Logs resource-policy mutation. CloudWatch logs are
sanitized operational evidence; they do not replace the private ledger,
CloudTrail or exact provider readback.

## Apply state machine

Before an effect-capable client is used, `apply` validates the private plan and
fresh execution authorization against independently supplied expected digests.
The authorization binds `live_checkpoint_digest`, `live_before_state_digest`,
`service_role_evidence_digest` and `operator_authority_evidence_digest` from the
fresh GUG-357 evidence package, in addition to the plan, caller and request.
It rejects static credential variables and endpoint/CA transport overrides and
requires one explicitly named approved profile and `us-east-1`.

STS caller identity is always the first AWS call. Before consuming the local
attempt ledger, every `apply` executes this closed read-only sequence:

1. `sts:GetCallerIdentity`;
2. `cloudformation:DescribeStacks` by the dedicated stack name;
3. `signer:DescribeSigningJob`;
4. `signer:GetSigningProfile` for the exact name/version;
5. `s3:GetBucketVersioning` for the shared private source/destination bucket;
6. unsigned-source `s3:HeadObject`, then `s3:GetObject` for exact byte hashing;
7. signed-destination `s3:ListObjectVersions`, `s3:HeadObject`, then
   `s3:GetObject` for exact version uniqueness and byte hashing;
8. `lambda:GetCodeSigningConfig` for `Enforce` and the exact publisher set; and
9. a second `cloudformation:DescribeStacks` absence check.

The signing preflight and second stack observation occur even when step 2 finds
a target, so every no-touch receipt also proves fresh signing readback. If the
first target disappears or changes identity by step 9, the result is ambiguous
and no mutation is attempted. If the second observation contains a stable
pre-existing target, CloudFormation readback remains incomplete because its
private parameters are masked and no causal GUG-363 execution ledger exists;
the result is no-touch and ambiguous, never complete. Only when both
observations prove absence does the state machine revalidate the authorization
and signature windows—the authorization cannot outlive the signature—consume
the create-only owner-local ledger, and send at most one exact
`cloudformation:CreateStack`.
Post-write readback is ordered as `DescribeStacks`, `GetTemplate`,
`ListStackResources`, then `DescribeStackEvents`.

`reconcile` repeats the complete read-only preflight and then the three remaining
CloudFormation readbacks after its second `DescribeStacks`; it has no mutation
step. Exact object bodies are used only for digest verification and are never
printed, persisted or extracted by the materializer. The runtime never calls an
upload, copy or AWS Signer mutation API and cannot repair a missing or failed
signing handoff.

Every receipt fixes
`materializer_readback_scope=CLOUDFORMATION_CONTROL_PLANE_ONLY`,
`provider_certification_complete=false` and
`gug357_certification_required=true`. Even `READBACK_VERIFIED` is therefore a
CloudFormation control-plane result, not the direct provider certification
required by GUG-357.

`artifact_signing_readback_complete=true` records the separate live
Signer/S3/Code Signing Config checks for apply/no-touch/reconcile. Complete
readback requires it, but it does not expand the materializer's post-create
provider-certification scope or authorize broker invocation.

For masked CloudFormation parameters, completion additionally requires the
validated ledger-to-plan binding and exact client-request token in stack events
from the materializer's own create attempt. A visible projection digest is a
drift guard, not independent proof for an arbitrary pre-existing stack.

The SDK has zero retries. Any uncertainty after the ledger is consumed removes
create from the allowed next actions. The only continuation is read-only
`reconcile` using the consumed ledger.

## Evidence classification

| Evidence | What it proves | What it does not prove |
|---|---|---|
| Passing focused tests | Repository contract against synthetic/injected clients | AWS permissions, service role, stack absence or deployment |
| GUG-215 source manifest/archive | Exact deterministic unsigned Signer input | Signed output, deployability or execution authorization |
| Private plan | Deterministic projection of reviewed local inputs and source-to-signed-destination contract | Owner authenticity, live signing evidence or execution authorization |
| GUG-357 authorization | One short-lived reviewed intent for one plan/caller/action and exact signing-evidence binding | Successful API call or final state |
| Create response | AWS accepted or ambiguously processed a request | Terminal stack/resource correctness |
| Exact materializer receipt | CloudFormation stack metadata, original template, resource identities/statuses and request token matched at that read | Direct Lambda/IAM/DynamoDB/Logs/URL/account-wide certification, production readiness or independent human approval |

`two_human_status` remains `NOT_PROVEN` throughout the ADR-050 route.

## Repository validation

The focused offline gate is:

```bash
make platform-authority-retirement-entrypoint-check
```

The aggregate platform-authority gate also includes it:

```bash
make platform-authority-bootstrap-check
make docs-check
make security-check
```

These commands must run without AWS credentials and do not authorize or perform
live materialization.
