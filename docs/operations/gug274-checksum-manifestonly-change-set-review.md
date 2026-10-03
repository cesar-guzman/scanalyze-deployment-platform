# GUG-274 ManifestOnly Change Set review packet

Status: **CHANGE SET CREATED AND RECONCILED / NOT EXECUTED / IAM ROLES ABSENT**.

The owner approved the entry ARN for the proposed plan and the exact CREATE-only
request for account `042360977644`, Region `us-east-1`. That request was sent
once and its readback is recorded below. This approval does not authorize
ExecuteChangeSet or installation of the proposed IAM trust and permissions.
The [roles proposal](gug274-checksum-role-proposal.md) remains the policy and
staging design. Its source is local and uncommitted; no issue assignment,
publication or CI completion is established by this packet.

## Evidence supplied by the owner

The owner ran the bounded discovery and validation commands:

- STS Account projection returned `042360977644`.
- IAM discovery returned one administrator-role candidate with the exact
  identity below. The owner subsequently selected it for this proposed plan
  and expressly authorized creation of this Change Set only.
- The reader profile returned AccessDenied for ValidateTemplate. The owner
  subsequently used the explicitly configured administrator profile for that
  single validation, with STS and the exact template-digest check first.
- ValidateTemplate returned `CAPABILITY_NAMED_IAM` and the nine expected
  parameters: mandatory entry ARN/digest, default `ManifestOnly`, and six empty
  Batch bindings. This is template validation, not a Change Set, permission
  simulation, resource creation, provider compatibility or production proof.

| Reviewed request element | Exact submitted value |
|---|---|
| Account / Region | `042360977644` / `us-east-1` |
| Caller profile | `042360977644_AWSAdministratorAccess` |
| Stack name | `scanalyze-gug274-checksum-roles` |
| Change Set name | `manifestonly-33c96276a16b-a79151b0` |
| Change Set type | `CREATE` |
| Client token | `gug274-manifestonly-33c96276a16b-a79151b0-v1` |
| Capability | `CAPABILITY_NAMED_IAM` |
| Template | `bootstrap/cfn-platform-authority-gug274-checksum-roles.yaml` |
| Template SHA-256 | `33c96276a16bf8149e374d943707fc198fabfa71feea07915b01e7c07ce5e556` |
| Parameters | `bootstrap/gug274-checksum-manifestonly.parameters.json` |
| Parameters SHA-256 | `f0d2e708f031e8cc7a6c4b0743c1ba396cec16d5c8a6c05e0d0386519491c2e3` |
| Entry ARN selected for this plan | `arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AWSAdministratorAccess_a79151b0e0ce8501` |
| Entry RoleId observed | `AROAQTXHJHDWHXEXV2CIG` |
| Role created only upon later execution | `arn:aws:iam::042360977644:role/scanalyze/platform-authority/ScanalyzeGug274ChecksumManifestWriter` |

The entry is a shared Identity Center role, not a grant exclusively to a named
person. On 2026-10-01 the owner explicitly accepted that shared entry scope,
including the assigned group. Its direct role ARN as Principal would include
callers who can use that role, subject to effective policy limits. Individual
membership/identity, session controls and effective access remain unverified.
No SSO permission set
or assignment is changed here; do not infer a new assignment from this packet.

The owner subsequently ran the separate read-only assignment-count helper
using `839393571433_AWSAdministratorAccess` in `us-east-1`. Its supplied output
confirmed caller account `839393571433`, target account `042360977644`, and
permission set `AWSAdministratorAccess`, with **one direct USER assignment and
one GROUP assignment**. `PrimaryRegionObserved` was null and is not treated as
confirmation of the primary Region. Group membership and the owner's directory
identity were not resolved. Two assignments do not establish two distinct
users, nor do they establish exclusive access by the owner. The owner's
subsequent acceptance closes the shared-entry scope decision; exclusive access
by a single named person is not claimed or required by this selected scope.

Preparation of a separate membership-count helper was rejected by PreToolUse
as a sensitive read/output attempt. No second helper was created and no
membership API was executed. Do not retry that rejected operation through
another tool or delegate. A human can review the assigned group locally and
supply only its member count and confirmation of the intended access scope;
names, emails and directory IDs are not needed in this packet. This evidence
does not grant execution permission or prove effective AssumeRole access.
The owner's scope decision likewise does not authorize ExecuteChangeSet,
source publication, job permissions, custody activation or production writes.

## Creation preflight and remaining execution gates

1. The local branch/worktree and reviewed template/parameter bytes were
   reconciled for CREATE-only review. Issue assignment, source publication and
   CI remain pending; an earlier PR's CI approval does not cover these files.
2. The owner expressly approved this selected ARN in the proposed plan and
   this exact CreateChangeSet request. Execution was explicitly excluded.
3. Fresh STS confirmed the caller account, expected assumed-role prefix and
   expected RoleId prefix. GetRole confirmed the exact ARN/RoleId and no
   permissions boundary. The owner accepted the shared entry and group scope;
   effective access and session controls still require review before
   provisioning. No exclusive-owner identity proof is asserted.
4. The proposed stack and both fixed writer-role names were confirmed absent.
   An AccessDenied, timeout or another error is not absence. If a stack, retained
   role or pending Change Set already exists, reconcile it; do not adopt,
   import, replace, switch to UPDATE or delete it automatically.
5. Template and parameter-file digests matched the reviewed bytes before
   sending. The six Batch bindings were empty. Stop for review if any
   entry, digest, parameter, resource, condition, policy or template byte changes.
6. Keep operator job permissions, custody provisioning/capture, artifact
   acceptance and production execution outside this request.

CreateChangeSet of type CREATE is a cloud write: AWS creates the Change Set
and a stack record in `REVIEW_IN_PROGRESS`. It does not provision the IAM role
until ExecuteChangeSet. If its send has an unknown outcome, inspect the same
named request before another send; do not change tokens or targets as a retry.
[AWS CreateChangeSet](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html)

## Exact creation command sent once

**Historical request, already sent successfully. Do not rerun it.**
The request used the Scanalyze checksum worktree. The parameter file contains
explicit empty Batch values; no artifact or manifest version was invented.

```sh
AWS_MAX_ATTEMPTS=1 aws cloudformation create-change-set \
  --profile 042360977644_AWSAdministratorAccess \
  --region us-east-1 \
  --stack-name scanalyze-gug274-checksum-roles \
  --change-set-name manifestonly-33c96276a16b-a79151b0 \
  --change-set-type CREATE \
  --client-token gug274-manifestonly-33c96276a16b-a79151b0-v1 \
  --template-body file://bootstrap/cfn-platform-authority-gug274-checksum-roles.yaml \
  --parameters file://bootstrap/gug274-checksum-manifestonly.parameters.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-include-nested-stacks \
  --no-import-existing-resources \
  --description 'Review only: GUG-274 ManifestOnly; one proposed manifest role, no Batch job or custody activation.' \
  --query '{ChangeSetArn:Id,StackArn:StackId}' \
  --output json --no-cli-pager
```

No `--role-arn` is supplied: this proposal must target a new stack, without a
previous associated CloudFormation service role. No new service role is
invented. Capabilities and ResourceTypes are mutually exclusive in this API;
the local exact-template/digest and Change Set inspection supply the resource
restriction, not an incompatible `--resource-types` flag. No import, macro,
auto-deploy or ExecuteChangeSet command is included.
[AWS CLI CreateChangeSet](https://docs.aws.amazon.com/cli/latest/reference/cloudformation/create-change-set.html)

## Observed creation readback

The single authorized request returned these exact bindings:

| Binding | Observed value |
|---|---|
| ChangeSetArn | `arn:aws:cloudformation:us-east-1:042360977644:changeSet/manifestonly-33c96276a16b-a79151b0/e1b915b3-2652-45d3-b04b-7f0a9d471c67` |
| StackArn | `arn:aws:cloudformation:us-east-1:042360977644:stack/scanalyze-gug274-checksum-roles/aed26cf0-bd52-11f1-bcd9-12b5fa5627e3` |
| Change Set status / execution status | `CREATE_COMPLETE` / `AVAILABLE` |
| Stack status | `REVIEW_IN_PROGRESS` |
| Stack service role / outputs | `RoleARN=null` / zero outputs |
| Resource changes | Exactly one `Add`: `ManifestWriterRole`, `AWS::IAM::Role` |
| Parameters | All nine match the reviewed file; six Batch bindings empty |
| Capabilities | Exactly `CAPABILITY_NAMED_IAM` |
| Nested stacks / existing-resource import | Both false; parent/root Change Set IDs null |
| Original template bytes | SHA-256 `33c96276a16bf8149e374d943707fc198fabfa71feea07915b01e7c07ce5e556`, matching local bytes |
| Original template semantics | Full parsed template equals the local template |
| Post-creation IAM readback | Both fixed writer-role names return `NoSuchEntity` |

DescribeChangeSet, DescribeStacks and GetTemplate were bound to the exact
returned ARNs. All resource changes were retained through normal CLI
pagination. GetTemplate used stage `Original`; its returned UTF-8 template
body was hashed directly and compared in memory, without printing its body
or hashing reformatted CLI output. Only bounded public metadata was emitted;
no credentials, raw session identity, stack events or audit logs were read.

The Change Set type is established by the submitted `CREATE` request;
DescribeChangeSet does not return that field. The absence of a service role
was checked through DescribeStacks, not inferred from DescribeChangeSet.
No ExecuteChangeSet request was sent. Creation produced the Change Set and
stack review record; no IAM role was provisioned.

## Readback contract and later execution approval

Capture the returned ChangeSetArn and StackArn and bind them to the request.
Review DescribeChangeSet by the exact returned ARN. `CREATE_COMPLETE` and
`ExecutionStatus=AVAILABLE` mean the proposal is available, not applied.
Stop on FAILED, a missing/ambiguous ARN, extra changes, or unexpected targets.

Expected resource change: exactly one Add for logical ID `ManifestWriterRole`,
type `AWS::IAM::Role`. The submitted template fixes its RoleName to
`ScanalyzeGug274ChecksumManifestWriter`; a deployed physical resource ID is
not expected in this initial creation proposal.
The six empty bindings must keep `BatchWriterRole` absent. Review the uploaded
original template, exact parameters and conditional result; the summary of
resource changes alone does not prove the trust or permissions.

Confirm the stack remains `REVIEW_IN_PROGRESS`, no IAM resource is deployed,
no execution has occurred and no service role has been attached. Use bounded
projections; avoid stack events or broad logging that might expose identities.
Creation can produce validation events despite not deploying resources.

Only after that readback prepare a separate execution request bound to the
exact stack/change-set ARNs and reviewed template/parameters. It must identify
the IAM role/trust/policies it will create, its actor, retention and rollback.
No role execution approval or deployment command is given by this packet.
[AWS CLI DescribeChangeSet](https://docs.aws.amazon.com/cli/latest/reference/cloudformation/describe-change-set.html)

## Validation and rollback boundaries

The roles template's existing 87 focused tests cover the local phase and policy
contracts and were not repeated. This new JSON passed a focused offline check
against the actual template's parameter constraints, phase Rules and resource
Conditions: nine distinct parameter keys, exact validated template digest and
selected entry, six empty Batch values, and only ManifestWriterRole active.
Both new files passed whitespace checks. These are local contract checks,
not IAM simulation. The authorized live Change Set evaluated the actual
parameter set and produced the conditional one-role proposal above. No IAM
simulation, AssumeRole canary, resource provisioning or production deployment
has run as part of this packet. Unchanged local test suites were not repeated.

The cloud Change Set and stack review record now exist. Local source removal
does not remove them. Change Set/stack-record cleanup needs its own reviewed
exact-target command and authorization;
do not delete a stack or a retained role automatically. ExecuteChangeSet is
not a cleanup operation. Retained IAM roles would survive some removals after
deployment; stage downgrade is not revocation.
