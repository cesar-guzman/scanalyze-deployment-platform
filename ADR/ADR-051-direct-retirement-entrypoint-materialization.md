# ADR-051: Direct Retirement Entrypoint Materialization

- **Status:** Proposed repository contract; not deployed
- **Date:** 2026-08-11
- **Implementation issue:** GUG-363
- **Live authorization issue:** GUG-357
- **Amends:** ADR-050 only for materializing its dedicated non-production PEP entrypoint
- **Does not amend:** the GUG-215 retirement effect, two-human normal mode, or production controls
- **AWS live validation:** None
- **Production:** **NO-GO**

## Context

ADR-050 defines the only bounded single-operator path for retiring the one exact
GUG-215 retained Change Set. It deliberately does not authorize deployment of
the broker, ledger, roles, aliases or Function URLs that enforce that path.
Using the retained review-shell Change Set to create its own retirement PEP
would make the target authorize its remover. Creating another Change Set would
also introduce a second mutable review object and another retirement problem.

GUG-363 therefore needs one narrow entrypoint materialization mechanism that is
separate from the retained shell, binds the complete reviewed template, unsigned
source package and externally signed deployment artifact, and cannot update or
delete infrastructure. The current one-person roster remains explicit: this
path is not independent approval and cannot be described as such.

## Decision

### 1. Use one dedicated stack and one direct create request

The only eligible target is the dedicated non-production stack
`scanalyze-platform-authority-gug357-retirement-entrypoint` in the fixed
platform-authority account and `us-east-1`. It is never the retained shell
`scanalyze-platform-authority-state-backend`.

The materializer exposes exactly one possible AWS mutation:

```text
cloudformation:CreateStack
```

It never calls `CreateChangeSet`, `ExecuteChangeSet`, `DeleteChangeSet`,
`UpdateStack`, `DeleteStack`, Terraform, S3 upload/copy, an AWS Signer mutation,
Lambda invocation or the GUG-215 ledger. Both the unsigned Signer source and the
signed destination must already exist as exact immutable S3 object versions.

The request fixes `CAPABILITY_NAMED_IAM`, `OnFailure=DO_NOTHING`, termination
protection, a deterministic client-request token, the complete template body,
the exact ordered parameter projection and the fixed CloudFormation service
role ARN. The stack name, Region, account and service role are code-owned
constants, not CLI, environment, intent or authorization choices.

### 2. CloudFormation uses a pre-existing fixed service role

The human operator does not receive direct IAM, Lambda, DynamoDB or Logs
provider authority. `CreateStack` must carry the fixed service role
`scanalyze-platform-authority-gug363-cfn-materializer` in the authority account,
and readback must prove that the created stack retains that exact `RoleARN`.

GUG-363 does not create, update or repair this role and does not grant
`iam:PassRole`. Before a GUG-357 execution checkpoint can be issued, separate
read-only evidence must prove all of the following:

- the exact role exists and trusts only the CloudFormation service principal
  under the reviewed account and Region boundary;
- its inline and attached policies, permissions boundary and tags exactly match
  the independently reviewed least-privilege contract for the twenty-one
  expected single-operator resources;
- the operator has only the reviewed CloudFormation create/read authority for
  the dedicated stack and `iam:PassRole` for that one role, with no provider
  mutation authority; and
- the role ARN is bound into the reviewed plan and fresh execution
  authorization; that authorization also binds the exact
  `service_role_evidence_digest`, `operator_authority_evidence_digest`,
  `live_before_state_digest` and overall `live_checkpoint_digest`.

The existing GUG-357 temporary audit permission-set package does not grant the
IAM role/policy reads needed to prove those facts. Missing that separately
authorized evidence is a hard stop, not an invitation to broaden the audit
policy or use an administrator profile.

### 3. Require an external signed-artifact handoff

The deterministic ZIP emitted by the GUG-215 packager is explicitly an
**unsigned AWS Signer source package**. Its archive digest, size and
`lambda_code_sha256` describe those unsigned source bytes only. That ZIP is not
a deployable Lambda artifact, and none of its S3 coordinates or byte digests may
be projected into the CloudFormation `Code` or `CodeSha256` parameters.

Before GUG-363 may materialize anything, a separate authorized workflow must:

1. place that exact unsigned ZIP at one private, versioned, KMS-encrypted Signer
   source location;
2. complete one AWS Signer job owned and invoked by the authority account using
   platform `AWSLambda-SHA384-ECDSA` and the exact reviewed signing-profile
   version, with no overrides or signing parameters; the named profile must
   remain active on the same platform, while its current version may rotate;
3. preserve the job's exact source and signed-destination identity and checksum
   evidence; and
4. place the signed output at one different private, versioned destination key
   in the same bucket under the same KMS key.

Only the exact signed destination object, its signed byte length and its signed
Lambda `CodeSha256` may project into `BrokerArtifactBucket`,
`BrokerArtifactKey`, `BrokerArtifactVersion` and
`BrokerArtifactCodeSha256`. The source/destination distinction is a hard
replacement of the earlier single-artifact interpretation; the two objects are
not interchangeable and `latest` is never accepted.

The pre-existing Lambda Code Signing Config must have policy `Enforce` and an
exact `AllowedPublishers.SigningProfileVersionArns` set containing only the
reviewed profile-version ARN. Binding the config ARN alone is insufficient.
The plan and fresh execution authorization bind the complete signing contract
and its separately reviewed live evidence.

At runtime, the first AWS call is `sts:GetCallerIdentity`, followed by the first
dedicated-stack `DescribeStacks`. Before the local attempt ledger can be
consumed, every `apply` performs this exact read-only sequence:
`DescribeSigningJob`, `GetSigningProfile`, `GetBucketVersioning`, unsigned
`HeadObject`/`GetObject`, signed `ListObjectVersions`/`HeadObject`/`GetObject`,
`GetCodeSigningConfig`, and a second `DescribeStacks`. The authorization and
signature windows are then revalidated before the ledger is persisted.

The full signing preflight occurs even when the first stack read sees a target,
so a no-touch result also carries fresh signing evidence. Because CloudFormation
masks private parameter values, a pre-existing target without a consumed
GUG-363 ledger remains ambiguous and can never receive a complete receipt from
this control-plane-only path. A target that disappears or changes identity
between the two reads is ambiguous and blocks all mutation. Only two absence
observations can reach the ledger claim.

Those calls fail closed unless the Signer job is successful and exactly binds
the reviewed source, destination and historical profile version; both S3
objects match their distinct byte digests, sizes, encryption and versions;
any provider SHA-256 furnished by S3 is consistent when it represents the full
object; bucket versioning is
enabled; the signed object is the one latest version at its exact key with no
delete marker; the two ZIPs contain exactly the same member names and member
payloads after safe in-memory parsing; and the config still has exact `Enforce`
and `AllowedPublishers` values. GUG-363 never uploads
or copies an object, starts or cancels a signing job, or creates/updates a
signing profile or Code Signing Config. Object bodies are read only to recompute
their exact digests and compare ZIP semantics without filesystem extraction;
they are neither logged nor persisted. Duplicate/unsafe entries, encrypted
members, symlinks, traversal names and size-limit violations fail closed.

Because CloudFormation masks `NoEcho` values in stack readback, the request
also carries a visible, domain-separated `PrivateParameterProjectionSha256`
commitment over every other ordered parameter. Readback requires that exact
commitment, the deterministic request token and the unmasked parameter values.
Masked values are accepted only after the validated local ledger and exact
request-token event establish the causal GUG-363 create chain; asterisks alone
never prove the underlying private values.

### 4. Build a deterministic private plan offline

`plan` performs no AWS call. It accepts only owner-only inputs outside the
repository, verifies a clean exact Git commit/tree, reads the CloudFormation
template from that Git object, and proves the worktree bytes are identical. It
then binds:

- the exact template digest and complete template body;
- the deterministic GUG-215 unsigned-source manifest and archive digest;
- the distinct exact versioned Signer source and signed-destination S3
  locations, checksums, sizes and encryption bindings;
- the completed Signer job, exact signing-profile version, Code Signing Config
  with `Enforce` and exact `AllowedPublishers`, and their evidence binding;
- the signed destination Lambda `CodeSha256` projected to CloudFormation and the
  manually pinned runtime;
- the ADR-050 owner authorization and exception digests;
- all private Identity Center, identity-proof, policy and assignment bindings;
- the fixed target and CloudFormation service-role ARN; and
- the exact twenty-one-resource single-operator graph, including the dedicated
  retained CloudWatch Logs group.

The plan is self-digested for integrity but states
`deployment_authorized = false`. Recomputing its digest does not authenticate
an owner or authorize AWS use.

### 5. Require a fresh external GUG-357 execution authorization

`apply` requires all of these independent inputs and controls:

- the exact private plan and its separately supplied expected digest;
- the separately supplied expected `artifact_signing_contract_digest`, which
  must match both the plan and authorization;
- a fresh private GUG-357 execution authorization and separately supplied
  expected authorization digest;
- `deployment_authorized = true` only in that authorization;
- `SINGLE_OPERATOR_NONPROD_EXCEPTION`, `two_human_status = NOT_PROVEN`,
  `independent_approval_present = false` and `production = false`;
- the exact caller ARN digest, fixed target, fixed service role and one allowed
  action;
- the exact GUG-357 live-checkpoint, before-state, service-role and operator
  authority evidence digests;
- the complete source-to-signed-destination contract and its fresh Signer, S3
  and Code Signing Config evidence;
- a validity window no longer than fifteen minutes;
- an authorization expiry no later than the bound signature expiry;
- an explicit `--allow-create-stack` acknowledgement; and
- an explicitly named approved profile and exact Region, with static credential
  and transport override environment variables rejected.

Neither this ADR, a passing CI run, the CLI flag, the plan nor the exception
artifact supplies that live authorization. Until GUG-357 records it for the
exact reviewed digests, `apply` is **NO-GO**.

### 6. Consume the attempt before the write and never retry

Before `CreateStack`, the materializer performs fresh caller and target checks,
read-only verification of the exact Signer job, unsigned source, signed
destination and Code Signing Config, revalidates the active authorization,
reserves a create-only owner-local execution ledger, and marks the sole attempt
consumed. The AWS SDK has zero retries. None of those preflight checks can
produce, upload, sign or repair an artifact.

After the sole call, CloudFormation readback is ordered as `DescribeStacks`,
`GetTemplate`, `ListStackResources` and `DescribeStackEvents`. `reconcile`
repeats the complete read-only preflight and the remaining CloudFormation
readback but never reaches the ledger-claim or create operations.

If the stack already exists, the materializer does not touch it. Without the
validated ledger-to-plan-to-event-token chain from its own attempted create,
masked parameters force an ambiguous result even when the visible structure
matches. It otherwise classifies in-progress target, partial target, drift or
ambiguity through read-only calls. After any attempted create, a missing,
malformed, timed-out or ambiguous response is permanently
`UNCERTAIN_RECONCILE_ONLY`; no second create is permitted.

`reconcile` requires the consumed ledger and performs read-only observation. It
cannot reset the ledger, call `CreateStack`, update, roll back or delete the
stack.

The owner-local ledger is an additional one-workstation guard, not a distributed
AWS authorization system. CloudFormation stack-name uniqueness, the deterministic
client token, exact GUG-357 authorization and operator governance remain part
of the boundary. Concurrent execution from another host is a residual risk and
must be excluded operationally.

### 7. Make the retained log boundary explicit

The template creates
`/aws/lambda/scanalyze-platform-authority-gug215-retirement` with 365-day
retention, CloudFormation retain policies and AWS-owned encryption at rest. The
Lambda uses JSON platform logging with application level `ERROR` and system
level `WARN`.

The broker source still emits no application log statements and accepts no
request data. Its execution role may only create streams and put events in that
exact log group; log-group creation, deletion, retention, KMS association and
resource-policy mutation are denied. Logs are operational evidence, not
authorization and not proof of a successful create or retirement.

## Readback and completion

A successful API response is not completion. Exact readback must prove:

1. the dedicated full stack ID, fixed `RoleARN`, template digest and parameter
   projection;
2. `CREATE_COMPLETE`, termination protection and no drifted stack identity;
3. exactly the twenty-one expected resources and no normal-mode alias family;
4. the exact retained log group and Lambda `LoggingConfig`;
5. the exact signed destination artifact and signed code SHA, completed Signer
   source/destination/profile binding, Code Signing Config `Enforce` policy and
   exact `AllowedPublishers`, runtime pin, role, aliases, Function URLs and
   permissions; and
6. a sanitized create-only receipt bound to the plan, authorization, resource
   set and observed stack.

The GUG-363 receipt deliberately labels its own scope
`CLOUDFORMATION_CONTROL_PLANE_ONLY`, keeps
`provider_certification_complete=false` and requires subsequent GUG-357
certification. `READBACK_VERIFIED` means that the stack metadata, original
template, resource identities/statuses and request token matched; it does not
claim that direct Lambda, IAM, DynamoDB, Logs, Function URL or account-wide
authority readback has completed. GUG-363 may record the pre-create signing
handoff checks described above as `artifact_signing_readback_complete=true` for
apply no-touch/create and reconcile results. A complete receipt requires that
value, but it does not widen the receipt's post-create scope. GUG-357 still owns the
post-create provider checks in items 4–5 and the remaining provider-level
certification before any broker invocation.

Repository tests use injected clients only. They do not prove the external
service role, `iam:PassRole`, live stack absence, AWS behavior or deployment.

## Rollback and recovery

Before a live attempt, rollback is a repository revert and invalidation of the
private authorization; it has no AWS effect. After the attempt is consumed,
rollback never means a second create, `UpdateStack` or `DeleteStack`.

`OnFailure=DO_NOTHING` intentionally preserves partial state for inspection.
Any partial or failed stack, retained log group, role, table, alias or Function
URL requires read-only inventory and a separate destructive recovery issue with
exact authorization. GUG-363 contains no cleanup path.

## Consequences

- The retained Change Set does not bootstrap or authorize its own retirement
  PEP.
- The operator does not receive direct provider mutation permissions, but the
  fixed external service role and exact `iam:PassRole` contract become critical
  preconditions and residual trusted boundaries.
- Artifact production is also an external prerequisite: the GUG-215 ZIP remains
  unsigned/non-deployable, while only a separately evidenced signed destination
  is eligible for CloudFormation.
- A direct one-shot `CreateStack` avoids creating another retained Change Set.
- Partial resources are preserved rather than automatically deleted.
- The repository now contains a materialization mechanism, not evidence that it
  was run.
- GUG-357 live authorization and exact service-role proof remain required.
- Independent approval remains **NOT_PROVEN** and production remains **NO-GO**.
