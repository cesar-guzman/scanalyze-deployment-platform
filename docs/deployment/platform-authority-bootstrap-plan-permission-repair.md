# Platform-Authority Bootstrap Plan permission repair

## Purpose

This contract defines a dedicated server-side policy-enforcement point (PEP)
for repairing one exact predecessor of the normal
`ScanalyzeAuthorityBootstrapPlan` Identity Center permission set. It does not
grant a person `sso-admin` or IAM mutation authority and it does not reuse the
GUG-221 collector repair.

Repository implementation is AWS-free evidence. It does not authorize a
deployment or repair. Production remains **NO-GO**.

## Current implementation boundary

This iteration provides the infrastructure, IAM, state-machine, concrete AWS
runtime and deterministic artifact contracts. The reviewed Lambda entrypoint
installs zero-retry `IdentityCenterPort` and `LedgerPort` adapters only inside
the source-closed package. The local CLI remains offline and can never install
or call those ports.

Before its first SDK client, the runtime validates every static ARN, ID,
digest, tag, window, reviewed policy digest, runtime-lock field and exact SDK
version. It then proves the local and assumed caller identities; all six local
and delegated IAM roles; the three published functions and aliases; the full
invocation graph; the retained DynamoDB/KMS controls; and the complete
Identity Center state. The effective-IAM guard reruns immediately before each
protected effect. Provider output, pagination and public errors are bounded and
fail closed.

This executable repository path is still not deployment or repair authority.
No package has been signed or staged from this unmerged worktree, no stack has
been deployed and production remains **NO-GO**.

The checked-in handler contract already rejects exhausted invocations: Plan
and reconcile require more than 60,000 milliseconds remaining at entry, while
repair requires more than 480,000 milliseconds before it can consume a Plan.
The immutable intent window separately requires at least 660 seconds before
the Plan claim and more than 75 seconds before either SSO write.
The concrete adapter adds operation-level guards of more than 75,000
milliseconds before either SSO mutation and more than 60,000 milliseconds
before every provider read or provisioning poll. Equality with a threshold is
insufficient and fails closed.

## Eligible predecessor

The desired policy is always rendered from reviewed source by
`tooling/platform_authority_bootstrap.py`. The only eligible live predecessor
is that same canonical document with the single
`ListOnlyExactBootstrapChangeSets` statement removed. All other statements,
the exact Change Set name, resource bindings and explicit denials must match.

The surrounding permission-set state must also be exact:

The normal Plan tags and the temporary invoker tags are separate contracts.
`ExpectedPlanPermissionSetTagsJson` describes only the already-existing Plan
permission set. The invoker tags are derived exclusively from the reviewed
source commit and the fixed CloudFormation values; they are never copied from
or required to equal the Plan tags.

| Surface | Required state |
|---|---|
| Permission set | `ScanalyzeAuthorityBootstrapPlan`, active instance, reviewed metadata and tags |
| Inline policy | Exact canonical predecessor only |
| Attachments and boundary | None |
| Assignment | One immutable `USER` assignment to account ending `7644` |
| Provisioned accounts | Only account ending `7644` |
| Pending operations | None |
| Generated IAM role | Exactly one expected `AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_*` role |
| Role policy | Existing predecessor through `AwsSSOInlinePolicy`, no additional authority |

Denied access, incomplete pagination, a repeated token, stale evidence or a
similar name never proves this state. Any second difference is blocked rather
than repaired.

## Two-account control plane

### Management account ending `1433`

The delegation stack owns:

- one mutation service role trusted only by the exact authority-account repair
  execution role;
- one readback service role trusted only by the exact authority-account Plan
  and reconcile roles;
- the invoke-only `ScanalyzeBootstrapPlanRepair` permission set; and
- when explicitly enabled, one reviewed temporary `USER` assignment targeting
  only the authority account.

The required `RepairInvokerAssignmentEnabled` parameter has no default.
`true` creates the temporary assignment for the separately authorized execution
window; `false` removes only that assignment while retaining the permission set
and both service roles. The same reviewed template bytes support both states.

The mutation role may read the exact Identity Center state and perform only:

```text
sso:PutInlinePolicyToPermissionSet
sso:ProvisionPermissionSet
```

It cannot create or update permission-set metadata, create/delete assignments,
attach policies, set boundaries, tag resources, delete resources, mutate IAM
or chain roles. The readback role has the same bounded inventory surface and no
write action.

### Authority account ending `7644`

The PEP stack owns:

- retained KMS and DynamoDB evidence resources;
- separate Plan, repair, reconcile and invocation-inspector roles;
- three private code-signed Lambda functions;
- one published numeric version and qualified alias per mode;
- zero-retry alias-level asynchronous configuration; and
- retained log groups.

Each function also has an explicit `AWS::Lambda::RuntimeManagementConfig` with
`UpdateRuntimeOn=FunctionUpdate`. CloudFormation establishes that control
before publishing the numeric version. The runtime reads the qualified
version's management state and rejects anything other than the exact
`FunctionUpdate` mode and active runtime-version ARN. The reviewed package can
therefore use the managed boto3/botocore libraries without being silently
moved to a newer managed runtime between function updates.

The Plan role can create, but not update, one ledger record. The repair role can
conditionally update, but not create, that record. Reconcile is read-only. The
table resource policy denies unsupported writes and all unrelated principals.

There are no function URLs, resource-based public permissions, event sources,
destinations, alias routing weights or unqualified invocation grants.

## Human boundary

The temporary human permission set invokes only:

```text
...:function:scanalyze-platform-authority-plan-policy-plan:plan-v1
...:function:scanalyze-platform-authority-plan-policy-repair:repair-v1
...:function:scanalyze-platform-authority-plan-policy-reconcile:reconcile-v1
```

Every invocation event must be exactly `{}`. A payload cannot select an
account, Region, permission set, policy, Change Set, source commit, repair ID,
mode or time window. Alias, published version and immutable deployment
configuration supply those bindings.

The invoker has no `sso:*`, `identitystore:*`, `iam:*`, `sts:AssumeRole`,
DynamoDB write or Lambda-management permission.

## Durable execution contract

The private intent binds:

- reviewed source commit and source bundle;
- desired-policy template bytes;
- predecessor, target and one-statement delta digests;
- Change Set name digest;
- exact instance, store, permission set, generated role and assignment digests;
- exact provisioned-account and invocation-authority graph digests; and
- account, Region, repair ID and maximum fifteen-minute window.

The separately materialized `ImmutableConfigurationDigest` is a canonical
projection of every operator-controlled runtime binding plus the fixed function
and resource identities. It is injected as `IMMU_CONFIG_DIGEST`, independently
recomputed before any SDK client is created, and included in every
`AWS::Lambda::Version` description. Any private parameter change with unchanged
ZIP bytes therefore replaces the numeric versions and moves the aliases only to
the newly bound configuration; an unverified digest is rejected.

Lambda environment size is the exact UTF-8 sum of every configured key and
value. The template constrains descriptions and tag JSON to printable ASCII,
caps tag JSON at 1,024 bytes and caps every variable-length parameter. The
worst-case reconcile environment is 3,940 bytes, below Lambda's 4,096-byte
limit, and the runtime repeats the exact calculation before SDK use.

The state machine records a conditional transition before each effect:

| Status | Stage | Attempted | Completed |
|---|---|---:|---:|
| `PLAN_VERIFIED` | `PLAN_STATE_VERIFIED` | 0 | 0 |
| `CLAIMED` | `BEFORE_FIRST_EFFECT` | 0 | 0 |
| `ATTEMPTING_1` | `BEFORE_PUT_INLINE_POLICY` | 0 | 0 |
| `COMPLETED_1` | `AFTER_PUT_INLINE_POLICY` | 1 | 1 |
| `ATTEMPTING_2` | `BEFORE_PROVISION_PERMISSION_SET` | 1 | 1 |
| `COMPLETED_2` | `AFTER_PROVISION_PERMISSION_SET` | 2 | 2 |
| `REPAIR_VERIFIED` | `FINAL_READBACK_VERIFIED` | 2 | 2 |

SDK retries are disabled. The provider re-observes exact state immediately
before dispatch, performs one call, and requires exact readback before
advancing. Provisioning polling is bounded by the immutable window and reserves
time for final readback.

Any ambiguity after dispatch becomes one of the terminal uncertain states only
when its CAS and readback are proven, and then requires read-only
reconciliation. If that seal is unproven, no public receipt is emitted and the
attempting state blocks replay. No uncertain record can re-enter repair.
Only the explicit state-machine edges are valid; a status skip, cross-effect
uncertainty stage, repeated claim timestamp or regressive update timestamp is
rejected before a replacement ledger is sealed.

## Public receipt boundary

The public receipt exposes only:

- source and contract digests;
- scalar effect counters;
- mutation-attribution classification;
- required next action;
- `retry_permitted=false`; and
- `production_status=NO-GO`.

It cannot contain raw account IDs, ARNs, principals, role/session names,
permission-set names, Change Set names, policy documents, request IDs, private
paths or provider payloads. Private intent, ledger and provider evidence remain
outside Git in owner-only custody. The semantic validator and JSON Schema share
the same exact closed field set, so a resealed record with an extra field is
still rejected.

## Deployment prerequisites

Before either stack is created, all of these facts must be reviewed and fresh:

1. exact merged source commit and successful required CI;
2. deterministic signed Lambda artifact and exact S3 version/checksum;
3. exact Identity Center instance/store and Plan permission-set ARN;
4. immutable `USER` ID and existing assignment;
5. current predecessor and target policy digests;
6. generated Plan role and SAML provider;
7. KMS mode/key/context and code-signing configuration;
8. exact Change Set names, creator and executor identities;
9. collision-free names for both stacks and all retained resources; and
10. a separately authorized bootstrap route scoped to the two exact templates,
    accounts and `us-east-1`.

The authority PEP template is larger than CloudFormation's 51,200-byte direct
`TemplateBody` limit. Its exact reviewed bytes must therefore be staged in the
approved versioned artifact bucket and referenced by an exact `TemplateURL` (or
by an equivalent reviewed packaging step that produces that versioned URL).
The upload is a separate authorized S3 mutation. A CLI convenience command may
not choose a different bucket, overwrite a key or obscure the final template
version/checksum.

None of the currently described narrow profiles can bootstrap both stacks by
itself. Broad administrator access is not an implicit fallback. Selecting a
temporary executor or a service-managed StackSet is a separate, explicit
change decision.

## Validation boundary

Repository validation must include:

```bash
make platform-authority-bootstrap-plan-repair-check
make platform-authority-bootstrap-check
make docs-check
```

After merge, the artifact must be built from the exact clean commit into a new
owner-only directory outside the repository:

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-package.py \
  --source-commit "$SOURCE_COMMIT" \
  --expected-boto3-version "$EXPECTED_BOTO3_VERSION" \
  --expected-botocore-version "$EXPECTED_BOTOCORE_VERSION" \
  --output-directory "$PRIVATE_OUTPUT_DIRECTORY"
```

The package builder reads exact Git-object bytes, emits a deterministic
`ZIP_STORED` archive, embeds a non-circular source-set digest and runtime lock,
and proves that all three handlers import from the ZIP with the repository and
`PYTHONPATH` absent. A separate read-only signed-artifact command rebuilds the
same protected main commit, makes STS its first signed call and produces the
exact CloudFormation artifact tuple from one completed Signer job and immutable
S3 version/checksum readbacks. It also reads the signing certificate with
`acm:GetCertificate` and checks the profile, job and certificate with
`signer:GetRevocationStatus` (`signer-data` is the SDK service name). The public
constructor derives certificate and template digests itself; the private
trusted-readback constructor is test-only and never accepts operator assertions
as deployment evidence. Uploading or starting Signer remains a separately
authorized mutation.

These commands use synthetic fixtures and injected providers only. Success
means the reviewed repository contract is internally consistent. It does not
mean that AWS state was read, that a stack was deployed, that the Plan policy
was repaired or that production is ready.

## Rollback

Before deployment, revert the repository change.

After stack deployment but before repair, update the same management stack with
the same reviewed template bytes and all other parameter values unchanged,
changing only `RepairInvokerAssignmentEnabled` from `true` to `false`. The
reviewed Change Set must remove only `RepairInvokerAssignment`; its execution
must read back `RepairInvokerAssignmentMode=false`, zero temporary assignments
and no relevant pending deletion. Retain the permission set, service roles and
all evidence resources. After either SSO effect is attempted, do not issue a
second write or delete the ledger. Invoke reconcile, preserve the exact
provider/CloudTrail evidence and obtain a new reviewed recovery decision.

```text
AWS_CALLS=0
AWS_MUTATIONS=0
RUNTIME_PORTS_BOUND_IN_SOURCE_CLOSED_PACKAGE
SIGNED_ARTIFACT_NOT_BUILT
LIVE_RUN_NOT_EXECUTED
NOT_DEPLOYED
PRODUCTION_NO_GO
```

## References

- [ADR-057](../../ADR/ADR-057-bootstrap-plan-permission-repair-pep.md)
- [Operations runbook](../operations/platform-authority-bootstrap-plan-permission-repair.md)
- [Canonical bootstrap contract](platform-authority-bootstrap.md)
- [GUG-221 separated repair](platform-authority-lambda-audit-provisioning-repair.md)
