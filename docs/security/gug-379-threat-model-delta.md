# GUG-379 threat-model delta: greenfield ACCOUNT_READY v2

Production: **NO-GO**. This delta covers repository-only candidate code and
synthetic offline tests. It does not claim AWS resource existence, account
vending, backend initialization, deployment, or control effectiveness.

## Trust boundary

`AccountVendingProvider` owns the baseline template and future live execution.
`tooling.account_ready_v2_materializer` is the sole repository producer. It may
transform only exact closed bootstrap readback bound to an approved deployment
target and independent anchor. `account-ready-gate` is a consumer with no state
or apply authority. Backend configuration remains derived by the existing
authorizer after every contract, target, anchor, and lock check passes.

`SharedServicesAccountId` is a privileged AccountVending input because a future
executor using `CAPABILITY_NAMED_IAM` selects the principals trusted by seven
terminal roles. Its format and inequality with the destination account do not
prove provenance. This repository exposes no direct-operator execution route;
GUG-123 must bind the exact AccountVending-authorized shared-services identity
before any live claim. The content-addressed child URL similarly requires a
trusted publication record proving that its exact non-null S3 `VersionId`
contains the reviewed SHA-addressed bytes.

## Threats and controls

| Threat | Repository control | Required negative evidence |
|---|---|---|
| v1 or placeholder baseline is treated as ready | DAG, catalog, verifier, and producer accept ACCOUNT_READY v2 only; no conversion or defaults | v1, empty, placeholder, unknown, and partial inputs fail with stable sanitized codes |
| forged target selects another destination | target v2 canonical digest must equal its independent exact-version anchor | altered target, self-anchored target, stale version, and digest mismatch fail |
| cross-customer/account/region/environment contract | tuple equality across target, readback, roles, resource tags, buckets, and KMS | each foreign tuple member and ARN partition/account mismatch fails |
| partial bootstrap emits success | closed readback requires exactly four buckets, three KMS keys, eight roles, and six exact controls | missing, duplicated, unexpected, or false control fails; no output survives |
| caller injects backend coordinates | producer does not accept backend input; authorizer derives bucket, KMS, and canonical DAG key | caller bucket/key/KMS/DynamoDB fields and unsafe templates fail |
| deterministic global bucket name is preclaimed | matching names are validation invariants, never ownership proof; bootstrap and materializer fail closed and never adopt an existing bucket | arbitrary same-partition buckets fail; collision remains an availability risk requiring a separately reviewed naming revision |
| shared-services and destination boundaries collapse | CloudFormation rejects `SharedServicesAccountId == AWS::AccountId`; terminal trusts require the exact external orchestrator role | same-account template parameters fail before resource creation |
| caller chooses an unanchored shared-services principal | `SharedServicesAccountId` is accepted only as privileged AccountVending input; format and inequality are explicitly insufficient evidence | no direct-operator template route exists; exact identity provenance remains `NOT_PROVEN` until GUG-123 |
| generic Apply establishes durable IAM authority | generic/global and CI/CD Apply cannot create roles or policies, attach policies, or change trust; three exact preprovisioned roles are each bound 1:1 to CodeBuild, CodePipeline, or ECS tasks in both role policy and boundary | IAM create/policy/trust mutations, wildcard PassRole, and Cartesian role/service pairings are absent; workload IAM provisioning remains downstream |
| Terraform assumes generic Apply can still create workload IAM | `modules/global/iam.tf` and `modules/cicd/main.tf` are explicitly incompatible with the narrowed policy, and parent/child do not create their three PassRole targets | AccountVending/preprovision migration or module redesign is required; global/CI/CD execution is `DEPLOYMENT_NO_GO` and IAM create must not be restored |
| IdentityApply persists cross-principal authority through IAM, a service resource policy, Cognito configuration, or alarm actions | IdentityApply and its boundary exclude IAM trust/policy mutation; direct policy mutators including `lambda:AddPermission`, `sqs:CreateQueue`, `sqs:SetQueueAttributes`, `dynamodb:PutResourcePolicy`, and `cloudwatch:PutMetricAlarm`; Cognito mutation including `cognito-idp:CreateUserPoolClient`; and secret-returning `cognito-idp:DescribeUserPoolClient`; its Lambda mutations name only the two reviewed functions and its two `iam:PassRole` grants bind each exact role 1:1 to its exact Lambda ARN | AccountVending must preprovision reviewed Lambda-only trusts/policies, exact Cognito pool/clients/scopes/groups/invocation permissions, queues/redrive policies, and alarm definitions/actions; current identity Terraform still declares those resources, so identity execution is `DEPLOYMENT_NO_GO` |
| terminal Apply persists access through a caller-selected KMS key policy | neither generic Apply nor IdentityApply may call `kms:CreateKey` or `kms:PutKeyPolicy`; AccountVending must preprovision workload keys with reviewed policies, while terminal roles may only inspect, rotate, tag, bind aliases, use, or create AWS-service grants on already owned keys | both actions are absent from effective policies and permissions boundaries; no caller-supplied key policy can become durable authority |
| current Terraform KMS creation and tags are treated as compatible | identity, data-foundation, and CI/CD currently create their own keys with incompatible tag sets, while the terminal policies require preprovisioned keys with the closed reviewed ownership set | AccountVending and caller modules must migrate before live use; identity/data-foundation/CI/CD remain `DEPLOYMENT_NO_GO` and policies are not widened |
| IdentityApply retags a resource to cross a binding | user-pool and KMS tag writes require existing ownership, exact replacement ownership values, and closed TagKeys; binding-tag removal is denied; Lambda, DynamoDB, SQS, alarm, and log-group grants are deployment-name ARN-bound rather than ResourceTag-authorized | foreign/untagged user pools and keys, extra tags, changed binding values, and removal of customer/deployment/layer tags fail |
| account-level service upper bound is mistaken for layer isolation | remaining generic Apply service mutations with `Resource: "*"` are explicitly classified as upper bounds only; dedicated-account scope and a session layer tag do not bind an individual target resource | per-layer session policies plus service-specific ARN/resource-tag bindings remain downstream; no terminal-role assumption or live claim is authorized before negative evidence |
| a uniform 15-minute claim obscures the protected live session contract | the protected orchestrator and Plan/Apply terminal callers request exactly 3,600 seconds, matching their role maximum; the GitHub job has a separate 45-minute ceiling; human Diagnostic/StateRecovery callers remain independently controlled at exactly 900 seconds | caller enforcement and negative live evidence remain downstream; `MaxSessionDuration` alone does not prove the path-specific request |
| recovery approval is self-asserted | StateRecovery policy is materialized as future authority but its current child trust is deny-only | no Allow trust or assumable path exists until GUG-123 proves an independent issuer |
| deleting the parent is mistaken for IAM revocation | the nested terminal-role stack is intentionally `Retain`, so its roles and seven live Allow trusts survive parent delete or replacement | decommission must revoke trusts first, prove no usable sessions remain, and retire the child only through a separately reviewed forward operation |
| raw saved plan becomes immutable long-lived evidence | `plan-execution/` is isolated in the dedicated versioned, non-Object-Lock `tf-plan` bucket; the bucket and policy are retained on stack deletion/replacement, while current and noncurrent plan versions expire by one-day lifecycle; the evidence bucket is COMPLIANCE WORM for sanitized output only | the controller exposes no saved-plan delete API, Apply can only read the exact version, and lifecycle cleanup still requires connected proof; plan paths never use the state or evidence bucket |
| raw saved-plan bytes are copied into an evidence key | every role that can read saved-plan/state versions lacks evidence-bucket PutObject and evidence-key encrypt/data-key authority; Apply boundaries explicitly deny both | a separate future evidence publisher requires sanitizer, schema, and live negative proof; path separation alone never proves content is sanitized |
| two layers or destinations collide on state | canonical templates are unique and bound to deployment/region/layer | cross-deployment, cross-region, cross-layer, traversal, and duplicate-template cases fail |
| execution lock is stolen or rewritten | execution lock is independent of `.tflock`, digest-bound, versioned, and CAS-governed | held, released, expired, future, foreign-owner, stale-version, and altered-digest cases fail |
| stale lock expiry becomes authority | expiry always stops; recovery remains separately reviewed and never force-unlocks automatically | automatic takeover and force-unlock paths are absent |
| dry-run leaks operational coordinates | manifest contains only opaque digests, versions, control status, and `NOT_PROVEN_LIVE`; errors use stable codes | stdout/stderr and manifest contain no account ID, ARN, bucket, key, KMS, target, anchor, or lock payload |
| local output is replaced through symlink/race | exclusive create, owner-only `0600`, outside-repository path, no symlink, and cleanup on failure | existing file, symlink, repository path, permissive mode, and interrupted write fail closed |
| passing tests is reported as live readiness | evidence class is embedded in the sanitized manifest and docs | repository candidate remains `NOT_PROVEN_LIVE`; AWS/deployment/production remain NO-GO |
| residual log group is adopted as greenfield | resource is explicitly excluded from template, materializer, and evidence | no import, tag, mutation, deletion, or ownership claim exists |

## Determinism and no-change

Canonical JSON uses sorted keys, fixed separators, and no ambient timestamps.
The materializer accepts the authoritative `provisioned_at` value from exact
readback; it does not call a clock. Identical inputs built at fresh output paths
must yield byte-identical contract, digest, and sanitized manifest. Any
pre-existing output path stops rather than becoming implicit authority.

Deterministic output proves integrity and reproducibility only. Hashes do not
prove writer identity, AWS provenance, resource controls, or terminal state.

## Review and live boundary

GUG-379 requires exactly one independent exact-final-head approval from
`@guguce-google`. Owner/self-approval is not a substitute. This issue-scoped
code-review rule does not reduce the separate human authorization, security
review, dual stale-lock review, saved-plan approval, AWS readback, rollback,
health, or production gates for a future live operation.

No AWS client, Terraform remote operation, CloudFormation mutation, artifact
publication, deployment, customer data, or production action is authorized by
this delta.
