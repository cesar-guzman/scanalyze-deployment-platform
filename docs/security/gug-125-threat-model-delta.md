# GUG-125 Threat-Model Delta: Non-Production Live Engine

## Assets and boundaries

Protected assets are the target binding, registry and ACCOUNT_READY anchors,
backend/lock, state lineage/serial, resolved contracts, signed release,
Terraform plan binary and version, plan metadata, independent approval,
execution ledger, post-apply state, producer contract, health receipt, and
reconciliation evidence.

Trust boundaries exist between GitHub and the shared-services orchestrator,
orchestrator and each destination terminal role, Plan and Apply, raw plan store
and durable metadata, Apply and Terraform state, producer and consumer layers,
and deployment A and deployment B.

The shared-services boundary refers only to a dedicated or formally designated
Scanalyze platform-authority account. Reusing a destination account or an
unrelated corporate shared-services account is denied.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Re-plan after review | Apply consumes only exact downloaded saved binary | Deny missing/mismatched readback |
| Substitute plan object | SHA-256, size, derived key, required version ID, create-only KMS write | Deny any mismatch |
| Reuse a plan | CAS ledger and `attempt_count` maximum one | Deny non-APPROVED or consumed ledger |
| Apply after state/contract/release drift | Complete plan bindings plus immediate state and authority revalidation | Expire plan and require new approval |
| Self-approve | Immutable initiator/approver IDs must differ; approval binds exact plan and Environment configuration | Deny approval |
| Terminal role forges approval state | Ledger writer is shared-services orchestrator; plan store and ledger adapters are disjoint | AWS/IAM or adapter denial |
| Caller supplies its own ledger-writer ARN | Adapter requires the exact `ScanalyzeOrchestrator-<deployment_id>` role in the independently bound shared-services account | Adapter denial before ledger access |
| Generic role enters identity layer | GUG-123 role/layer contract and distinct identity Plan/Apply roles | Deny terminal session |
| KMS-encrypted plan cannot be safely handed off | Minimum Plan encrypt and Apply decrypt plus exact version read | Stop before apply |
| Lost apply response triggers retry | `UNCERTAIN` blocks resume; read-only reconciliation required | Reconcile or forward recovery |
| Failed health ignored | HEALTHY transition consumes exact receipt; downstream requires ledger, plan, and receipt | Stop DAG |
| Forged health/reconciliation receipt | Receipt binds plan digest and source ledger digest/version; ledger stores outcome receipt digest | Deny transition/downstream |
| Dry-run obtains cloud identity | Ambient AWS variables denied; no profile option; CI has no OIDC | Fail dry-run |
| Production selected | Schema accepts only sandbox/dev/staging | Deny before cloud I/O |
| Sensitive evidence leaks | mode-0600 files outside repo; sanitized stdout; repository security gate | Stop and contain |
| Cross-deployment plan/ledger use | exact customer/deployment/account/region/change/layer comparisons and leading-key policy | Deny without enumeration |

## Residual risk and live blockers

Offline tests cannot prove GitHub Environment protection, OIDC token claims,
IAM policy evaluation, S3/KMS/versioning configuration, DynamoDB conditional
semantics, Terraform provider behavior, runtime health, failure recovery,
two-account isolation, or cleanup. The current destination sessions were not
valid and the required separate shared-services platform authority was not
available. Destination accounts cannot be promoted to platform authority by
convenience because that breaks the accepted GUG-123 separation.

The generic Apply permission policy remains broad because it is an upstream
terminal-role design. GUG-125 relies on the exact GUG-123 trust/session-policy
boundary and must validate it live before use; any ability to mutate outside
the principal-tagged deployment is a P0/P1 blocker.

No live validation or production-readiness claim is made. Production remains
**NO-GO**.

## Platform-authority factory delta

The new `platform-authority` module/root adds a dedicated machine control-plane
boundary. It contains only registry/ledger control metadata and immutable
release material; customer documents, PII, Terraform state for customer
deployments, queues, ECS workloads, Cognito tenants, and extracted payloads
remain in the destination accounts.

| Threat | Factory control | Failure behavior |
|---|---|---|
| Authority is a customer destination | Root and module require authority account to differ from every destination | Plan denied |
| One role controls multiple deployments | One exact role per deployment with immutable ownership tags; caller contract requests 15 minutes under the AWS one-hour role ceiling | Binding mismatch denied |
| Wildcard GitHub trust | Exact `StringEquals` audience and Environment subject; wildcard input invalid | Configuration denied |
| Repository namespace is renamed, transferred, or recycled | Exact `repository_owner_id` and `repository_id` claims are required in addition to `sub` and `aud`; legacy and immutable subject formats remain exact | STS trust evaluation denies the token |
| Cross-tenant registry/ledger access | DynamoDB leading key equals the role's `deployment_id` | IAM denial |
| Control-data loss | KMS encryption, PITR, deletion protection, S3 versioning, no force destroy | Routine deletion denied |
| Release bucket silently shared or unreadable under SSE-KMS | Bucket name and exact authority KMS key ARN are reviewed root outputs substituted into the runtime policy | Missing or malformed binding denied |
| Human bootstrap becomes standing machine authority | IAM Identity Center is bootstrap/recovery only; GitHub OIDC is normal machine authority; no static access key | Activation stopped |
| Root bootstraps its own trust | State backend and Identity Center assignment must pre-exist under an independent procedure | Initialization stopped |

Live proof remains blocked until a third authority account/profile, backend,
protected GitHub Environments, destination `ACCOUNT_READY` records, and explicit
non-production mutation authorization are independently available.
