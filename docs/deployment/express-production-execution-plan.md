# Express production deployment preparation

## Destination and execution status

The owner confirmed a **new production environment** in account `905418363887`,
Region `us-east-1`, for initial use on Friday, 11 September 2026. The destination
decision is complete. Preserve the existing DEV application and unrelated
resources in this account.

This packet identifies the implementation and input gaps before producing an
executable plan. **No production request, saved Terraform plan, CloudFormation
change set, release publication, or deployment has been executed.** A target
confirmation is not an approval of unspecified IAM changes or resource creation.
Do not feed this document or synthetic test fixtures to a deployment controller.

## Verified account context

Read-only inspection used `905418363887_AWSReadOnlyAccess` with explicit
`AWS_REGION=us-east-1`, after STS confirmed account `905418363887`.

| Read-only source | Observed metadata | Deployment implication |
| --- | --- | --- |
| ECS `list-clusters` | No clusters returned | No existing Scanalyze ECS runtime identified |
| ELBv2 `describe-load-balancers` | No load balancers returned | No existing Scanalyze ALB identified |
| API Gateway v2 `get-apis` | `bcm-dev-zendesk-integration-api` | Existing integration; do not modify it |
| CloudFront `list-distributions` | Empty aggregate response without `DistributionList` | No distribution observed; does not establish DEV domain ownership |
| ECR `describe-repositories` | `base-images/python`, immutable tags | Base repository exists; no application repository identified |
| EC2 `describe-vpcs` | Non-default `vpc-0ab1fb179f5093b07`, `10.0.0.0/16` | Preserve it; select a reviewed non-overlapping CIDR for the new VPC |
| CloudFormation `list-stacks`, selected terminal statuses | `bcm-dev-ec2-rds-scheduler`, `CREATE_COMPLETE` | Preserve it; this was not an exhaustive stack-status inventory |
| Route53 `list-hosted-zones` | Empty list | DNS ownership/delegation must be resolved outside this observation |
| SSM `describe-parameters`, `/scanalyze` prefix | Access denied | Existing Scanalyze parameter inventory is unknown, not absent |

No objects, document contents, logs, database rows, credentials, or Terraform
state were read. No cloud resource was changed. The same read-only role cannot
be presumed to publish, provision, or administer identities.

## Inputs still needed for a bound deployment

| Input | Source or decision | Current status |
| --- | --- | --- |
| Account, Region, environment | Owner | Confirmed: `905418363887`, `us-east-1`, `production`, new environment |
| Customer/deployment/request identifiers | Authoritative provisioning record | No applicable new-production record observed; existing environment files identify the previous sandbox |
| Public hostname and passkey relying-party domain | Owner and DNS operator | Hostname choice requested; no DNS write authorized |
| DNS zone/account and ACM ownership | Read-only DNS/certificate metadata under the correct profile | Unresolved; cannot infer ownership from the public DEV URL |
| Internal ALB TLS name and certificate | Bound platform contract | Must match API Gateway TLS verification; public SPA hostname alone does not supply this contract |
| Network CIDR/AZs and capacity | New-environment design | Unresolved; account already has `10.0.0.0/16` |
| Shared-services account and terminal-role artifact | Platform authority/release publication | Baseline requires a different account plus exact version-pinned template URL |
| Immutable release | Reviewed commit, seven service images, two Lambda ZIPs, frontend package | No complete published release established for this candidate |
| Execution identity and resource plan | Reviewed narrowly scoped deployment mechanism | Not supplied; read-only inspection profile is not an apply identity |
| Operator, initial users, volume and cost limits | Initial production operating agreement | Unresolved; real processing and NAT/ECS/ALB carry costs |

## Code and deployment blockers

| Area | Exact source | Required change/evidence |
| --- | --- | --- |
| AWS physical names | `modules/container-platform/alb.tf`, `modules/data-foundation/s3.tf`, `modules/services/ecs_services.tf` | Local patch preserves full deployment identity while fitting ALB/TG limits and S3 character rules. Review replacement implications before any existing deployment uses it. |
| API forwarding | `modules/services/alb_routing.tf`, `modules/services/ecs_services.tf` | Local patch adds explicit per-service forwarding and orders ECS after listener association. Bind `alb_service_routes` to the actual ingest service and correct application port; unmatched routes retain the platform's default 404. |
| Private integration TLS/path | `modules/edge-identity/api_gateway.tf`, root inputs | Local patch requires `alb_tls_server_name`, enables TLS/SNI and preserves `$request.path`; both enter the reviewed deployment digest. Verify the name against the platform listener's certificate before use. |
| Human result access | `app/auth.py`, `app/main.py`, identity trigger, identity/service gates | Implement the [human access plan](express-production-human-access.md), including trusted recent passkey evidence, current membership, durable authorization audit and session renewal. |
| Runtime permissions | `modules/global/iam.tf` and resource-owning layers | Workload roles currently have a permissions boundary but no observed attached workload grants. Review exact per-service grants, resource ARNs and required boundary changes; a boundary alone grants no access. |
| Listener-rule execution permissions | `bootstrap/cfn-terminal-roles.yaml`, service mutation policy and boundary | Current allowlists include target groups but omit `elasticloadbalancing:CreateRule`. The new routing resource needs reviewed lifecycle permissions and a newly published, pinned baseline artifact before execution. No baseline IAM was changed locally. |
| Runtime inputs | `modules/services/locals.tf`, task definitions, root contract projections | Bind tables, ledger, document bucket, FIFO queues, stage settings and immutable images to this deployment. Do not reuse legacy/demo tfvars. |
| Root input transport | `scripts/deployment/validate-contract-resolution.py`, `scripts/deployment/contract_projection.py`, contract catalog, `scripts/deployment/terraform-layer.sh` | Current projection does not emit `alb_service_routes` or `alb_tls_server_name`; it also does not supply `service_definitions`. A reviewed release-bound input path is still required. |
| Browser storage access | `modules/data-foundation/s3.tf`, edge ownership | Add exact-origin document PUT CORS, define ownership of the private frontend asset bucket, and bind its OAC policy and immutable asset publication. |
| Startup observability | `modules/services/ecs_services.tf`, `modules/addons/cloudwatch.tf`, `deployment/layers.yaml` | ECS references log groups created later in addons. Resolve ownership/order before starting tasks; retain bounded metadata-only logs and alarm routing. |
| Production materialization | `schemas/deployment-request.schema.json`, `tooling/account_ready_v2_materializer.py` | Git-safe request/materializer are nonproduction-only. The separate provisioning schema accepting `production` does not make this execution route production-capable. |
| Release publication | `.github/workflows/microservices-build.yml`, `tooling/nonprod_live_orchestrator.py` | Legacy publisher explicitly denies publication and the live engine accepts nonproduction only. Prepare a separately reviewed production execution route and artifact authorization; do not relabel production as dev or remove the denial without replacing its authority chain. |
| Acceptance harness | `scripts/validation/document-journey-smoke.py` and its implementation | Current harness is DEV/STAGING-only. Production needs its own reviewed execution binding plus real human-browser and isolation evidence. |

The baseline in `bootstrap/cfn-tf-state-backend.yaml` accepts `production`, but
requires a different `SharedServicesAccountId` and the exact content-addressed,
version-pinned terminal-role template URL. Its ability to create baseline
resources does not close the application release or account-ready gaps.

### New routing inputs and certificate binding

The services root requires `alb_service_routes`, keyed by the exact service name
in `service_definitions`. Every service with a port must have one association;
workers without ports must have none. Each route declares a unique integer
priority and reviewed `/api/v1/...` or `/api/v2/...` path patterns. For the ingest
API, the intended patterns are `/api/v1/*` and `/api/v2/*`. Neither the listener
nor the API Gateway integration strips the `/api` prefix.

The edge-identity root requires `alb_tls_server_name`: a certificate hostname,
not an AWS ALB DNS name inferred from its output or the SPA name assumed to be
equivalent. Read back the listener's certificate ARN and its validated names;
bind that evidence to the platform input `internal_certificate_arn` and this
exact TLS name. The existing closed `platform/v2` schema does not publish these
TLS fields; the patch does not silently add new contract properties.

The new rule also needs the exact ALB listener to be deployment-bound. Obtain
`alb_listener_arn` from the verified upstream platform contract; the production
input transport must reject overrides of it. Scope the reviewed baseline
permissions to that listener and its deployment. Merely accepting a syntactically
valid listener ARN in a Terraform input does not establish ownership in this
shared account.

The browser sends `/api/v2/...` through CloudFront unchanged. API Gateway uses
HTTPS:443 over VPC Link; ALB forwards HTTP to the selected container port. The
ingest image sets `PORT=80`. Use port 80 or explicitly set matching `PORT` in the
reviewed task environment; changing `service_definitions.port` alone does not
change the process listener. Target health checks use `/health` directly without
adding a public health route.

These required inputs must be added to the reviewed deployment input package.
Existing callers need the same input migration before their next plan; do not
assume the new module signature is compatible with older tfvars. Local provider
tests cannot supply certificate ownership or a production request binding.

The current contract-only renderer does not transport either new input. Changing
module signatures is not sufficient to make `terraform-layer.sh` executable for
this release. The production route must validate and transport these reviewed
non-contract inputs together with service definitions, without widening the
closed upstream schemas or accepting arbitrary overrides of ownership fields.

The customer/deployment registry is also a real prerequisite. The existing
`environments/cicd.tfvars` labels its deployment as BCM Corp Sandbox; the legacy
service tfvars use `bcm-corp`, not an authoritative canonical customer record.
The required sources are documented in
`docs/deployment/platform-authority-bootstrap.md` and
`docs/deployment/registry-account-baseline-backend-locking.md`. Neither a local
AWS profile nor a request payload is a substitute for that registration.

## Preparation and eventual execution sequence

1. Complete the public/domain, authority and operating inputs above. Validate
   them against the actual production schema/route selected for implementation.
2. Finish and review the bounded code/IaC changes. Run repository ownership,
   schema, Terraform/provider, application and negative authorization tests.
3. Produce a complete immutable release with digests, signatures, provenance,
   scan results and the matching frontend configuration schema. Record its exact
   commit. The current uncommitted worktree is not a release identifier.
4. Prepare the baseline change set and each layer's saved plan under the exact
   target-bound execution identity. Present sanitized resource changes, IAM
   effects, replacement/deletion counts, estimated cost and rollback behavior.
   Existing unrelated resources must have no changes. Review authority must be
   tied to the exact artifacts and plans, not just this prose packet.
5. After approval of the concrete action, execute the authoritative layer DAG:
   account-ready-gate → global → network → platform → data-foundation → cicd →
   artifact-publication → identity-control-plane → services → edge-identity →
   edge → addons → synthetic-validation. Resolve the known log-group startup
   dependency before execution; do not silently reorder contract owners.
6. Read back resources and deployment contracts. Confirm healthy ECS tasks and
   target groups, trusted JWT routing, exact configuration/API version, private
   storage access, FIFO/DLQ behavior, alarms and artifact digests. A successful
   Terraform command is not evidence of a working document journey.
7. Exercise synthetic human sign-in, upload, processing, full result access,
   uncertain-operation recovery, duplicate prevention and foreign-tenant denial.
   Test passkey expiry and session refresh beyond five minutes. Open the first
   production cohort only after these connected checks pass.

## Review and rollback boundaries

Local changes live only in `codex/friday-express-production`, based on
`914ffad7c1aca0e3443be7d6a965c80a935afb17`. The dirty primary checkout remains
untouched. No commit, push, review request, merge or cloud mutation was performed.

Physical resource naming changes are intended for the **new** deployment. Applying
them to a managed existing deployment can force ALB, target-group or bucket
replacement. Inspect a real plan before use; never migrate document storage by
accepting an unreviewed replacement.

Rollback for an uncommitted local patch is to discard only the named changes in
the isolated worktree. A first production deployment has no known-good previous
release: close admission and preserve data, queues, memberships and evidence for
reconciliation. Do not destroy shared resources or erase documents as rollback.

The Friday date remains at risk until human access, publication and the bound
infrastructure route are complete. See the [release record](../operations/express-production-release.md)
for actual validation results; none of the pending steps above is a claim of
completion.
