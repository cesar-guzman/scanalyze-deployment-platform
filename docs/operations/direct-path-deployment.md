# Direct-path deployment of one non-production environment (GUG-543)

The direct path deploys Scanalyze into a new, dedicated AWS account without the
factory-v2 orchestrator. For each Terraform root the owner renders a backend
file and a tfvars file with `scripts/deployment/direct-path.py`, runs
`terraform init`, `plan -out`, reviews the plan, applies it and saves
`terraform output -json`. There is no target registry, ACCOUNT_READY v2 record,
execution lock, platform authority, PEP, ledger, broker or SSM contract
publication. `scripts/deployment/scanalyze-deploy.sh` is not used.

> **Status (2026-11-16): offline only.** The kit, this runbook and the example
> config were validated with synthetic inputs: `tests/test_gug543_direct_path_kit.py`
> and a mock-provider `terraform test` of every root
> (`scripts/deployment/direct-path-selfcheck.sh`). Nothing was planned or applied
> against AWS. Production stays **NO-GO**; the kit refuses `environment: production`.
>
> **Blocked on this branch.** `roots/identity-control-plane` and
> `roots/edge-identity` cannot plan because of four precondition bugs (B1-B4 in
> [Known gaps](#known-gaps)). Their tfvars are otherwise accepted. Until those
> are fixed, layers 1-5 (global to cicd) and addons can be applied; services,
> edge-identity and edge cannot. A working document pipeline also needs PR #135
> (B5).

## Files

| File | Purpose |
|---|---|
| `scripts/deployment/direct-path.py` | `layers`, `backend <layer>`, `tfvars <layer>`. Python 3.11, stdlib plus PyYAML. No AWS calls; never overwrites a rendered file. |
| `deployment/direct-path/deployment.example.yaml` | Every value the owner provides. Synthetic placeholders only. |
| `scripts/deployment/direct-path-selfcheck.sh` | Optional local check (not CI): renders all layers from the example and fixtures and runs each root with `terraform test` and mock providers. |
| `tests/test_gug543_direct_path_kit.py`, `tests/fixtures/direct_path/` | CI tests and synthetic `terraform output -json` fixtures. |
| PR #136 (not on this branch yet) | `docs/operations/direct-path-publish.md`, `scripts/deployment/publish-direct-release.sh`, `scripts/deployment/render-direct-service-definitions.py`, `scripts/deployment/publish-frontend.sh`, and the `browser_origins` input of `roots/data-foundation`. |
| PR #135 (not on this branch yet) | The `runtime_wiring` input of `roots/services` and service-owned log groups. |

The kit is forward-compatible with both PRs: it emits `browser_origins` and
`runtime_wiring` only when the target root's `variables.tf` declares them.

## How each layer's inputs are sourced

Contract variables are projected the way the orchestrator projects them: the
bindings in `deployment/contract-catalog.v1.json`, the envelope fields of
`scripts/deployment/contract_projection.py` (`contract_id`, `schema_version`,
`customer_id`, `deployment_id`, `account_id`, `region`,
`release_manifest_digest`, `contract_digest`), and the digest rule of
`scripts/deployment/publish-contract.py`: SHA-256 over the canonical JSON of
the upstream `contract_payload.outputs` (`tooling/validate_digest.py`).
`tfvars` prints the source of every variable it writes.

Every layer also receives, when its root declares them, `customer_id`,
`deployment_id`, `account_id`, `region`, `environment`, `release_version` and
`domain_name` from the config, and the self-attested `release_manifest_digest`.

| Layer | Layer-specific config | From saved upstream outputs | Self-attested, derived or fixed |
|---|---|---|---|
| global | optional `global.*` (Bedrock model IDs, SSM prefix) | none | ACCOUNT_READY digest pair and schema `2`; `aws_partition=aws` |
| network | none | global/v1 digest and schema | none |
| platform | `internal_certificate_arn` | network/v2 `vpc_id`, `private_subnet_ids`, `vpc_cidr_block`, digest | none |
| data-foundation | none | platform/v2 digest | `browser_origins = ["https://<domain_name>"]`, only when declared (PR #136) |
| cicd | `microservices` | platform/v2 `ecs_cluster_name`; data-foundation/v2 digest and id | `enable_codecommit=false`, `enable_codepipeline=false` |
| identity-control-plane | `identity.lambda_artifact`, `identity.m2m_bindings`, optional `identity.alarm_actions` | `global_contract` and its digest | `release_manifest_contract` and `m2m_registry_contract` with their digests; `policy_version`/`policy_digest` from `policies/authorization/`; `control_processor_enabled=true`; `aws_partition=aws` |
| addons | none | none | edge/v2 digest pair and schema `2` (edge is applied later) |
| services | `services.inputs_file` | global execution and task roles, network, platform, data-foundation digest and id, identity contract and digest; cicd ECR URLs for the image check | `runtime_wiring` from the data-foundation outputs and `environment`, only when declared (PR #135) |
| edge-identity | `alb_tls_server_name`, `api_access_log_group_arn`, `edge_identity.*` | network, platform, services and identity contracts with digests | `cors_allowed_origins = ["https://<domain_name>"]` |
| edge | `route53_zone_id`, optional `edge.frontend_features` | edge-identity/v2 API, Cognito and policy values, digest and id | `frontend_bucket_domain_name = scanalyze-<account>-frontend.s3.<region>.amazonaws.com` |

**Self-attested values.** None is signed or externally verified; every root
precondition only checks that the values are consistent with each other.

- **Release manifest digest.** SHA-256 over the canonical JSON of customer,
  deployment, account, region, environment and release version. `tfvars global`
  records it in `<outputs-dir>/direct-path-release.json`. Every later layer
  refuses to render if the config no longer produces the recorded value. A new
  `release_version` therefore needs a fresh outputs directory and a re-render
  from global.
- **`release_manifest_contract`.** Built from `identity.lambda_artifact`, with
  `contract_digest` computed like `tooling/identity_adapters.py`: the canonical
  JSON of the contract without `contract_digest`.
- **`m2m_registry_contract`.** Built from `identity.m2m_bindings` with the same
  digest rule. No identity-contract/v2 document exists on the direct path.
- **ACCOUNT_READY (global) and edge/v2 (addons).** A digest over a fixed
  description of the deployment. Neither root reads a value from those
  contracts.

## Prerequisites

Everything below is created by the owner in the new account, from the owner's
shell. Values go into the config. Run these after `aws sts get-caller-identity`
shows the dedicated account. Region is `us-east-1` (see G4).

1. **Tools.** Terraform 1.14.6 (the roots require `>= 1.14.6, < 1.15.0`), Python
   3.11 with PyYAML, AWS CLI v2, `jq`, Docker with `linux/amd64` builds (images).
   Use a clean checkout of the reviewed commit.
2. **State bucket** (`state_bucket`):

   ```bash
   aws s3api create-bucket --bucket "$STATE_BUCKET" --region us-east-1
   aws s3api put-bucket-versioning --bucket "$STATE_BUCKET" --versioning-configuration Status=Enabled
   aws s3api put-public-access-block --bucket "$STATE_BUCKET" --public-access-block-configuration \
     BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   ```

   Locking uses the S3 lock file (`use_lockfile = true`); no DynamoDB table.
   Set `state_kms_key_id` if the bucket uses SSE-KMS.
3. **Route 53 public hosted zone** (`route53_zone_id`) that serves `domain_name`
   and is delegated from its parent. The edge layer writes the A/AAAA alias and
   the ACM validation records into it, with the same credentials.
4. **Internal ALB certificate** (`internal_certificate_arn`,
   `alb_tls_server_name`). A public ACM certificate in the deployment region for
   the exact `alb_tls_server_name`, DNS-validated and **ISSUED** before platform:

   ```bash
   aws acm request-certificate --region us-east-1 --domain-name "$ALB_TLS_SERVER_NAME" --validation-method DNS
   aws acm describe-certificate --certificate-arn "$CERT_ARN" \
     --query 'Certificate.DomainValidationOptions[0].ResourceRecord'   # add this CNAME to the zone
   aws acm wait certificate-validated --certificate-arn "$CERT_ARN"
   ```

   API Gateway reaches the ALB by listener ARN and verifies the certificate
   against `alb_tls_server_name`; no DNS record for that name is needed beyond
   validation.
5. **API access log group** (`api_access_log_group_arn`, without `:*`):

   ```bash
   aws logs create-log-group --log-group-name "/scanalyze/$DEPLOYMENT_ID/api-access"
   aws logs put-retention-policy --log-group-name "/scanalyze/$DEPLOYMENT_ID/api-access" --retention-in-days 90
   ```

6. **Frontend bucket** `scanalyze-<account_id>-frontend` in the deployment
   region, public access blocked, default SSE-S3 encryption. The edge layer
   writes `<deployment_id>/config.json` into it (`modules/edge/runtime_config.tf:118-132`),
   so it must exist before edge. Its CloudFront read policy is a gap (G2).
7. **Identity Lambda artifact** (`identity.lambda_artifact`). One zip serves both
   handlers (`identity_control_plane.entrypoints.pre_token_handler` and
   `control_processor_handler`, python3.12, arm64). The package is pure Python
   and uses the runtime's boto3. Use a versioned bucket in the deployment
   region:

   ```bash
   ART_BUCKET="scanalyze-$ACCOUNT_ID-identity-artifacts"
   aws s3api create-bucket --bucket "$ART_BUCKET" --region us-east-1
   aws s3api put-bucket-versioning --bucket "$ART_BUCKET" --versioning-configuration Status=Enabled
   aws s3api put-public-access-block --bucket "$ART_BUCKET" --public-access-block-configuration \
     BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   (cd "$REPO/backend/lambdas/scanalyze-identity-control-plane/src" &&
     zip -X -r "$WORK/identity-control-plane.zip" identity_control_plane -x '*/__pycache__/*')
   SHA="$(shasum -a 256 "$WORK/identity-control-plane.zip" | cut -d' ' -f1)"
   aws s3api put-object --bucket "$ART_BUCKET" --key "identity-control-plane/sha256-$SHA.zip" \
     --body "$WORK/identity-control-plane.zip" --query VersionId --output text
   ```

   Put the bucket, the key and the printed VersionId in the config. The kit
   derives the base64 SHA-256 (`source_code_hash`) from the key; see B1.
8. **Bedrock model access** in the region for the module defaults
   `amazon.nova-lite-v1:0` (classifier) and
   `anthropic.claude-3-haiku-20240307-v1:0` (bank, personal, gov). Check they
   are listed and active, and complete the Anthropic use-case form if the
   console asks for it:

   ```bash
   aws bedrock list-foundation-models --region us-east-1 \
     --query "modelSummaries[?modelId=='amazon.nova-lite-v1:0' || modelId=='anthropic.claude-3-haiku-20240307-v1:0'].[modelId,modelLifecycle.status]"
   ```

9. **ECR and images.** After cicd, publish the seven images with the PR #136
   runbook `docs/operations/direct-path-publish.md`
   (`publish-direct-release.sh`, which needs a base image mirrored into a
   `<dep-ulid>/scanalyze/base` repository you create), then render the services
   inputs with `render-direct-service-definitions.py` (step 3 below).
10. **Merge PR #135 and PR #136 first** if possible: see B5, G1 and G2.

## 1. Work directory and config

Keep everything outside the repository, owner-only:

```bash
REPO=/path/to/scanalyze-deployment-platform   # clean checkout of the reviewed commit
WORK="$HOME/scanalyze-direct/<deployment_id>"
mkdir -p "$WORK"/{backend,tfvars,plans,outputs} && chmod 700 "$WORK"
cp "$REPO/deployment/direct-path/deployment.example.yaml" "$WORK/deployment.yaml"
"${EDITOR:-vi}" "$WORK/deployment.yaml"        # replace every placeholder
python3 "$REPO/scripts/deployment/direct-path.py" layers
```

The config needs real values for every key the example sets. The kit checks
formats and cross-field bindings (for example that the certificate and log
group ARNs belong to the account and region) and fails closed with the key
name when one is missing or invalid. It cannot tell a placeholder from a real
value; `allowed_account_ids` in the backend file stops `terraform init` with
credentials for any other account.

## 2. Per-layer command sequence

Apply the layers in this order: global, network, platform, data-foundation,
cicd, (publish images), identity-control-plane, addons, services, edge-identity,
edge. account-ready-gate and platform-authority are not applied. For each
layer, run exactly:

```bash
LAYER=global
CFG="$WORK/deployment.yaml"

# 1. backend file (bucket, key from deployment/layers.yaml, region, encrypt, use_lockfile, allowed_account_ids)
python3 "$REPO/scripts/deployment/direct-path.py" backend "$LAYER" --config "$CFG" \
  --out "$WORK/backend/$LAYER.backend.hcl"
# 2. init against the committed provider lock (aws 5.100.0)
terraform -chdir="$REPO/roots/$LAYER" init -reconfigure -input=false -lockfile=readonly \
  -backend-config="$WORK/backend/$LAYER.backend.hcl"
# 3. tfvars from the config and every upstream <layer>.outputs.json
python3 "$REPO/scripts/deployment/direct-path.py" tfvars "$LAYER" --config "$CFG" \
  --outputs-dir "$WORK/outputs" --out "$WORK/tfvars/$LAYER.tfvars.json"
# 4. saved plan
terraform -chdir="$REPO/roots/$LAYER" plan -input=false \
  -var-file="$WORK/tfvars/$LAYER.tfvars.json" -out="$WORK/plans/$LAYER.tfplan"
# 5. review: resources, replacements and destroys, names, account and region
terraform -chdir="$REPO/roots/$LAYER" show "$WORK/plans/$LAYER.tfplan"
# 6. apply exactly the reviewed plan
terraform -chdir="$REPO/roots/$LAYER" apply -input=false "$WORK/plans/$LAYER.tfplan"
# 7. save the outputs the next layers read
terraform -chdir="$REPO/roots/$LAYER" output -json > "$WORK/outputs/$LAYER.outputs.json"
```

- `tfvars` never overwrites `--out`. To re-render after a change, use a new name
  (for example `$LAYER.2.tfvars.json`). `backend` accepts an identical existing
  file and refuses a different one.
- Re-save `outputs/<layer>.outputs.json` after every apply of that layer; it is
  the only source the downstream layers read.
- `-reconfigure` prevents an accidental state migration if the root was
  initialized before for another backend. `-lockfile=readonly` keeps the
  committed `.terraform.lock.hcl` unchanged (checked offline on darwin_arm64
  with the global root).

| # | Layer | Before you run it | What to look for in the plan |
|---|---|---|---|
| 1 | global | prerequisites 1-2 | IAM roles `<dep>-workload-<service>`, the execution role and two permissions boundaries; writes `outputs/direct-path-release.json` |
| 2 | network | - | VPC 10.0.0.0/16, 2 private and 2 public subnets in use1-az1/use1-az2, 2 NAT gateways and EIPs, 6 interface endpoints, S3 and DynamoDB gateway endpoints |
| 3 | platform | certificate ISSUED (4) | ECS cluster, internal ALB with deletion protection, HTTPS listener (TLS 1.3 policy) |
| 4 | data-foundation | - | KMS key, documents table and jobs table, documents bucket, 9 stage queues + DLQs, 6 legacy worker queues + DLQs |
| 5 | cicd | - | 7 ECR repositories `<dep-ulid>/scanalyze/<service>` (immutable tags, KMS), artifact bucket, SSM release metadata; **no** CodeCommit, CodeBuild or CodePipeline |
| - | images | cicd applied | Section 3 |
| 6 | identity-control-plane | Lambda artifact (7); **blocked by B1 and B2** | Cognito user pool (PLUS tier, deletion protection), resource server, SPA client, domain, two Lambdas, DynamoDB tables, FIFO queues, alarms |
| 7 | addons | - | dashboard, CPU alarms, DLQ alarms, SNS topic, `/ecs/<dep>/<service>` log groups (see G1, G7) |
| 8 | services | `services.inputs.json`; PR #135 (B5, G1) | task definitions, services, target group and listener rule for `scanalyze-ingest-api` |
| 9 | edge-identity | **blocked by B3 and B4** | HTTP API, VPC link, JWT authorizer, one route per `api_authorization_routes` key, `$default` stage with access logs |
| 10 | edge | frontend bucket (6) | ACM certificate in us-east-1 with DNS validation, WAF, CloudFront, A/AAAA alias, `config.json` object |

## 3. Images and services inputs (after cicd, before services)

Follow `docs/operations/direct-path-publish.md` from PR #136. In short, after a
`--dry-run` review:

```bash
"$REPO/scripts/deployment/publish-direct-release.sh" --account-id "$ACCOUNT_ID" --region us-east-1 \
  --deployment-id "$DEPLOYMENT_ID" --base-image "<account>.dkr.ecr.us-east-1.amazonaws.com/<dep-ulid>/scanalyze/base@sha256:<digest>" \
  --tag "pilot-$(git -C "$REPO" rev-parse --short=12 HEAD)" --output "$WORK/release-images.json"
python3 "$REPO/scripts/deployment/render-direct-service-definitions.py" \
  --release-images "$WORK/release-images.json" --out "$WORK/services.inputs.json" --desired-count 1 \
  --without-ocr-poller   # drop this flag once roots/services declares runtime_wiring (PR #135)
```

Write the renderer output to `$WORK/services.inputs.json` (the config's
`services.inputs_file`), **not** into `roots/services`: a `*.auto.tfvars.json`
file there would be loaded by Terraform on its own. `tfvars services` checks
that every image is digest-pinned in one of this deployment's ECR repositories
(cicd `ecr_repository_urls`), that every service has a workload role in the
global outputs, and that the OCR poller is only present when `runtime_wiring`
exists.

## 4. After edge

- **CloudFront access to the frontend bucket** (G2). The repository creates the
  origin access control but no bucket policy. Unverified proposal, applied by
  the owner:

  ```bash
  DIST_ID="$(jq -r '.contract_payload.value.outputs.cloudfront_distribution_id' "$WORK/outputs/edge.outputs.json")"
  aws s3api put-bucket-policy --bucket "scanalyze-$ACCOUNT_ID-frontend" --policy "$(jq -n \
    --arg b "scanalyze-$ACCOUNT_ID-frontend" --arg d "arn:aws:cloudfront::$ACCOUNT_ID:distribution/$DIST_ID" \
    '{Version:"2012-10-17",Statement:[{Sid:"AllowCloudFrontRead",Effect:"Allow",Principal:{Service:"cloudfront.amazonaws.com"},Action:"s3:GetObject",Resource:"arn:aws:s3:::\($b)/*",Condition:{StringEquals:{"AWS:SourceArn":$d}}}]}')"
  ```

- **SPA.** Optional: `publish-frontend.sh` (PR #136). Human login is disabled
  (G6), so the SPA cannot sign anyone in; the first end-to-end run uses a
  machine token.

## 5. M2M client (manual) and the identity re-apply

Terraform does not create M2M clients. After identity-control-plane is applied:

```bash
POOL_ID="$(jq -r '.contract_payload.value.outputs.cognito_user_pool_id' "$WORK/outputs/identity-control-plane.outputs.json")"
CLIENT_ID="$(aws cognito-idp create-user-pool-client --user-pool-id "$POOL_ID" \
  --client-name "${DEPLOYMENT_ID}-m2m-smoke" --generate-secret \
  --allowed-o-auth-flows client_credentials --allowed-o-auth-flows-user-pool-client \
  --allowed-o-auth-scopes scanalyze.api.v1/read scanalyze.api.v1/write scanalyze.api.v1/admin \
  --access-token-validity 15 --token-validity-units AccessToken=minutes \
  --enable-token-revocation --prevent-user-existence-errors ENABLED \
  --query 'UserPoolClient.ClientId' --output text)"
```

The query prints only the client ID. Read the secret with
`aws cognito-idp describe-user-pool-client` straight into your password manager
or a Secrets Manager secret; never put it in the config, a tfvars file, the
repository or shell history. Then add the binding to the config:

```yaml
identity:
  m2m_bindings:
    - client_id: <CLIENT_ID>
      required_scopes: [scanalyze.api.v1/read, scanalyze.api.v1/write, scanalyze.api.v1/admin]
```

The kit adds `customer_id` and `deployment_id`. Pick `required_scopes` to match
the scopes granted to the client and the routes you will call; full results and
exports need admin (`docs/operations/edge-runtime-input-readiness.md`). Then
re-run the section 2 sequence, with new `--out` names, for
identity-control-plane, services and edge-identity, saving each layer's outputs
before rendering the next. This propagates the client to the identity contract,
the API's `COGNITO_ALLOWED_CLIENT_IDS` and `M2M_CLIENT_IDENTITY_BINDINGS_V1`, and
the JWT authorizer audiences. Edge reads no M2M value; its re-rendered plan is
expected to show no changes (unverified).

## 6. Smoke test outline

1. **Platform.** `aws ecs describe-services --cluster "<dep>-cluster" --services "<dep>-scanalyze-ingest-api" ...`
   shows running tasks; `aws elbv2 describe-target-health` shows the ingest
   target healthy; `aws logs tail "/ecs/<dep>/scanalyze-ingest-api"` shows startup.
2. **Token.** Client credentials against the pool's domain. Its prefix is the
   deployment ID in lowercase with `-` instead of `_`, followed by `-identity`
   (`modules/identity-control-plane/locals.tf:22`). Load `CLIENT_SECRET` from
   your password manager without typing it on the command line:

   ```bash
   curl -sS -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials \
     -d scope="scanalyze.api.v1/read scanalyze.api.v1/write scanalyze.api.v1/admin" \
     "https://<hosted-ui-prefix>.auth.us-east-1.amazoncognito.com/oauth2/token"
   ```

3. **Gateway.** Without a token, `curl -i "https://$DOMAIN/api/v2/documents/<uuid>"`
   must return 401 from API Gateway. With the token it must reach the API (a JSON
   4xx such as 404 from the backend, not 401/403 from the gateway or 5xx from the
   integration). Use `/api/v2/...` or the `/api/<path>` facade, not `/api/v1/...` (G3).
4. **Document journey.** `scripts/validation/document-journey-smoke.py`, as
   described in `docs/operations/document-journey-smoke.md`, with the token in
   `SCANALYZE_SMOKE_ACCESS_TOKEN`. It needs PR #135 (B5) for the workers to run.

## 7. Teardown notes

Destroy in reverse order (edge first, global last) with
`terraform plan -destroy -out=...`, review, then apply. Expect these to stop a
plain destroy:

- **`prevent_destroy`** (`terraform destroy` errors until the guard is removed in
  code, or the resource is removed from state with `terraform state rm` and
  deleted by hand): identity KMS key (`modules/identity-control-plane/storage.tf:116`),
  the four identity DynamoDB tables (`storage.tf:187`, `:223`, `:259`, `:295`), the
  bootstrap FIFO queues (`bootstrap.tf:9`, `:31`), both identity Lambda log groups
  (`pre_token.tf:7`, `control_processor.tf:7`), the Cognito user pool
  (`cognito.tf:89`), the six legacy worker queues and DLQs
  (`modules/data-foundation/sqs.tf:77`, `:97`) and the SPA `config.json` object
  (`modules/edge/runtime_config.tf:128`).
- **Deletion protection**, to disable first: the Cognito user pool
  (`deletion_protection = "ACTIVE"`, `cognito.tf:3`), the identity DynamoDB tables
  (`storage.tf:135`, `:201`, `:237`, `:273`) and the internal ALB
  (`modules/container-platform/alb.tf:14`).
- **Non-empty resources:** the versioned documents bucket and cicd artifact
  bucket (`force_destroy = false`, `modules/cicd/main.tf:112`) need every object
  version deleted; ECR repositories with images fail to delete; the frontend,
  state and Lambda artifact buckets are owner-created and stay.
- **KMS keys** are scheduled for deletion, not deleted: 30 days for the data and
  identity keys, 7 for cicd.

For a throwaway pilot account, closing the account after exporting what you
need may be simpler than a guarded destroy (owner decision).

## Known gaps

### Blockers on this branch

Verified with `terraform console` and the self-check; no Terraform under
`roots/` or `modules/` was changed.

- **B1. Real SHA-256 digests are rejected.**
  `roots/identity-control-plane/contract_validation.tf:107-108` and `:139-140`,
  and the module validations `modules/identity-control-plane/variables.tf:228`
  and `:299`, require `can(base64decode(x)) && length(base64decode(x)) == 32`.
  Terraform's `base64decode` must produce valid UTF-8 and `length` counts
  characters, so a real digest fails (`can(base64decode("Hz2aTG6LDS9KbI4LLU9qjA4rTW+KDC5LbY8KLE5rjQ8="))`
  is `false`); only digests whose 32 bytes are all ASCII pass, as in the module
  tests (`IiIi...`, `MzMz...`). Fix: a canonical Base64 regex such as
  `^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$` (as `tooling/identity_adapters.py:220`).
- **B2. Scope-set comparison is always false.**
  `roots/identity-control-plane/contract_validation.tf:164-168` compares an
  object of `list(string)` with a literal object of tuples; `==` needs identical
  types. Fix: `tolist([...])` per attribute, as `roots/services/contract_validation.tf:90-92`.
- **B3. Same in edge-identity.** `roots/edge-identity/contract_validation.tf:86`
  (`allowed_token_uses == ["access"]`) and `:92-96` (`action_scope_sets`) are
  always false. Fix: `tolist(...)`.
- **B4. Edge-identity needs at least one M2M binding.**
  `roots/edge-identity/contract_validation.tf:122-124` compares
  `toset(m2m_client_ids)` with a `toset([for ...])` that is an empty set of an
  unknown element type when there are no bindings, so it is false. With one or
  more bindings it is true. Fix: `setsubtract` both ways, as
  `roots/services/contract_validation.tf:135-142`. Until fixed, create the M2M
  client (section 5) before the first edge-identity apply.

With these expressions corrected in a temporary copy only, both roots pass the
mock-provider plan with the kit's tfvars. Because services reads the identity
outputs and edge reads edge-identity, B1-B3 block layers 6 and 8-10.

- **B5. Services without PR #135 cannot process documents.** On this branch the
  task definitions inject no table, bucket or queue settings
  (`modules/services/ecs_services.tf:40-61`), and every worker exits at start
  without `SCANALYZE_ENV`/`SCANALYZE_TENANT` and an SSM tenant tree that nothing
  on the direct path writes (`backend/workers/scanalyze-bank-worker/src/bank_worker/config.py:24-33`).
  PR #135 adds `runtime_wiring`; the kit fills it from the data-foundation
  outputs and the config `environment`.

### Other gaps

- **G1. Service log groups.** Task definitions log to
  `/ecs/<dep>/scanalyze-<service>` (`modules/services/ecs_services.tf:66`), but
  addons creates `/ecs/<dep>/<service>` without the prefix
  (`modules/addons/cloudwatch.tf:84`, defaults in `modules/addons/variables.tf:26-38`),
  and `roots/addons/main.tf:24` does not expose `service_names`. The awslogs
  driver does not create groups, so tasks cannot start. PR #135 makes services
  create its own groups. Without it, create the seven groups by hand before
  services and import them once PR #135 lands.
- **G2. No CloudFront read policy on the frontend bucket.** No
  `aws_s3_bucket_policy` exists in `modules/` or `roots/`; see section 4.
- **G3. `/api/v1/...` through CloudFront is rewritten to `/api/v1/v1/...`.**
  `modules/edge/api_path_rewrite.js:10-11` preserves only `/api/v2`, unlike the
  claim in `docs/operations/edge-runtime-input-readiness.md`. Clients must use
  `/api/v2/...` or the `/api/<path>` facade; the gateway route keys stay
  `/api/v1/...`.
- **G4. us-east-1 only.** `roots/network/main.tf:24` leaves the subnet maps at
  the module defaults keyed by AZ IDs `use1-az1`/`use1-az2`
  (`modules/network/variables.tf:32-48`). The kit refuses other regions for
  network and refuses a `network:` config section until the root exposes it.
- **G5. Self-attested contracts.** See "How each layer's inputs are sourced". The
  direct path has no ACCOUNT_READY record, signed release manifest or
  identity-contract/v2 document.
- **G6. Human sign-in is disabled by design.** The pre-token Lambda runs with
  `HUMAN_RUNTIME_ENABLED=false` and `USER_POOL_ID=UNBOUND`
  (`modules/identity-control-plane/pre_token.tf:95`, `:105`), and the
  services and edge-identity preconditions require human provisioning to stay
  off. Keep it off.
- **G7. Addons watch names that do not exist.** CPU alarms and the dashboard use
  service names `<dep>-<service>` (`modules/addons/cloudwatch.tf:21`, `:70`) while
  services are `<dep>-scanalyze-<service>` (`modules/services/ecs_services.tf:87`),
  and the DLQ alarms watch the legacy `<dep>-<worker>-dlq` queues
  (`modules/addons/dlq_monitoring.tf:30`), not the stage DLQs
  (`modules/data-foundation/sqs.tf:131`). Expect INSUFFICIENT_DATA.
- **G8. Identity alarms have no target** unless `identity.alarm_actions` is set.
  The addons SNS topic exists only after addons; re-apply identity with it if
  wanted.
- **G9. Route map is a proposal.** `edge_identity.api_authorization_routes` in the
  example follows the M2M column of `docs/operations/edge-runtime-input-readiness.md`
  (R to read, W to write, R + A to admin) and leaves out human-only admin,
  passkey, health and docs routes. The owner must review it.

## Assumptions to verify in AWS

None of these was checked against AWS.

- The credentials are for the new, dedicated account, and Terraform's S3 backend
  accepts `allowed_account_ids` (the orchestrator renders the same key in
  `scripts/deployment/terraform-layer.sh`).
- Quotas: 2 Elastic IPs and NAT gateways, 6 interface endpoints in 2 AZs, Fargate
  vCPU for the services, one CloudFront distribution, one WAF web ACL.
- The internal certificate is ISSUED, matches `alb_tls_server_name`, and API
  Gateway's private-integration TLS verification accepts it.
- The hosted zone is public and delegated, and holds `domain_name`.
- API Gateway HTTP APIs can write access logs to the owner-created group without
  an extra resource policy.
- The identity zip runs on python3.12 arm64 with only the runtime's boto3, and
  its key's sha256 matches the uploaded object (`aws lambda get-function`
  `CodeSha256` equals the derived `sha256_b64` after apply).
- Bedrock access for both default model IDs in us-east-1, and Textract for the
  OCR worker.
- Cost: Cognito Plus tier with ENFORCED advanced security
  (`modules/identity-control-plane/cognito.tf:4`, `:39`) and M2M token requests,
  NAT gateways, interface endpoints, Fargate tasks, CloudFront and WAF.
- `required_scopes` semantics of the M2M binding match the ingest API
  (`backend/workers/scanalyze-ingest-api/app/config.py`).
- Edge's plan after the M2M re-apply shows no changes.

## Offline validation

```bash
python3 -m pytest tests/test_gug543_direct_path_kit.py -q
TF_PLUGIN_CACHE_DIR="$HOME/.terraform.d/plugin-cache" scripts/deployment/direct-path-selfcheck.sh
```

The self-check renders all ten layers from the example config and the fixtures,
copies each root and its modules to a temporary directory, and runs
`terraform test` (`command = plan`) with mock AWS providers. Mocks: cicd's
caller-identity and partition data sources return the configured account and
`aws`, and the edge ACM certificate exposes its validation option at plan time,
as the AWS provider does. On this branch it reports eight roots passing and
identity-control-plane and edge-identity failing on B1-B4.
