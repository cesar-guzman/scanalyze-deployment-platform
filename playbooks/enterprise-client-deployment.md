# Scanalyze Platform v2 — Enterprise Client Deployment Playbook

**Version: 3.0**
**Date: 2026-07-07**
**Audience: Platform Engineers, SREs, DevOps**
**Status: PRODUCTION — Validated end-to-end (deploy + destroy + redeploy)**
**Last Validated Deploy: 2026-07-06, Account 905418363887**
**Last Validated Destroy: 2026-07-07, Account 905418363887**

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Step 0: Account Baseline](#step-0-account-baseline)
4. [Step 1: Configure Environment](#step-1-configure-environment)
5. [Step 2: Deploy Terraform Layers](#step-2-deploy-terraform-layers)
6. [Step 3: Build & Push Container Images](#step-3-build--push-container-images)
7. [Step 4: Deploy Services](#step-4-deploy-services)
8. [Step 5: Frontend Config & Auth Setup](#step-5-frontend-config--auth-setup)
9. [Step 6: E2E Validation](#step-6-e2e-validation)
10. [Step 7: Client Onboarding](#step-7-client-onboarding)
11. [Rollback Procedures](#rollback-procedures)
12. [Troubleshooting](#troubleshooting)
13. [Security Checklist](#security-checklist)
14. [Appendix](#appendix)

---

## Overview

Este playbook documenta el procedimiento end-to-end para desplegar un ambiente Scanalyze para un nuevo cliente enterprise. Cada cliente obtiene una cuenta AWS aislada con su propio stack de infraestructura.

> **IMPORTANTE: Este playbook fue validado en producción real el 2026-07-06.**
> Todos los comandos han sido ejecutados y verificados contra una cuenta real.

### Arquitectura del Deploy

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    DEPLOYMENT ORDER (≈45-60 min)                         │
│                                                                          │
│  Step 0: Account Baseline (5 min)                                        │
│     ├── S3 state bucket + versioning + encryption                       │
│     ├── DynamoDB lock table (o S3 lockfile para TF >= 1.14)             │
│     └── Verify bootstrap                                                 │
│                                                                          │
│  Step 1: Configure Environment (5 min)                                   │
│     ├── Create bcm-corp.tfvars (shared)                                  │
│     ├── Create bcm-corp-platform.tfvars                                  │
│     ├── Create bcm-corp-edge.tfvars                                      │
│     ├── Create bcm-corp-edge-identity.tfvars                             │
│     ├── Create bcm-corp-services.tfvars                                  │
│     └── Create cicd.tfvars                                               │
│                                                                          │
│  Step 2: Terraform Layers (20 min, sequential)                           │
│     ├── 2a. global         → IAM roles, permissions boundary            │
│     ├── 2b. network        → VPC, subnets, NAT, endpoints              │
│     ├── 2c. data-foundation → S3 buckets, DynamoDB tables, frontend S3  │
│     ├── 2d. platform       → ECS cluster, ALB, SQS queues              │
│     ├── 2e. edge-identity  → Cognito user pool, app clients, domain    │
│     ├── 2f. edge           → API Gateway, CloudFront, config.json      │
│     ├── 2g. services       → ECS services, SSM params, task defs       │
│     ├── 2h. cicd           → ECR repos, CodeBuild, CodePipeline         │
│     └── 2i. addons         → CloudWatch, alarms, dashboards            │
│                                                                          │
│  Step 3: Build & Push Images (10 min)                                    │
│     ├── docker build 7 services                                          │
│     ├── ECR push with immutable tags                                     │
│     └── SSM digest update                                                │
│                                                                          │
│  Step 4: Deploy Services (5 min)                                         │
│     ├── services layer terraform apply                                   │
│     └── ECS force-deploy                                                 │
│                                                                          │
│  Step 5: Frontend Config & Auth (5 min)                                  │
│     ├── Upload config.json to S3                                         │
│     ├── CloudFront invalidation                                          │
│     └── Create admin user in Cognito                                     │
│                                                                          │
│  Step 6: E2E Validation (5 min)                                          │
│     ├── 7/7 services healthy                                             │
│     ├── Frontend loads                                                   │
│     ├── Login flow works                                                 │
│     └── API endpoints respond                                            │
│                                                                          │
│  Step 7: Client Onboarding                                               │
│     ├── Create admin users                                               │
│     ├── DNS & certificates (if custom domain)                            │
│     └── Hand over credentials                                            │
└──────────────────────────────────────────────────────────────────────────┘
```

### Services Architecture

| Service | Type | Queue | Purpose |
|---------|------|-------|---------|
| ingest-api | API (FastAPI) | N/A | Document upload & API gateway |
| ocr-worker | Worker | ocr-queue | OCR text extraction |
| postprocess-worker | Worker | postprocess-queue | Document post-processing |
| classifier-worker | Worker | classifier-queue | Document classification |
| bank-worker | Worker | bank-queue | Bank statement processing |
| personal-worker | Worker | personal-queue | Personal document processing |
| gov-worker | Worker | gov-queue | Government document processing |

---

## Prerequisites

### Required Tools

| Tool | Version | Purpose | Install |
|------|---------|---------|---------|
| AWS CLI | v2.x | AWS API interactions | `brew install awscli` |
| Terraform | >= 1.5.0 | Infrastructure as Code | `brew install terraform` |
| Docker | Latest | Container image builds | Docker Desktop |
| Git | Latest | Version control | `brew install git` |
| Python | 3.11+ | Backend builds | `brew install python@3.11` |
| Node.js | 18+ | Frontend builds | `brew install node` |
| jq | Latest | JSON parsing | `brew install jq` |

### AWS Account Requirements

- [ ] New AWS account provisioned in AWS Organizations
- [ ] AWS SSO configured with Permission Sets:
  - `ScanalyzeDeploy` — Terraform apply, ECR push, SSM write, Cognito admin
  - `ScanalyzeDestroy` — Terraform destroy, cleanup operations
  - `ScanalyzeReadOnly` — Monitoring, debugging
- [ ] Deployment ID generated (format: `dep_<ULID>`)
- [ ] Region selected (default: `us-east-1`)

### Required IAM Permissions (Deploy Role)

The deploy role needs at minimum:

- ec2, ecs, elasticloadbalancing, s3, dynamodb, sqs, ssm
- cloudfront, apigateway (apigatewayv2)
- cognito-idp (AdminCreateUser, AdminSetUserPassword, CreateGroup, AdminAddUserToGroup)
- ecr, codebuild, codepipeline, codecommit
- cloudwatch, logs
- kms, iam (CreateRole, PutRolePolicy, PassRole)

---

## Step 0: Account Baseline

> **Run ONCE per account, FIRST before any Terraform.**

### 0.1 Set Environment Variables

```bash
# === CLIENT-SPECIFIC VALUES ===
export AWS_ACCOUNT_ID="<ACCOUNT_ID>"        # e.g. 905418363887
export DEPLOYMENT_ID="dep_<ULID>"           # e.g. dep_01KWM783E0S1FZVAM8FRDV1HR2
export SANITIZED_ID=$(echo "$DEPLOYMENT_ID" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
export AWS_REGION="us-east-1"
export ENVIRONMENT="production"

# Derived values
export BUCKET="scanalyze-${SANITIZED_ID}-tf-state"
export TABLE="scanalyze-${SANITIZED_ID}-tf-lock"
```

### 0.2 Configure AWS Credentials

```bash
# Option A: AWS SSO (recommended for enterprise)
aws sso login --profile <PROFILE_NAME>
export AWS_PROFILE=<PROFILE_NAME>

# Option B: Temporary credentials (session token)
export AWS_ACCESS_KEY_ID="<KEY>"
export AWS_SECRET_ACCESS_KEY="<SECRET>"
export AWS_SESSION_TOKEN="<TOKEN>"
export AWS_DEFAULT_REGION="$AWS_REGION"

# Verify identity
aws sts get-caller-identity
```

### 0.3 Create State Backend

```bash
# Create S3 bucket
aws s3api create-bucket --bucket "$BUCKET" --region $AWS_REGION
aws s3api put-bucket-versioning --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled
aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,\
    BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption --bucket "$BUCKET" \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}'

# Create DynamoDB lock table
aws dynamodb create-table \
  --table-name "$TABLE" \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region $AWS_REGION
```

### 0.4 Verify Bootstrap

```bash
aws s3api head-bucket --bucket "$BUCKET"
aws s3api get-bucket-versioning --bucket "$BUCKET"
aws dynamodb describe-table --table-name "$TABLE" \
  --query "Table.TableStatus" --output text
# Expected: ACTIVE
```

---

## Step 1: Configure Environment

> **Copiar templates y editar con valores del cliente.**

### 1.1 Shared Variables (bcm-corp.tfvars)

```hcl
# environments/<CLIENT>.tfvars
deployment_id = "dep_<ULID>"
region        = "us-east-1"
environment   = "production"
```

### 1.2 Services Variables

> **⚠️ CRITICAL: Image references MUST use `@sha256:digest`, NOT `:tag`.**

```hcl
# environments/<CLIENT>-services.tfvars
# See Step 3 for how to get digests after image build
```

### 1.3 CICD Variables

```hcl
# environments/cicd.tfvars
pipelines = {
  ingest-api = {
    service_name  = "ingest-api"
    ecr_repo_name = "scanalyze/ingest-api"
  }
  ocr-worker = {
    service_name  = "ocr-worker"
    ecr_repo_name = "scanalyze/ocr-worker"
  }
  # ... repeat for all 7 services
}
```

---

## Step 2: Deploy Terraform Layers

### Deploy Pattern (repeat for each layer)

```bash
cd roots/<LAYER>

# Initialize
terraform init \
  -backend-config="bucket=${BUCKET}" \
  -backend-config="key=${DEPLOYMENT_ID}/${AWS_REGION}/<LAYER>/terraform.tfstate" \
  -backend-config="region=${AWS_REGION}" \
  -backend-config="dynamodb_table=${TABLE}" \
  -backend-config="encrypt=true"

# Plan
terraform plan -var-file=../../environments/<CLIENT>.tfvars \
  [-var-file=../../environments/<CLIENT>-<LAYER>.tfvars] \
  -out=plan.tfplan

# Apply
terraform apply plan.tfplan

cd ../..
```

### Layer Order

> **⚠️ CRITICAL:** Deploy in this exact order. Each layer depends on outputs from the previous ones.

| # | Layer | Var Files | Key Outputs |
|---|-------|-----------|-------------|
| 0 | global | `<CLIENT>.tfvars` | IAM roles, permissions boundary |
| 1 | network | `<CLIENT>.tfvars` | VPC ID, Subnet IDs |
| 2 | data-foundation | `<CLIENT>.tfvars` | S3 buckets, DynamoDB, Frontend bucket |
| 3 | platform | `<CLIENT>.tfvars`, `<CLIENT>-platform.tfvars` | ECS cluster, ALB, SQS queues |
| 4 | edge-identity | `<CLIENT>.tfvars`, `<CLIENT>-edge-identity.tfvars` | Cognito Pool ID, Client IDs, Domain |
| 5 | edge | `<CLIENT>.tfvars` | CloudFront domain, API Gateway endpoint |
| 6 | services | `<CLIENT>.tfvars`, `<CLIENT>-services.tfvars` | ECS services, SSM worker configs |
| 7 | cicd | `<CLIENT>.tfvars`, `cicd.tfvars` | ECR repos, Pipelines |
| 8 | addons | `<CLIENT>.tfvars` | Dashboards, Alarms |

> **NOTA:** Layer `services` crea automáticamente ~52 SSM parameters para runtime config de workers
> (queue URLs, table names, bucket names, feature flags) bajo `/scanalyze/demo/tenants/{tenant}/{key}`.
> No necesitas crearlos manualmente.

After each apply, verify: `terraform plan → No changes`

---

## Step 3: Build & Push Container Images

### 3.1 ECR Login

```bash
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin \
  ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com
```

### 3.2 Build and Push

```bash
SERVICES="ingest-api ocr-worker postprocess-worker classifier-worker bank-worker personal-worker gov-worker"
ECR_PREFIX="${SANITIZED_ID}/scanalyze"
TAG="v1.0.0"

for svc in $SERVICES; do
  REPO="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_PREFIX}/${svc}"
  
  docker build -t ${REPO}:${TAG} \
    -f backend/workers/scanalyze-${svc}/Dockerfile \
    backend/workers/scanalyze-${svc}/
  
  docker push ${REPO}:${TAG}
  
  DIGEST=$(aws ecr describe-images \
    --repository-name "${ECR_PREFIX}/${svc}" \
    --image-ids imageTag=${TAG} \
    --query "imageDetails[0].imageDigest" --output text)
  
  echo "$svc → $DIGEST"
  
  aws ssm put-parameter \
    --name "/${DEPLOYMENT_ID}/cicd/images/${svc}/image_digest" \
    --value "$DIGEST" --type String --overwrite
  aws ssm put-parameter \
    --name "/${DEPLOYMENT_ID}/cicd/images/${svc}/image_tag" \
    --value "$TAG" --type String --overwrite
done
```

### 3.3 Update Services tfvars with digests

Update image references in `<CLIENT>-services.tfvars` using `@sha256:<DIGEST>`.

---

## Step 4: Deploy Services

```bash
cd roots/services
terraform apply -var-file=../../environments/<CLIENT>.tfvars \
  -var-file=../../environments/<CLIENT>-services.tfvars \
  -var="customer_id=<CUSTOMER_ID>"

# Find cluster
ECS_CLUSTER=$(aws ecs list-clusters --region $AWS_REGION \
  --query "clusterArns[0]" --output text | awk -F/ '{print $NF}')

# Force deploy all
for svc in $SERVICES; do
  aws ecs update-service \
    --cluster "$ECS_CLUSTER" \
    --service "${DEPLOYMENT_ID}-${svc}" \
    --force-new-deployment --region $AWS_REGION \
    --query "service.status" --output text
done

# Wait 60s then verify
sleep 60
aws ecs describe-services --cluster "$ECS_CLUSTER" \
  --services $(for svc in $SERVICES; do echo "${DEPLOYMENT_ID}-${svc}"; done) \
  --region $AWS_REGION \
  --query "services[].{Name:serviceName,Running:runningCount,Desired:desiredCount,Status:status}" \
  --output table
```

---

## Step 5: Frontend Config & Auth Setup

### 5.1 Upload config.json

> **⚠️ CRITICAL: Field names MUST match the frontend AppConfig interface.**
> Wrong fields cause the app to hang on "Verificando sesión segura..."

```bash
# Get values
CLOUDFRONT_DOMAIN=$(aws cloudfront list-distributions --region $AWS_REGION \
  --query "DistributionList.Items[0].DomainName" --output text)
API_GW_ENDPOINT=$(aws apigatewayv2 get-apis --region $AWS_REGION \
  --query "Items[0].ApiEndpoint" --output text)
FRONTEND_BUCKET="${SANITIZED_ID}-frontend"

# These come from edge-identity Terraform outputs
COGNITO_POOL_ID="<pool_id>"
COGNITO_CLIENT_ID="<client_id>"
COGNITO_DOMAIN="<domain>"

cat > /tmp/config.json <<EOF
{
  "env": "production",
  "apiBaseUrl": "${API_GW_ENDPOINT}",
  "cognitoRegion": "${AWS_REGION}",
  "cognitoUserPoolId": "${COGNITO_POOL_ID}",
  "cognitoClientId": "${COGNITO_CLIENT_ID}",
  "cognitoDomain": "https://${COGNITO_DOMAIN}",
  "redirectUri": "https://${CLOUDFRONT_DOMAIN}/callback",
  "postLogoutRedirectUri": "https://${CLOUDFRONT_DOMAIN}/"
}
EOF

python3 -m json.tool /tmp/config.json  # Validate

aws s3 cp /tmp/config.json s3://${FRONTEND_BUCKET}/config.json \
  --content-type "application/json" \
  --cache-control "no-cache,no-store,must-revalidate" \
  --region $AWS_REGION

# Invalidate CloudFront cache
CF_DIST_ID=$(aws cloudfront list-distributions --region $AWS_REGION \
  --query "DistributionList.Items[0].Id" --output text)
aws cloudfront create-invalidation \
  --distribution-id "$CF_DIST_ID" --paths "/config.json"
```

### 5.2 config.json Field Reference

| ✅ Correct Field | ⛔ DO NOT Use | Type |
|------------------|--------------|------|
| `cognitoRegion` | `region` | `"us-east-1"` |
| `cognitoUserPoolId` | `cognitoAuthority` | `"us-east-1_XXXXX"` |
| `postLogoutRedirectUri` | `logoutUri` | `"https://xxx/"` |

### 5.3 Create Admin User

```bash
EMAIL="admin@client.com"

aws cognito-idp admin-create-user \
  --user-pool-id $COGNITO_POOL_ID \
  --username "$EMAIL" \
  --user-attributes Name=email,Value="$EMAIL" Name=email_verified,Value=true \
  --message-action SUPPRESS --region $AWS_REGION

aws cognito-idp admin-set-user-password \
  --user-pool-id $COGNITO_POOL_ID \
  --username "$EMAIL" \
  --password "TempPass2026!" \
  --permanent --region $AWS_REGION

# Verify
aws cognito-idp admin-get-user \
  --user-pool-id $COGNITO_POOL_ID --username "$EMAIL" \
  --region $AWS_REGION \
  --query "{Status:UserStatus,Enabled:Enabled}" --output json
# Expected: CONFIRMED, true
```

---

## Step 6: E2E Validation

```bash
# 1. Services (7/7 ACTIVE, Running=1)
aws ecs describe-services --cluster "$ECS_CLUSTER" \
  --services $(for svc in $SERVICES; do echo "${DEPLOYMENT_ID}-${svc}"; done) \
  --region $AWS_REGION \
  --query "services[].{Name:serviceName,Running:runningCount,Status:status}" \
  --output table

# 2. Frontend
curl -s -o /dev/null -w "HTTP %{http_code}\n" "https://${CLOUDFRONT_DOMAIN}"

# 3. config.json
curl -s "https://${CLOUDFRONT_DOMAIN}/config.json" | python3 -m json.tool

# 4. OIDC Discovery
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  "https://cognito-idp.${AWS_REGION}.amazonaws.com/${COGNITO_POOL_ID}/.well-known/openid-configuration"

# 5. API Gateway
curl -s -o /dev/null -w "HTTP %{http_code}\n" "${API_GW_ENDPOINT}/api/health"
```

### Acceptance Criteria

| # | Check | Expected |
|---|-------|----------|
| 1 | 7/7 services RUNNING | All Running=1, ACTIVE |
| 2 | Frontend HTTP | 200 |
| 3 | config.json | 8 correct fields |
| 4 | OIDC discovery | 200 |
| 5 | Login page | Shows "Iniciar Sesión" button |
| 6 | Admin user | CONFIRMED |
| 7 | Terraform plan | No changes |

### 6.2 Pipeline E2E Smoke Test (Optional but Recommended)

> **⚠️ Este paso valida que el pipeline de procesamiento funciona end-to-end, no solo que los servicios están arriba.**

```bash
# Prerequisites: Obtain an auth token first
# Option A: Use Cognito hosted UI to login and extract id_token from callback URL
# Option B: Use admin credentials programmatically

TOKEN="<id_token_from_cognito>"
API_URL="${API_GW_ENDPOINT}/ingest-api"

# 1. Create a batch
BATCH_RESPONSE=$(curl -s -X POST "${API_URL}/api/v1/batches" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name": "smoke-test-batch", "description": "Deploy validation"}')
BATCH_ID=$(echo "$BATCH_RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin).get('batchId',''))")
echo "Batch created: $BATCH_ID"

# 2. Upload a test PDF
curl -s -X POST "${API_URL}/api/v1/batches/${BATCH_ID}/documents" \
  -H "Authorization: Bearer ${TOKEN}" \
  -F "file=@test_document.pdf" \
  -o /dev/null -w "Upload HTTP: %{http_code}\n"

# 3. Wait and check pipeline progress (poll every 30s, max 5 min)
for i in $(seq 1 10); do
  sleep 30
  STATUS=$(aws dynamodb query \
    --table-name "${DEPLOYMENT_ID}-documents" \
    --index-name "BatchIndex" \
    --key-condition-expression "batchId = :bid" \
    --expression-attribute-values '{":bid":{"S":"'${BATCH_ID}'"}}' \
    --query "Items[*].status.S" --output text --region $AWS_REGION)
  echo "[$(date +%H:%M:%S)] Documents status: $STATUS"
  [[ "$STATUS" == *"COMPLETED"* ]] && echo "✅ Pipeline E2E PASS" && break
  [[ $i -eq 10 ]] && echo "⚠️ Pipeline did not complete in 5 min — check CloudWatch logs"
done
```

### Expected Pipeline Flow

```
Upload → ingest-api → SQS ocr-queue → ocr-worker → SQS classifier-queue
  → classifier-worker → SQS {bank|personal|gov}-queue → extraction-worker
  → SQS postprocess-queue → postprocess-worker → COMPLETED
```

---

## Step 7: Client Onboarding

### Hand Over

| Item | Value |
|------|-------|
| Application URL | `https://<CLOUDFRONT_DOMAIN>` |
| Login Email | `<admin_email>` |
| Temporary Password | `<provided_password>` |

---

## Rollback Procedures

Destroy in **reverse order**:
```
addons → cicd → services → edge → edge-identity → data-foundation → platform → network → global
```

> **📖 Full destroy procedure:** See [Scanalyze Environment Destroy Playbook](../reports/scanalyze-environment-destroy-playbook.md)
> for detailed step-by-step with variables, pre-cleanup, and troubleshooting.

---

## Troubleshooting

### App stuck on "Verificando sesión segura..."
**Cause:** config.json has wrong field names (e.g., `cognitoAuthority` instead of `cognitoUserPoolId`)
**Fix:** Upload corrected config.json + CloudFront invalidation. See Step 5.2.

### API returns 403 Forbidden for POST /batches
**Cause:** Frontend sending `access_token` instead of `id_token`, missing the `custom:customerId` claim needed for tenant resolution.
**Fix:** Ensure frontend uses `id_token` for user-facing API calls, and backend task definition has `COGNITO_ALLOWED_TOKEN_USES=access,id`.

### ECS service keeps restarting
**Cause:** Container import error. Check CloudWatch logs.
**Fix:** Fix source, push via CodePipeline, update digest.

### ECR push "tag already exists"
**Cause:** IMMUTABLE tags. Use new tag, update SSM.

### CodeBuild 403 on docker pull
**Cause:** Missing base image ECR ARN in CodeBuild policy.
**Fix:** Update CICD layer IAM policy.

### ECS cluster not found
**Cause:** Cluster name is derived from deployment_id, not `scanalyze-cluster`.
**Fix:** `aws ecs list-clusters --region $AWS_REGION`

### OCR Worker deletes messages as "poison" instead of processing
**Cause:** Worker routing logic doesn't recognize the customer_id/tenant. Falls through to poison handler.
**Fix:** Update OCR worker's `main.py` routing table to include the new customer_id. Rebuild + redeploy image.

### Classifier Worker `ValidationException: The provided key element does not match the schema`
**Cause:** Classifier uses `documentId` as the DynamoDB key, but the table schema uses `pk=DOC#{id}` + `sk=METADATA`.
**Fix:** Update `build_key()` in classifier-worker's `aws.py` to construct composite keys: `{"pk": {"S": f"DOC#{document_id}"}, "sk": {"S": "METADATA"}}`.

### `var.customer_id: Enter a value` during terraform apply
**Cause:** Services layer requires `customer_id` variable but it's not in the var file.
**Fix:** Add `-var="customer_id=<CUSTOMER_ID>"` to the apply command.

### Dashboard analytics shows no data after batch upload
**Cause:** Batch processing pipeline may be stuck at OCR or classification stage. Check worker logs in CloudWatch.
**Fix:** Verify each SQS queue for pending messages: `aws sqs get-queue-attributes --queue-url <URL> --attribute-names ApproximateNumberOfMessages`.

---

## Security Checklist

- [ ] No hardcoded ARNs, secrets, or credentials
- [ ] ECR: IMMUTABLE tags, scan-on-push
- [ ] S3: versioned, encrypted, public access blocked
- [ ] config.json: `no-cache` headers
- [ ] Cognito as auth authority
- [ ] Runtime config (NOT build-time env vars)
- [ ] PII masking for CLABE, NSS, RFC, CURP

---

## Appendix: Architecture

```
CloudFront → S3 (React SPA)
CloudFront → API Gateway (JWT Auth) → ALB → ECS Fargate (7 services)
                                              ├── SQS Queues
                                              ├── DynamoDB
                                              └── S3 Documents
Auth: Cognito User Pool → PKCE → JWT
```

**Total deploy time: ≈55-75 minutes for a new client account.**

---

> **Playbook complementario:** [Scanalyze Environment Destroy Playbook](../reports/scanalyze-environment-destroy-playbook.md)
