# Scanalyze Platform v2 — Enterprise Client Deployment Playbook

**Version: 1.0**
**Date: 2026-07-03**
**Audience: Platform Engineers, SREs, DevOps**

---

## Overview

This playbook documents the end-to-end procedure for deploying a new Scanalyze customer environment. Each customer gets an isolated AWS account with its own infrastructure stack. The deployment is **reproducible** and follows the Platform v2 architecture.

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEPLOYMENT ORDER                             │
│                                                                 │
│  Step 0: Bootstrap (CloudFormation)                             │
│     ├── S3 state bucket                                         │
│     ├── DynamoDB lock table                                     │
│     └── KMS key for state encryption                            │
│                                                                 │
│  Step 1: Terraform Layers (sequential)                          │
│     ├── 1a. global         → account-level resources            │
│     ├── 1b. network        → VPC, subnets, NAT, endpoints      │
│     ├── 1c. platform       → ECS cluster, ALB, Cognito, RDS    │
│     ├── 1d. edge-identity  → Cognito pools & app clients       │
│     ├── 1e. edge           → API Gateway, CloudFront, WAF      │
│     ├── 1f. services       → ECS services, task definitions    │
│     ├── 1g. cicd           → ECR, CodePipeline, CodeBuild      │
│     ├── 1h. addons         → monitoring, alarms, dashboards    │
│     └── 1i. data-foundation → S3 data, DynamoDB tables         │
│                                                                 │
│  Step 2: Post-Deploy                                            │
│     ├── Validate SSM contracts                                  │
│     ├── Smoke test endpoints                                    │
│     ├── Build & push container images                           │
│     └── Update services with image digests                      │
│                                                                 │
│  Step 3: Onboard Client                                         │
│     ├── Configure tenant                                        │
│     ├── Set up auth                                             │
│     └── DNS & certificates                                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

### Tools Required

| Tool | Version | Purpose |
|------|---------|---------|
| AWS CLI | v2+ | AWS API interactions |
| Terraform | >= 1.5.0 | Infrastructure as Code |
| Docker | Latest | Container image builds |
| Git | Latest | Version control |
| Python 3.11 | Latest | Backend builds |
| Node.js 18+ | Latest | Frontend builds |

### AWS Account Setup

- [ ] New AWS account provisioned in AWS Organizations
- [ ] AWS SSO configured with Permission Sets:
  - `ScanalyzeDeploy` — Terraform apply, ECR push, SSM write
  - `ScanalyzeDestroy` — Terraform destroy, cleanup operations
  - `ScanalyzeReadOnly` — Monitoring, debugging
- [ ] Deployment ID generated (format: `dep_<ULID>`)
- [ ] Region selected (default: `us-east-1`)

---

## Step 0: Bootstrap — Terraform State Backend

> **Run ONCE per account, FIRST before any Terraform.**

### 0.1 Generate Deployment Variables

```bash
# Set deployment variables
export DEPLOYMENT_ID="dep_<YOUR_ULID>"
export SANITIZED_ID=$(echo "$DEPLOYMENT_ID" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
export AWS_REGION="us-east-1"
export ENVIRONMENT="sandbox"  # or staging, production
```

### 0.2 Deploy State Backend

#### Option A: CloudFormation (recommended for automation)

```bash
aws cloudformation create-stack \
  --stack-name scanalyze-tf-state-backend \
  --template-body file://bootstrap/cfn-tf-state-backend.yaml \
  --parameters \
    ParameterKey=DeploymentId,ParameterValue=$DEPLOYMENT_ID \
    ParameterKey=SanitizedDeploymentId,ParameterValue=$SANITIZED_ID \
    ParameterKey=Environment,ParameterValue=$ENVIRONMENT \
  --tags \
    Key=deployment_id,Value=$DEPLOYMENT_ID \
    Key=managed_by,Value=cloudformation \
    Key=layer,Value=bootstrap \
  --region $AWS_REGION

# Wait for completion
aws cloudformation wait stack-create-complete \
  --stack-name scanalyze-tf-state-backend \
  --region $AWS_REGION

# Get outputs
aws cloudformation describe-stacks \
  --stack-name scanalyze-tf-state-backend \
  --query "Stacks[0].Outputs" \
  --output table
```

#### Option B: AWS CLI (for restricted permission sets)

```bash
BUCKET="scanalyze-${SANITIZED_ID}-tf-state"
TABLE="scanalyze-${SANITIZED_ID}-tf-lock"

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

### 0.3 Verify Bootstrap

```bash
# S3
aws s3api head-bucket --bucket "$BUCKET"
aws s3api get-bucket-versioning --bucket "$BUCKET"
aws s3api get-public-access-block --bucket "$BUCKET"

# DynamoDB
aws dynamodb describe-table --table-name "$TABLE" \
  --query "Table.TableStatus" --output text
# Expected: ACTIVE
```

---

## Step 1: Terraform Layers

### 1.0 Create Environment File

```bash
# Copy template
cp environments/template.tfvars environments/${ENVIRONMENT}.tfvars

# Edit with deployment values
cat > environments/${ENVIRONMENT}.tfvars <<EOF
deployment_id = "${DEPLOYMENT_ID}"
region        = "${AWS_REGION}"
environment   = "${ENVIRONMENT}"
# ... additional variables per layer
EOF
```

### 1.1 Initialize Each Root with Remote Backend

For each root (example: cicd):

```bash
cd roots/<layer>

# Create backend config (not committed)
cat > backend.tfvars <<EOF
bucket         = "scanalyze-${SANITIZED_ID}-tf-state"
key            = "${DEPLOYMENT_ID}/${AWS_REGION}/<layer>/terraform.tfstate"
region         = "${AWS_REGION}"
dynamodb_table = "scanalyze-${SANITIZED_ID}-tf-lock"
encrypt        = true
EOF

# Initialize
terraform init -backend-config=backend.tfvars

# Plan
terraform plan -var-file=../../environments/${ENVIRONMENT}.tfvars -out=plan.tfplan

# Review plan, then apply
terraform apply plan.tfplan
```

### 1.2 Layer Deployment Order

Deploy in this order (dependencies flow downward):

```
global → network → platform → edge-identity → edge
                  ↘ data-foundation
                  ↘ services
                  ↘ cicd
                  ↘ addons
```

| Order | Layer | Key Resources | Dependencies |
|-------|-------|---------------|-------------|
| 1 | global | Account-level resources | None |
| 2 | network | VPC, subnets, NAT, endpoints | global |
| 3 | platform | ECS cluster, ALB, RDS, Cognito | network |
| 4 | edge-identity | Cognito user pools, app clients | platform |
| 5 | edge | API Gateway, CloudFront, WAF | platform, edge-identity |
| 6 | data-foundation | S3 data buckets, DynamoDB | network |
| 7 | services | ECS services, task definitions | platform, cicd (SSM) |
| 8 | cicd | ECR, CodeBuild, CodePipeline | platform |
| 9 | addons | CloudWatch, alarms, dashboards | services |

### 1.3 SSM Contract Validation

After deploying each layer, validate SSM parameter contracts:

```bash
cd roots/<layer>
terraform plan -var-file=../../environments/${ENVIRONMENT}.tfvars
# Must show: No changes
```

---

## Step 2: Post-Deploy Validation

### 2.1 Full Platform Validation

```bash
# Run from repo root
make agent-verify  # or ./scripts/agent/preflight.sh

# Layer-by-layer plan check
for layer in global network platform edge-identity edge data-foundation services cicd addons; do
  echo "=== $layer ==="
  cd roots/$layer
  terraform plan -var-file=../../environments/${ENVIRONMENT}.tfvars -no-color | tail -1
  cd ../..
done
```

### 2.2 Build & Push Container Images

```bash
# ECR login
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin \
  ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Build and push each service
SERVICES="ingest-api ocr-worker postprocess-worker classifier-worker bank-worker personal-worker gov-worker"
ECR_PREFIX="${SANITIZED_ID}/scanalyze"

for svc in $SERVICES; do
  docker build -t ${ECR_PREFIX}/${svc}:v1.0.0 -f services/${svc}/Dockerfile .
  docker tag ${ECR_PREFIX}/${svc}:v1.0.0 \
    ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_PREFIX}/${svc}:v1.0.0
  docker push ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_PREFIX}/${svc}:v1.0.0

  # Get digest and update SSM
  DIGEST=$(aws ecr describe-images \
    --repository-name "${ECR_PREFIX}/${svc}" \
    --image-ids imageTag=v1.0.0 \
    --query "imageDetails[0].imageDigest" --output text)

  aws ssm put-parameter \
    --name "/${DEPLOYMENT_ID}/cicd/images/${svc}/image_digest" \
    --value "$DIGEST" --type String --overwrite
  aws ssm put-parameter \
    --name "/${DEPLOYMENT_ID}/cicd/images/${svc}/image_tag" \
    --value "v1.0.0" --type String --overwrite
done
```

### 2.3 Update Services with Digests

```bash
cd roots/services
terraform plan -var-file=../../environments/${ENVIRONMENT}.tfvars
# Should show task definition updates with new image digests
terraform apply -var-file=../../environments/${ENVIRONMENT}.tfvars
```

### 2.4 Smoke Tests

```bash
# Health check endpoint
curl -s https://${API_DOMAIN}/health | jq .

# Auth flow test
# (use test credentials for the environment)
```

---

## Step 3: Client Onboard

### 3.1 Configure Tenant

```bash
# Create tenant in platform
# (via admin API or DynamoDB direct)
```

### 3.2 DNS & Certificates

```bash
# Route53 records
# ACM certificate validation
# CloudFront distribution update
```

---

## Rollback Procedures

### Layer Rollback

```bash
cd roots/<layer>
terraform plan -destroy -var-file=../../environments/${ENVIRONMENT}.tfvars
# Review, then:
terraform destroy -var-file=../../environments/${ENVIRONMENT}.tfvars
```

### Full Account Teardown

Destroy in **reverse order**:

```
addons → cicd → services → data-foundation → edge → edge-identity → platform → network → global
```

After all Terraform resources destroyed:

```bash
# Delete state backend (bootstrap)
aws s3 rm s3://${BUCKET} --recursive
aws s3api delete-bucket --bucket "$BUCKET"
aws dynamodb delete-table --table-name "$TABLE"

# Or delete CloudFormation stack
aws cloudformation delete-stack --stack-name scanalyze-tf-state-backend
```

---

## Security Checklist

- [ ] No hardcoded ARNs, bucket names, or secrets
- [ ] No `.env`, `.tfstate`, or credentials committed
- [ ] IAM roles follow least privilege
- [ ] S3 buckets: versioned, encrypted, PAB enabled
- [ ] ECR repos: IMMUTABLE tags, scan-on-push
- [ ] No ECS deploy stage in CodePipeline
- [ ] No `ecs:*` or `iam:PassRole "*"` in CI/CD IAM
- [ ] Cognito as auth authority
- [ ] Runtime config (not build-time env vars) for frontend
- [ ] PII masking for CLABE, NSS, RFC, CURP

---

## File Reference

| File | Purpose |
|------|---------|
| `bootstrap/cfn-tf-state-backend.yaml` | CloudFormation template for state backend |
| `environments/<env>.tfvars` | Environment-specific variables |
| `roots/<layer>/backend.tfvars` | Backend config (gitignored, per-environment) |
| `roots/<layer>/backend.example.hcl` | Backend template for reference |
| `modules/` | Reusable Terraform modules |
| `tooling/` | Validation scripts (linters, safety checks) |
| `reports/` | Audit and reconciliation reports |
