# Scanalyze Environment Destroy Playbook

> **STATUS: HISTORICAL EVIDENCE — DO NOT EXECUTE.** This report preserves a
> legacy destroy record. It contains `-auto-approve`, imperative cleanup,
> outdated layer inputs/order, and state-surgery guidance that conflicts with
> current ownership and safety policy. A new decommissioning runbook requires
> separate design, approval, non-production validation, and review of every
> destructive plan. Terraform state is not rollback.

> **Clasificación:** Archivo histórico · No operativo
> **Versión:** 2.0  
> **Fecha:** 2026-07-07  
> **Autor:** Equipo de Plataforma Scanalyze  
> **Validado con:** 2 destroys reales en cuenta <ACCOUNT_ID> (Sandbox, Jul-05 y Jul-07)

---

## 1. Propósito

Este documento define el procedimiento end-to-end para destruir de forma segura y completa un ambiente Scanalyze desplegado en AWS. Está diseñado para ser reproducible, auditable y aplicable a cualquier deployment ID.

> **⚠️ PRECAUCIÓN:** Este procedimiento es **irreversible**. Toda la infraestructura, datos y configuraciones del ambiente serán eliminados permanentemente. Asegúrate de tener aprobación formal antes de ejecutar.

---

## 2. Arquitectura de Capas

Scanalyze utiliza una arquitectura de 9 capas Terraform con dependencias estrictas:

```
Layer 1: Addons        → SNS Alerts, SSM Parameters
Layer 2: CICD          → CodePipeline, CodeBuild, ECR, CodeCommit
Layer 3: Edge          → CloudFront, WAF, OAC
Layer 4: Edge Identity → API Gateway HTTP API, Cognito User Pool, VPC Link
Layer 5: Services      → ECS Services, Task Definitions, Target Groups
Layer 6: Data Found.   → S3 Buckets, DynamoDB, SQS Queues + DLQs, KMS
Layer 7: Platform      → ECS Cluster, ALB, Security Groups
Layer 8: Network       → VPC, Subnets, NAT Gateway, Internet Gateway
Layer 9: Global        → IAM Roles, Permissions Boundary Policy
```

**Orden de destroy (inverso):** 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9

---

## 3. Prerequisitos

### 3.1 Herramientas

| Herramienta | Versión Mínima | Verificación |
|-------------|---------------|--------------|
| Terraform | 1.14+ | `terraform version` |
| AWS CLI | 2.x | `aws --version` |
| Python | 3.9+ | `python3 --version` |
| jq | 1.6+ | `jq --version` |

### 3.2 Credenciales Requeridas

| Credential | Cuenta | Uso |
|-----------|--------|-----|
| `ScanalyzeSandboxDestroy` | Target (ej: <ACCOUNT_ID>) | Ejecutar `terraform destroy` |
| `AWSAdministratorAccess` | Management (ej: <MANAGEMENT_ACCOUNT_ID>) | Modificar Permission Sets si hay AccessDenied |

### 3.3 Permisos del Permission Set `ScanalyzeSandboxDestroy`

> **IMPORTANTE:** El PS debe incluir TODAS estas acciones. Fueron descubiertas durante el destroy real.

| SID | Acciones Clave | Resource Scope |
|-----|---------------|----------------|
| NetworkDestroy | `ec2:*` | `*` (`<AWS_REGION>`) |
| ECSDestroy | `ecs:DeleteCluster`, `ecs:PutClusterCapacityProviders`, etc. | `*` (`<AWS_REGION>`) |
| LoadBalancerDestroy | `elasticloadbalancing:*` | `*` (`<AWS_REGION>`) |
| DataFoundationDestroy | `s3:*`, `dynamodb:*`, `sqs:*` | `*` |
| S3BucketConfigDestroy | `s3:PutBucketVersioning`, `s3:PutBucketPublicAccessBlock`, `s3:PutEncryptionConfiguration`, `s3:PutLifecycleConfiguration`, `s3:DeleteBucket*` | `arn:aws:s3:::dep-*` |
| KMSDestroy | `kms:*` | `*` (`<AWS_REGION>`) |
| EdgeIdentityDestroy | `cognito-idp:*`, `apigateway:*`, `execute-api:*` | `*` (`<AWS_REGION>`) |
| EdgeGlobalDestroy | `cloudfront:*`, `wafv2:*` | `*` (global) |
| KMSRetireGrant | `kms:RetireGrant` | `*` (`<AWS_REGION>`) — **Requerido para eliminar ECR repos con KMS encryption** |
| IAMDestroy | `iam:*` | `arn:aws:iam::*:role/dep_*`, `arn:aws:iam::*:policy/dep_*` |
| MonitoringDestroy | `logs:*`, `cloudwatch:*` | `*` (`<AWS_REGION>`) |
| SNSDestroy | `sns:*` | `*` (`<AWS_REGION>`) |
| CICDDestroy | `codepipeline:*`, `codebuild:*`, `codecommit:*`, `ecr:*`, `ssm:*` | `*` (`<AWS_REGION>`) |
| TerraformStateAccess | `s3:*`, `dynamodb:*` | `scanalyze-*-tf-state`, `scanalyze-*-tf-locks` |

---

## 4. Procedimiento de Destroy

### Fase 0: Preparación (5 min)

#### 0.1 Configurar credenciales

```bash
export AWS_PROFILE="<APPROVED_DESTROY_PROFILE>"
export AWS_REGION="<AWS_REGION>"
aws sso login --profile "$AWS_PROFILE"

# Verificar identidad y cuenta
aws sts get-caller-identity --query Account --output text
```

#### 0.2 Definir variables del deployment

```bash
export DEPLOYMENT_ID="dep_<ULID>"
export ACCOUNT_ID="<ACCOUNT_ID>"
export REGION="<AWS_REGION>"
export ROOTS="/path/to/scanalyze-deployment-platform/roots"
```

#### 0.3 Generar digests placeholder

```bash
RELEASE_DIGEST=$(echo -n "destroy-run-$(date +%Y%m%d)" | shasum -a 256 | awk '{print "sha256:"$1}')
UPSTREAM_DIGEST=$(echo -n "container-platform-v1" | shasum -a 256 | awk '{print "sha256:"$1}')
```

---

### Fase 1: Pre-Destroy Cleanup (10 min)

> **⚠️ ADVERTENCIA:** NO omitas esta fase. S3 buckets con versioning y roles con inline policies bloquean terraform destroy.

#### 1.1 Vaciar S3 Buckets (incluyendo versiones y delete markers)

```bash
purge_bucket() {
  local BUCKET=$1
  echo "Purging $BUCKET..."
  while true; do
    OBJECTS=$(aws s3api list-object-versions --bucket "$BUCKET" --max-items 1000 --output json)
    VERSIONS=$(echo "$OBJECTS" | python3 -c "
import json,sys
data=json.load(sys.stdin)
objs=[{'Key':v['Key'],'VersionId':v['VersionId']} for v in data.get('Versions',[])]
objs+=[{'Key':d['Key'],'VersionId':d['VersionId']} for d in data.get('DeleteMarkers',[])]
if objs: print(json.dumps({'Objects':objs,'Quiet':True}))
else: print('EMPTY')
")
    [[ "$VERSIONS" == "EMPTY" ]] && break
    aws s3api delete-objects --bucket "$BUCKET" --delete "$VERSIONS" > /dev/null
  done
  echo "  Done: $BUCKET purged"
}

# Ejecutar para cada bucket del deployment
BUCKET_PREFIX=$(echo "$DEPLOYMENT_ID" | tr '_' '-' | tr '[:upper:]' '[:lower:]')
purge_bucket "${BUCKET_PREFIX}-frontend"
purge_bucket "${BUCKET_PREFIX}-documents"
purge_bucket "${BUCKET_PREFIX}-cicd-artifacts"
```

#### 1.2 Eliminar Inline Policies de Workload Roles

```bash
ROLES=$(aws iam list-roles \
  --query "Roles[?contains(RoleName,'${DEPLOYMENT_ID}')].RoleName" \
  --output text)

for ROLE in $ROLES; do
  POLICIES=$(aws iam list-role-policies --role-name "$ROLE" --query "PolicyNames" --output text)
  for POL in $POLICIES; do
    echo "  Removing $POL from $ROLE"
    aws iam delete-role-policy --role-name "$ROLE" --policy-name "$POL"
  done
done
echo "Inline policies removed"
```

#### 1.3 Vaciar ECR Repositories

> **⚠️ ADVERTENCIA:** Si los repos tienen imágenes, `terraform destroy` falla con `RepositoryNotEmptyException`.
> Si el PS no tiene `kms:RetireGrant`, los repos deben vaciarse y borrarse manualmente, luego usar `terraform state rm`.

```bash
SANITIZED_ID=$(echo "$DEPLOYMENT_ID" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
SERVICES="ingest-api ocr-worker postprocess-worker classifier-worker bank-worker personal-worker gov-worker"

for svc in $SERVICES; do
  REPO="${SANITIZED_ID}/scanalyze/${svc}"
  echo "Purging ECR repo: $REPO"
  
  IMAGES=$(aws ecr list-images --repository-name "$REPO" \
    --query 'imageIds[*]' --output json --region $REGION 2>/dev/null)
  
  if [[ "$IMAGES" != "[]" && -n "$IMAGES" ]]; then
    aws ecr batch-delete-image \
      --repository-name "$REPO" \
      --image-ids "$IMAGES" \
      --region $REGION > /dev/null
    echo "  ✅ Images deleted from $REPO"
  else
    echo "  ⏭️  $REPO already empty"
  fi
done
```

#### 1.4 Limpiar Tablas DynamoDB Orphan (creadas fuera de Terraform)

> Algunas tablas pueden haber sido creadas manualmente (ej: `batches`). Identifícalas y elimínalas antes del destroy de `data-foundation`.

```bash
# Listar tablas del deployment
aws dynamodb list-tables \
  --query "TableNames[?contains(@,'${DEPLOYMENT_ID}')]" \
  --output text --region $REGION

# Para cada tabla orphan (NO gestionada por Terraform):
# aws dynamodb delete-table --table-name <TABLE_NAME> --region $REGION
```

---

### Fase 2: Destroy por Capas (20-40 min)

#### Variables comunes

```bash
COMMON_VARS=(
  -var="deployment_id=${DEPLOYMENT_ID}"
  -var="account_id=${ACCOUNT_ID}"
  -var="region=${REGION}"
  -var="release_version=0.0.0-destroy"
  -var="release_manifest_digest=${RELEASE_DIGEST}"
  -var="upstream_contract_digest=${UPSTREAM_DIGEST}"
  -var="expected_upstream_digest=${UPSTREAM_DIGEST}"
  -var="upstream_schema_version=1"
)
```

> **REGLA CRÍTICA:** NUNCA uses `| grep` con terraform. Causa buffering de stdout y el comando parece colgarse. Usa `2>&1` para output completo.

#### Step 1: Addons (~1 min)

```bash
cd "$ROOTS/addons"
terraform destroy "${COMMON_VARS[@]}" -auto-approve 2>&1
```

#### Step 2: CICD (~10 min)

```bash
cd "$ROOTS/cicd"
terraform destroy "${COMMON_VARS[@]}" \
  -var="ecs_cluster_name=<CLUSTER_NAME>" \
  -var='microservices={}' \
  -auto-approve 2>&1
```

> CICD usa remote state en S3. Un lock aparentemente stale requiere investigar
> primero al owner y la ejecución activa; no usar `force-unlock` como operación
> rutinaria ni manipular state sin un procedimiento break-glass aprobado.

#### Step 3: Edge (~3 min)

```bash
cd "$ROOTS/edge"
terraform destroy "${COMMON_VARS[@]}" \
  -var="domain_name=" \
  -var="route53_zone_id=" \
  -var="api_gateway_endpoint=https://placeholder.execute-api.${REGION}.amazonaws.com" \
  -var="frontend_bucket_domain_name=placeholder.s3.amazonaws.com" \
  -var="frontend_bucket_arn=arn:aws:s3:::placeholder" \
  -var="cognito_domain=placeholder" \
  -var="cognito_spa_client_id=placeholder" \
  -var="cognito_user_pool_id=placeholder" \
  -auto-approve 2>&1
```

> CloudFront disable+delete toma ~2-3 minutos. Es normal ver "Still destroying...".

#### Step 4: Edge Identity (~30 sec)

```bash
cd "$ROOTS/edge-identity"
terraform destroy "${COMMON_VARS[@]}" \
  -var="domain_name=" \
  -var="vpc_id=<VPC_ID>" \
  -var='private_subnet_ids={"use1-az1":"<SUBNET_A>","use1-az2":"<SUBNET_B>"}' \
  -var="alb_listener_arn=<ALB_LISTENER_ARN>" \
  -var="alb_security_group_id=<SG_ID>" \
  -var="api_access_log_group_arn=" \
  -var="resource_server_identifier=scanalyze-ingest" \
  -var='api_scopes=[{"name":"documents.read","description":"Read"},{"name":"documents.write","description":"Write"}]' \
  -var='spa_callback_urls=["https://placeholder/callback"]' \
  -var='spa_logout_urls=["https://placeholder/login"]' \
  -auto-approve 2>&1
```

#### Step 5: Services (~3 min)

```bash
cd "$ROOTS/services"
terraform destroy "${COMMON_VARS[@]}" \
  -var="ecs_cluster_arn=arn:aws:ecs:${REGION}:${ACCOUNT_ID}:cluster/<CLUSTER>" \
  -var="ecs_task_execution_role_arn=arn:aws:iam::${ACCOUNT_ID}:role/${DEPLOYMENT_ID}-ecs-task-execution" \
  -var='workload_role_arns={}' \
  -var="vpc_id=<VPC_ID>" \
  -var='private_subnet_ids={"use1-az1":"<SUBNET_A>","use1-az2":"<SUBNET_B>"}' \
  -var="alb_listener_arn=<ALB_LISTENER_ARN>" \
  -var="alb_security_group_id=<SG_ID>" \
  -var='service_definitions=[]' \
  -var="customer_id=<CUSTOMER_ID>" \
  -auto-approve 2>&1
```

> **NOTA:** `customer_id` es obligatorio. Sin esta variable, Terraform pedirá input interactivo y el destroy se cuelga en modo no-interactivo.

#### Step 6: Data Foundation (~2 min)

```bash
cd "$ROOTS/data-foundation"
terraform destroy "${COMMON_VARS[@]}" -auto-approve 2>&1
```

#### Step 7: Platform (~30 sec)

```bash
cd "$ROOTS/platform"
terraform destroy "${COMMON_VARS[@]}" \
  -var="vpc_id=<VPC_ID>" \
  -var='private_subnet_ids={"use1-az1":"<SUBNET_A>","use1-az2":"<SUBNET_B>"}' \
  -var="vpc_cidr_block=10.0.0.0/16" \
  -var="internal_certificate_arn=" \
  -auto-approve 2>&1
```

#### Step 8: Network (~2 min)

```bash
cd "$ROOTS/network"
terraform destroy "${COMMON_VARS[@]}" -auto-approve 2>&1
```

> NAT Gateway release toma ~1-2 minutos.

#### Step 9: Global (~30 sec)

```bash
cd "$ROOTS/global"
terraform destroy "${COMMON_VARS[@]}" -auto-approve 2>&1
```

---

### Fase 3: Verificación Post-Destroy (5 min)

#### 3.1 Verificar States Vacíos

```bash
for layer in addons cicd edge edge-identity services data-foundation platform network global; do
  RESOURCES=$(cd "$ROOTS/$layer" && terraform state list 2>/dev/null | wc -l | tr -d ' ')
  printf "  %-20s %s resources\n" "$layer" "$RESOURCES"
done
# TODOS deben ser 0
```

#### 3.2 Verificar Recursos Orphan en AWS

```bash
echo "CloudFront:" && aws cloudfront list-distributions \
  --query "DistributionList.Items[*].DomainName" --output text
echo "ECS Clusters:" && aws ecs list-clusters --output text
echo "VPCs (non-default):" && aws ec2 describe-vpcs \
  --filters "Name=isDefault,Values=false" --query "Vpcs[*].VpcId" --output text
echo "S3 (dep-):" && aws s3api list-buckets \
  --query "Buckets[?contains(Name,'dep-')].Name" --output text
echo "Cognito:" && aws cognito-idp list-user-pools \
  --max-results 10 --query "UserPools[*].Name" --output text
echo "NAT GWs:" && aws ec2 describe-nat-gateways \
  --filter "Name=state,Values=available" --query "NatGateways[*].NatGatewayId" --output text
echo "Log Groups:" && aws logs describe-log-groups \
  --log-group-name-prefix "/ecs/dep" --query "logGroups[*].logGroupName" --output text
```

#### 3.3 Cleanup del TF State Backend (Opcional)

```bash
# Solo DESPUÉS de confirmar que TODOS los layers tienen 0 resources
purge_bucket "scanalyze-${BUCKET_PREFIX}-tf-state"
aws s3 rb "s3://scanalyze-${BUCKET_PREFIX}-tf-state"
aws dynamodb delete-table --table-name "scanalyze-${BUCKET_PREFIX}-tf-locks"
```

---

## 5. Troubleshooting

### 5.1 Errores Comunes

| Error | Causa | Solución |
|-------|-------|----------|
| `BucketNotEmpty` | S3 tiene versiones/delete markers | Ejecutar `purge_bucket()` con loop de versiones |
| `RepositoryNotEmptyException` | ECR repos tienen imágenes Docker | Ejecutar paso 1.3 (ECR purge) antes de CICD destroy |
| `KmsException: RetireGrant` | PS no tiene `kms:RetireGrant` | Agregar permiso al PS, o si repos ya están borrados: `terraform state rm` los ECR resources |
| `AccessDenied: sns:DeleteTopic` | PS no tiene SNS permissions | Agregar `sns:*` al PS via admin |
| `AccessDenied: s3:PutBucketVersioning` | PS no tiene S3 config permissions | Agregar S3 bucket config actions al PS |
| `AccessDenied: ecs:PutClusterCapacityProviders` | PS no tiene ECS detach permission | Agregar acción al statement ECSDestroy |
| `Error acquiring state lock` | Lock stale de sesión anterior | `terraform force-unlock -force <LOCK_ID>` |
| `ExpiredToken` | STS session expiró (1 hora) | Obtener credenciales frescas del PS |
| Terraform "colgado" con `\| grep` o `\| tail` | stdout buffering por pipe | **NUNCA** usar pipes con terraform. Usar `2>&1` sin pipes |
| `var.microservices: Enter a value` | Variable interactiva no provista | Agregar `-var='microservices={}'` |
| `var.customer_id: Enter a value` | Variable services no provista | Agregar `-var="customer_id=<CUSTOMER_ID>"` |
| `var.cognito_domain: Enter a value` | Variable edge no provista | Agregar `-var="cognito_domain=placeholder"` (ver Step 3) |

### 5.2 Cómo Agregar Permisos al PS (desde cuenta admin)

```bash
INSTANCE_ARN="arn:aws:sso:::instance/<INSTANCE_ID>"
PS_ARN="arn:aws:sso:::permissionSet/<INSTANCE_ID>/<PS_ID>"

# 1. Obtener policy actual
CURRENT=$(aws sso-admin get-inline-policy-for-permission-set \
  --instance-arn "$INSTANCE_ARN" \
  --permission-set-arn "$PS_ARN" \
  --query "InlinePolicy" --output text)

# 2. Modificar (agregar statement)
UPDATED=$(echo "$CURRENT" | python3 -c "
import json,sys
pol = json.load(sys.stdin)
pol['Statement'].append({
    'Sid': 'NewPermission',
    'Effect': 'Allow',
    'Action': ['service:Action'],
    'Resource': '*'
})
print(json.dumps(pol))
")

# 3. Aplicar y provisionar
aws sso-admin put-inline-policy-to-permission-set \
  --instance-arn "$INSTANCE_ARN" \
  --permission-set-arn "$PS_ARN" \
  --inline-policy "$UPDATED"

aws sso-admin provision-permission-set \
  --instance-arn "$INSTANCE_ARN" \
  --permission-set-arn "$PS_ARN" \
  --target-type ALL_PROVISIONED_ACCOUNTS

sleep 15  # Esperar propagación
```

---

## 6. Evidencia de Destroys Reales

### 6.1 Destroy #2 — Sandbox 2026-07-07 (Más reciente)

| Campo | Valor |
|-------|-------|
| Cuenta | <ACCOUNT_ID> |
| Deployment ID | dep_<ULID> |
| Inicio | 2026-07-07 05:05 UTC |
| Fin | 2026-07-07 05:44 UTC |
| Duración | ~39 minutos |
| Resources destruidos | 194+ (100%) |
| Errores resueltos | 5 |

| # | Layer | Resources | Duración | Errores |
|---|-------|-----------|----------|---------|
| 1 | addons | 23 | ~1 min | Ninguno |
| 2 | cicd | 71+ | ~3 min | ECR repos no vacíos + KMS RetireGrant |
| 3 | edge | 7 | ~3 min | Vars faltantes (cognito_domain) + pipe buffering |
| 4 | edge-identity | 13 | ~8s | Ninguno |
| 5 | services | 76 | ~3 min | customer_id faltante |
| 6 | data-foundation | 26 | ~3 min | SQS queue deletion lento |
| 7 | platform | 11 | ~30s | Ninguno |
| 8 | network | 27 | ~2.5 min | VPC endpoints lentos |
| 9 | global | 11 | ~2s | Ninguno |
| **Total** | | **~194+** | **~39 min** | **5 resueltos** |

Pre-destroy cleanup adicional requerido:
- 3 S3 buckets vaciados (frontend, documents, cicd-artifacts)
- 7 ECR repos vaciados (7 microservicios)
- 7 inline policies removidas de workload roles
- 1 tabla DynamoDB orphan eliminada (batches, creada manualmente)

### 6.2 Destroy #1 — Sandbox 2026-07-05 (Primer destroy)

| Campo | Valor |
|-------|-------|
| Cuenta | <ACCOUNT_ID> |
| Deployment ID | dep_<ULID> |
| Inicio | 2026-07-04 13:30 UTC |
| Fin | 2026-07-05 16:35 UTC |
| Resources destruidos | 165/165 (100%) |
| Errores resueltos | 4 |

| # | Layer | Resources | Duración | Errores |
|---|-------|-----------|----------|---------|
| 1 | addons | 23 | 1 min | SNS:DeleteTopic (resuelto) |
| 2 | cicd | 71 | 10 min | State lock, microservices prompt |
| 3 | edge | 5 | 2m48s | Ninguno |
| 4 | edge-identity | 12 | 8s | Ninguno |
| 5 | services | 6 | 1 min | Ninguno |
| 6 | data-foundation | 16 | 2 min | S3 versioning + bucket configs |
| 7 | platform | 6 | 28s | ecs:PutClusterCapacityProviders |
| 8 | network | 15 | 2 min | Ninguno |
| 9 | global | 11 | 2s | Ninguno |
| **Total** | | **165** | **~20 min** | **4 resueltos** |

### Lecciones Aprendidas (Ambos Destroys)

1. **NUNCA usar pipes (`| grep`, `| tail`) con terraform** — Causa buffering de stdout y el proceso parece colgado
2. **S3 versioned buckets necesitan deep purge** — `aws s3 rm` solo crea delete markers, usar `purge_bucket()` con loop de versiones
3. **ECR repos deben vaciarse antes del destroy** — `RepositoryNotEmptyException` bloquea CICD destroy
4. **`kms:RetireGrant` necesario para ECR cleanup** — Sin este permiso, workaround es `terraform state rm` + borrado manual
5. **Remote state locks persisten** — Usar `force-unlock` antes de retry
6. **TODAS las variables deben ser explícitas** — Verificar con `grep 'variable "' *.tf` antes de cada layer
7. **PS necesita permisos de "undo"** — No solo delete, también put/modify
8. **Tablas creadas fuera de Terraform son orphans** — Deben limpiarse manualmente en pre-destroy

---

## 7. Checklist de Aprobación Pre-Destroy

- [ ] Aprobación del responsable del ambiente
- [ ] Backup de datos críticos (si aplica)
- [ ] Verificar que no hay pipelines activos
- [ ] Verificar que no hay usuarios activos en Cognito
- [ ] Permission Set tiene todos los permisos de §3.3
- [ ] Credenciales STS válidas (< 1 hora de expiración)
- [ ] S3 buckets vaciados (incluyendo versiones)
- [ ] Inline policies removidas de workload roles

---

> **Próxima revisión:** Después del siguiente destroy de ambiente  
> **Contacto:** Equipo de Plataforma Scanalyze  
> **Playbook complementario:** [Enterprise Client Deployment Playbook](../playbooks/enterprise-client-deployment.md)
