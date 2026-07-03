# M3-CICD — Ownership Matrix

## Resource Ownership (Platform v2)

| Recurso | Owner Layer | State Key | Contract |
|---------|-------------|-----------|----------|
| VPC, Subnets, NAT | `network` | `{dep_id}/{region}/network` | network/v1 |
| ECS Cluster | `platform` | `{dep_id}/{region}/platform` | platform/v1 |
| ALB, Listeners, SGs | `platform` | `{dep_id}/{region}/platform` | platform/v1 |
| S3 Data Buckets | `data-foundation` | `{dep_id}/{region}/data-foundation` | data-foundation/v1 |
| DynamoDB Tables | `data-foundation` | `{dep_id}/{region}/data-foundation` | data-foundation/v1 |
| **ECS Task Definitions** | **`services`** | `{dep_id}/{region}/services` | services/v1 |
| **ECS Services** | **`services`** | `{dep_id}/{region}/services` | services/v1 |
| ALB Target Groups | `services` | `{dep_id}/{region}/services` | services/v1 |
| ALB Listener Rules | `services` | `{dep_id}/{region}/services` | services/v1 |
| Cognito User Pool | `edge-identity` | `{dep_id}/{region}/edge-identity` | edge-identity/v1 |
| API Gateway | `edge-identity` | `{dep_id}/{region}/edge-identity` | edge-identity/v1 |
| CloudFront | `edge` | `{dep_id}/global/edge` | edge/v1 |
| WAF WebACL | `edge` | `{dep_id}/global/edge` | edge/v1 |
| S3 Frontend | `edge` | `{dep_id}/global/edge` | edge/v1 |
| **CodePipeline** | **`cicd`** | `{dep_id}/{region}/cicd` | cicd/v1 |
| **CodeBuild** | **`cicd`** | `{dep_id}/{region}/cicd` | cicd/v1 |
| **CodeCommit Repos** | **`cicd`** | `{dep_id}/{region}/cicd` | cicd/v1 |
| **ECR Repositories** | **`cicd`** | `{dep_id}/{region}/cicd` | cicd/v1 |
| **S3 Artifacts** | **`cicd`** | `{dep_id}/{region}/cicd` | cicd/v1 |
| **KMS Artifacts Key** | **`cicd`** | `{dep_id}/{region}/cicd` | cicd/v1 |
| **Release Metadata SSM** | **`cicd`** | `{dep_id}/{region}/cicd` | cicd/v1 |
| SSM Addons | `addons` | `{dep_id}/{region}/addons` | addons/v1 |

## Cross-Layer Contracts

```
platform/v1 ──► cicd/v1      (ecs_cluster_name via SSM)
cicd/v1     ──► services/v1  (ecr_repo_urls, image digests via SSM)
edge-identity/v1 ──► edge/v1 (cognito config, api gateway)
data-foundation/v1 ──► services/v1 (bucket names, table names)
```

## Conflict Matrix

| Conflicto | Legacy (ci-cd-micros) | Platform v2 | Status |
|-----------|----------------------|-------------|--------|
| ECS task def owner | Pipeline + Terraform | Terraform only | 🔴 Resuelto en v2 |
| ECS service owner | Pipeline + Terraform | Terraform only | 🔴 Resuelto en v2 |
| ECR repo owner | platform-scanalyze (legacy) | cicd layer | 🔴 Resuelto en v2 |
| CodeCommit owner | Manual / no Terraform | cicd layer | 🔴 Resuelto en v2 |
| Image tagging | Commit SHA (mutable) | SHA + digest (immutable) | ⚠️ Pending enforcement |
