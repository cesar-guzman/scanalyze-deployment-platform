# Terraform Roots

> **Status**: Scaffold only. No `.tf` files until M0 acceptance gates pass.

Each root corresponds to one Terraform state file and one layer in the
deployment stack.

## Planned Roots

```
roots/
├── global/             # Layer 0: IAM roles, permissions boundaries
├── network/            # Layer 1: VPC, subnets, endpoints (regional)
├── platform/           # Layer 2: ECS, ALB (regional)
├── data-foundation/    # Layer 3: DynamoDB, S3, SQS, KMS (regional)
├── services/           # Layer 4: ECS services + task defs (regional)
├── edge-identity/      # Layer 5a: Cognito, API Gateway (regional)
├── edge/               # Edge: CloudFront, Route53, WAF (global)
└── addons/             # Layer 5b: Monitoring, dashboards (regional)
```
