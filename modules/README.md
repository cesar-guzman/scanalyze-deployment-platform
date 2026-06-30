# Terraform Modules

> **Status**: Scaffold only. No `.tf` files until M0 acceptance gates pass.

Modules will be implemented in M1+ milestones after the schemas, policies,
contracts, and tests from M0 are verified.

## Planned Modules

| Module | Layer | Description |
|---|---|---|
| `network` | network | VPC, subnets, NAT, VPC endpoints |
| `platform` | platform | ECS cluster, ALB, security groups |
| `data-foundation` | data-foundation | DynamoDB, S3, SQS, KMS |
| `services` | services | ECS services + task definitions |
| `edge-identity` | edge-identity | Cognito, API Gateway, Lambda authorizer |
| `edge` | edge | CloudFront, Route53, WAF, ACM |
| `addons` | addons | CloudWatch dashboards, alarms |
