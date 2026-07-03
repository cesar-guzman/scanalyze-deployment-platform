# Root: cicd
# Layer: 8 (after edge, before services)
# Scope: regional
# State: {deployment_id}/{region}/cicd/terraform.tfstate
#
# Build-only CI/CD pipelines for Scanalyze microservices.
# Terraform owns ECS — this layer ONLY builds and pushes images.

## Deployment Order

```
1. account-ready-gate
2. global
3. network
4. platform
5. data-foundation
6. edge-identity
7. edge
8. cicd              ← this root
9. build/promote
10. release manifest
11. services
12. addons
13. synthetic validation
```
