# Rollback Procedures

## Principles

1. **Rollback = new Terraform plan, not state revert.**
2. Rollback target is always a previously-validated set of image digests.
3. No rollback is automatic; all require explicit approval.
4. The `rollback` section of the deployment manifest defines the target state.

## Rollback Strategy: Digest Revert

The default rollback strategy (`digest-revert`) works by:

1. Reading `rollback.last_known_good_digests` from the deployment manifest.
2. Generating a new `services` layer Terraform plan with those digest values.
3. Reviewing the plan for unexpected changes.
4. Applying the plan with `--approve`.

```bash
# Generate rollback plan
scripts/deployment/scanalyze-deploy.sh plan-layer \
  --manifest /path/to/manifest.yaml \
  --layer services \
  --plan-dir /path/outside/repo/plans

# Review the plan
cat /path/outside/repo/plans/services-plan-summary.txt

# Apply with approval
SCANALYZE_ALLOW_LIVE=1 scripts/deployment/scanalyze-deploy.sh apply-layer \
  --manifest /path/to/manifest.yaml \
  --layer services \
  --plan-dir /path/outside/repo/plans \
  --approve --no-dry-run
```

## What Can Be Rolled Back

| Component | Rollback Method |
|---|---|
| ECS service images | Digest revert via Terraform plan |
| ECS task definitions | Terraform plan (new revision with old digest) |
| ALB listener rules | Terraform plan |
| SQS configuration | Terraform plan |

## What Cannot Be Rolled Back Easily

| Component | Reason | Mitigation |
|---|---|---|
| DynamoDB schema changes | Additive-only by convention | Schema changes are append-only |
| S3 object deletions | Versioning helps but not instant | Enable versioning |
| Cognito user pool changes | Some changes are irreversible | Test in non-production first |

## Rollback Timing

- **Target**: < 15 minutes from decision to completion.
- **ECS service update**: ~5 minutes (new task definition, rolling deployment).
- **Terraform plan + apply**: ~5-10 minutes.

## Post-Rollback Verification

1. Run `scanalyze-deploy.sh validate-live` to verify running digests.
2. Run `scanalyze-deploy.sh smoke-e2e` with synthetic document.
3. Update `rollback.last_known_good_digests` in manifest if the rolled-back state is confirmed stable.

## Anti-Patterns

- ❌ Reverting Terraform state (use new plan instead)
- ❌ Force-stopping ECS tasks without plan
- ❌ Rolling back infrastructure layers (global, network, platform) without full assessment
- ❌ Rollback without updating the deployment manifest
