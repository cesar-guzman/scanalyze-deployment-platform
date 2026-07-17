# GUG-207 Threat-Model Delta: KMS Alias Authorization

## Assets and trust boundaries

- exact platform-authority state alias;
- tagged state KMS key;
- reviewed CloudFormation Change Set;
- short-lived Apply permission-set session;
- CloudFormation forward-access context.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Unsupported alias condition silently removes authorization | Alias-resource statement has no conditions; `kms:RequestAlias` is forbidden on alias-management actions; contract tests validate both statement shapes | CI fails before publication |
| Principal manages another alias | Alias-side permission names one exact account/region alias ARN | AWS denies the foreign alias |
| Exact alias is bound to a foreign or unreviewed key | Key-side permission requires exact account/region and four canonical resource tags | AWS denies the affected key |
| Direct KMS mutation bypasses the Change Set | Required key-side statement requires `aws:CalledVia` to include CloudFormation; KMS also requires the exact alias-side permission | Direct request is denied on the key authorization |
| Rollback cannot remove the alias | Key-side and alias-side statements both include `kms:DeleteAlias` | CloudFormation can reconcile the reviewed resource |
| Update swaps to an unauthorized key | KMS must authorize the exact alias plus current and new keys; both keys must satisfy the tag boundary | Update is denied |
| Static policy validation is mistaken for runtime proof | Evidence classes separate syntax/CI from live authorization | Live status remains unvalidated |

## Residual risks

- Resource tags are part of the authorization boundary. Separate policy
  statements must continue to prevent an Apply principal from adding canonical
  ownership tags to an unrelated key through a direct request.
- The alias-resource statement intentionally has no condition because KMS does
  not support condition keys there. Its exact ARN and the independently
  required, conditioned key-side statement form one indivisible authorization.
- `aws:CalledVia` proves a CloudFormation forward-access path, not that an
  arbitrary Change Set is approved. The separate exact Change Set ARN and
  Plan/Apply contracts remain mandatory.
- IAM Access Analyzer validates policy structure but does not prove that a
  condition key is present in every service operation request.

## Evidence boundary

Synthetic policy tests and required CI are local/CI evidence only. No AWS
permission set, Change Set, key, alias, backend, deployment, or live
authorization was created or exercised by GUG-207. Production remains
**NO-GO**.
