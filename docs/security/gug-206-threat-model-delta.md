# GUG-206 Threat-Model Delta: Dedicated Authority Bootstrap

## Assets and trust boundaries

- short-lived Identity Center bootstrap and approver sessions;
- exact CloudFormation Change Set;
- Terraform state bucket/key and native lockfile;
- state KMS key and key policy;
- private plan, approval, verification, and backend records;
- organization-owned Control Tower, Config, CloudTrail, GuardDuty, and Security
  Hub boundaries.

The platform-authority account is separate from every customer destination and
from organization audit/log-archive accounts.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Wrong account or region | STS equality, template Rules, derived bucket name | Deny before Change Set or apply |
| Customer account becomes authority | Exact destination exclusion and unique account list | Deny binding |
| Request-supplied backend/key | Fixed stack/key and account-region-derived bucket | Deny binding |
| Legacy or concurrent locking | Native S3 lockfile only; no DynamoDB table | Template/test failure |
| Plan substitution | Change Set ARN, resource changes, template digest, plan digest | Deny apply |
| Self approval | Distinct operator IDs and hashed live STS principals | Deny approval/apply |
| Direct API separation or plan substitution | Disjoint roles plus Apply policy rendered to the exact Change Set ARN | AWS authorization denies every other Change Set |
| Static credential bootstrap | Ambient key/token variables rejected; live STS ARN must be an `AWSReservedSSO_*` session | Deny before protected operation |
| Profile-name spoofing | Canonical Plan/Apply permission-set role checked from live STS, never profile text | Deny mutation |
| Public state exposure | Account and bucket public blocking, bucket owner enforced, cross-account deny | Verification fails closed |
| Wrong/missing encryption | Exact SSE-KMS header/key denies, default encryption, key rotation | Write denied or verification fails |
| Arbitrary S3 data storage | Only exact state and `.tflock` object keys accepted | Write denied |
| State deletion | Bucket policy deny and retained resources | Delete denied |
| Lost apply response | Read-only verification; no retry | Reconciliation required |
| Sensitive evidence disclosure | 0600 external files; sanitized stdout; repository/Linear exclusions | No receipt generated in repo |
| Organization-control conflict | GuardDuty/Security Hub/organization trails remain delegated-admin owned | Member-level activation blocked |

## Residual risks

- Identity Center principal digests prove distinct AWS sessions, not an HR
  identity separation policy; permission-set assignments and audit evidence
  must enforce different humans.
- The account-level S3 public block is not a CloudFormation resource and is an
  explicitly ordered action in the bootstrap orchestrator.
- Retain semantics require a separately authorized manual decommission.
- A broad administrator permission set can bypass least privilege; live
  execution remains blocked until both disjoint permission sets have
  non-overlapping assignments and independent review.

## Evidence boundary

Synthetic tests and template validation are local/CI evidence. Account
inventory is read-only live evidence. Only an authorized exact Change Set,
independent approval, execution, and post-verification can establish backend
live validation. Neither backend validation nor platform-authority creation
proves customer deployment isolation. Production remains **NO-GO**.
