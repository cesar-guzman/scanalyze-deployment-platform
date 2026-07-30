# GUG-210 Threat-Model Delta: Change Set IAM Binding

## Assets and boundaries

- canonical platform-authority stack;
- exact predeclared Change Set name;
- full UUID-bearing Change Set ARN in the controlled plan;
- independent Plan and Apply Identity Center principals;
- exact request tags and reviewed resource inventory.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| IAM uses an unsupported Change Set resource shape | Create/Delete/Execute require the exact stack ARN | Renderer denies the policy |
| Operator substitutes another Change Set | Exact `cloudformation:ChangeSetName`; full ARN/UUID re-read by the PEP | Request is denied before effect |
| Name is reused for another instance | Signed plan retains the full ARN, digest and UUID | Mismatch requires a new plan |
| Creation drops governance tags | Exact request tags, tag keys and create-bound `TagResource` | Create is denied |
| Apply receives Plan authority | Structural validator rejects mixed mutation action sets | Policy is not emitted |
| Wildcard or foreign account/region is introduced | Canonical binding renders account, region, stack and name | Policy is denied locally |

## Residual risk

IAM cannot bind these three actions to the Change Set UUID. The runtime PEP
must re-read the exact ARN and compare every reviewed field immediately before
execution. Repository validation is not AWS live evidence.

## Evidence boundary

The change is implemented and validated offline only. It creates no permission
set, assignment, Change Set, stack, S3 bucket, KMS key, Terraform state, or
customer resource. Production remains **NO-GO**.
