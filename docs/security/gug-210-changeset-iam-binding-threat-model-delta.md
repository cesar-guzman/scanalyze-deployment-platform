# GUG-210 Threat-Model Delta: Change Set IAM Binding

## Assets and boundaries

- canonical platform-authority stack;
- exact predeclared Change Set name;
- full UUID-bearing Change Set ARN in the controlled Plan artifact;
- SHA-256 of the exact `Original` template read back by that full ARN during
  Plan;
- the single parser that derives an immutable typed identity and exact bare
  name from that ARN;
- independent Plan and Apply Identity Center principals;
- exact request tags and reviewed resource inventory.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| IAM and the runtime authorize different request fields | Create and Execute use the exact stack ARN plus `cloudformation:ChangeSetName`; Apply sends that same bare name with the exact stack | Policy rendering or local request validation fails |
| Policy rendering and Apply parse the ARN differently | Both call one canonical parser that validates partition, region, account, name, UUID shape and the complete ARN | No policy or AWS mutation request is emitted |
| Operator supplies a bare name or caller-controlled name | Apply accepts only the controlled full ARN from the Plan and derives the name locally | Input is rejected before AWS access |
| Operator substitutes a foreign partition, account or region | The parser binds every ARN coordinate to the canonical bootstrap binding | Input is rejected before AWS access |
| Malformed, expired or internally mismatched local evidence triggers provider access | Apply rejects duplicate keys and validates Plan/approval digests, bindings, template, time windows and the full ARN before constructing an AWS client | No STS, CloudFormation or other AWS request is possible |
| Plan digest refers only to an unbound local template | Plan reads `Original` with the full Change Set ARN, requires exact equality with the local template and hashes that body; Apply rechecks the local digest and the same full ARN | Plan is not emitted, or Apply fails before Execute |
| Name is reused for another Change Set UUID | The Plan retains the full ARN; Apply re-reads that exact ARN immediately before execution | Mismatch or missing Change Set fails closed and requires a new Plan |
| A prior AWS mutation makes the first read stale | Apply checks the exact empty stack after Public Access Block, then makes full-ARN `DescribeChangeSet` the last CloudFormation call before Execute and rechecks approval time locally | Any drift or newly expired approval fails before Execute |
| Creation drops governance tags | Exact request tags, tag keys and create-bound `TagResource` | Create is denied |
| Apply receives Plan authority | Structural validator rejects mixed mutation action sets | Policy is not emitted |
| Wildcard or foreign account/region is introduced | Canonical binding renders account, region, stack and name | Policy is denied locally |
| Legacy normal-path cancellation bypasses the retirement broker | The compatibility `cancel` command fails locally with `NORMAL_CANCEL_RETIRED` before Plan loading, identity discovery, ledger writes or AWS access | No `DeleteChangeSet` request is possible from the normal CLI; GUG-215 remains the sole retirement authority |
| Ambiguous Execute result causes a duplicate mutation | Apply issues one Execute request, sets provider attempts to one and contains no mutation retry | Operator uses read-only reconciliation; a second Execute is not automatic |
| Diagnostics disclose the controlled ARN or AWS output | Local binding and retired-cancel diagnostics are fixed and sanitized | Raw identifiers and payloads are not printed by these failure paths |

## Residual risk

IAM cannot bind Create or Execute to the Change Set UUID. The runtime PEP must
therefore retain the full ARN as evidence, re-read that exact ARN after the
preceding AWS mutation, and compare every reviewed field before execution. A
same-name replacement between the last read and Execute remains a bounded
AWS-side race; the exact empty-stack readback, one-shot mutation rule and
read-only ambiguous-result reconciliation reduce its impact without claiming
atomicity. The Plan and approval digests bind repository records but are not
digital signatures: a coordinated rewrite to another valid same-name UUID and
recomputation of both digests is locally indistinguishable. Custody of both
reviewed files and the independent live approver therefore remain operational
prerequisites, and publication requires explicit owner acceptance of that trust
boundary or a separately scoped external signature, MAC, or protected ledger.
Repository validation is not AWS live evidence.

## Evidence boundary

The controls are exercised with synthetic clients and fake executables only.
They do not prove live IAM evaluation, Identity Center assignment, AWS API
behavior, deployment, or production readiness. The change creates no
permission set, assignment, Change Set, stack, S3 bucket, KMS key, Terraform
state, or customer resource. Production remains **NO-GO**.
