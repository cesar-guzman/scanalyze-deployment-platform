# GUG-211 threat-model delta: durable founder bootstrap PEP

## Scope

This delta covers the management seed, durable intent/ledger, temporary founder
roles, exact CloudFormation effects, uncertainty and revocation. It does not
authorize production, customers, workload deployment, Terraform apply, or a
normal self-approval path.

| Threat | Control | Failure behavior |
|---|---|---|
| Local file or operator assertion authorizes Apply | DynamoDB is the sole live ledger; local receipts are digest inputs only | Deny before effect |
| Bootstrap creates its own trust store | Management-seeded service-managed StackSet; exact account/Region intersection | Seed mismatch/absence blocks temporary roles |
| Seed spreads to customers or Audit | Auto deployment disabled; exact account filter; foreign instance/target detection | Seed stops and reports P0 |
| Public state bucket precondition is changed by founder | Organization S3 policy enforces all BPA settings; founder roles deny direct PAB mutation | Plan/Apply denied |
| Replayed or concurrent Plan | Create-only item plus CAS on version/digest/state/counters | One succeeds; all others fail |
| Replayed or concurrent Apply | CAS consumes zero Apply attempts before ExecuteChangeSet | No second effect |
| Response loss causes retry | Lost terminal CAS response is reread by exact digest; an uncommitted claim is closed `UNCERTAIN` | Read-only reconciliation only |
| Operator substitutes Change Set | Exact name/ARN, stack, tags, status, original template SHA-256 and four resources re-read | Deny before effect |
| Operator edits table/account/Region | Constants, exact ARN, leading key and table-control readback | Deny |
| Plan can execute | Disjoint Plan policy plus explicit unsafe-action deny | AWS IAM deny |
| Apply can create/cancel or delete | Disjoint Apply policy and unsafe-action deny | AWS IAM deny |
| Temporary role administers itself | No IAM, SSO Admin or Organizations permissions | AWS IAM deny |
| Generic administrator is used operationally | Seed and identity lifecycle CLIs require exact task-specific SSO permission-set names | Deny before read/write |
| Identity administrator retargets customer or foreign permission set | Exact management identity, exact instance/account resources and GUG-211 resource tags; tool rejects all foreign inventory | Deny before mutation |
| Group membership hides a second authority path | Direct `USER` assignments only; no Identity Store mutation permission; zero-assignment readback | Deny/close blocked |
| Plan and Apply overlap | Opposite permission set must have zero assignments; exact time windows; Plan revocation only in quarantine gap | Activation/revocation denied |
| Old session outlives assignment | AWS `CurrentTime` explicit deny retained twelve hours | Requests denied despite cached session |
| Subject/profile spoofing | STS exact role plus Identity Center subject condition and intent digest | Deny |
| GSI/Scan leaks other exceptions | Single-key GetItem/PutItem only; no Scan/GSI/Delete/BatchWrite | AWS IAM and code deny |
| Evidence leaks operator or AWS locators | Private 0600 artifacts; sanitized output only | Publication rejected |
| Seed/table deletion erases evidence | Retain policy, deletion protection and PITR | Destructive change blocked/escalated |
| Revocation is asserted locally | Identity Center assignment/policy/provisioning readback plus `SUCCEEDED -> REVOKED` DynamoDB CAS | Exception remains open |
| Exception becomes a customer deployment bypass | Exact authority account, non-production and backend-only resource inventory | Deny |

## Residual risk

The founder operator still lacks an independently attributable human approver.
The management account performs the initial trust-store seed. Both facts are
explicitly recorded and limited to one non-production bootstrap. The exception
must be revoked after the first attempt and cannot authorize later customer or
production actions.

DynamoDB IAM binds the temporary roles to one table and one partition key, but
AWS does not provide an IAM condition key that forces `PutItem` callers to use
the reviewed compare-and-swap expression or validates the complete item
semantics. A malicious or compromised authority administrator/founder session
could therefore bypass the CLI protocol. The live run is blocked unless broad
administrator assignments are removed from the execution window and the
operator uses only the exact temporary permission set. GUG-211 protects the
reviewed workflow against concurrency, replay and ambiguous responses; it does
not claim malicious-management-administrator resistance. A trusted-compute PEP
plus independent administration is required before treating this control as a
production approval boundary.

## Evidence classes

- Implemented: reviewed repository artifacts.
- Locally validated: named local test/gate results only.
- CI validated: exact commit required checks only.
- Live validated: pending seed, role readback, CAS/effect, backend verification,
  revocation and main evidence.
- Production: **NO-GO**.
