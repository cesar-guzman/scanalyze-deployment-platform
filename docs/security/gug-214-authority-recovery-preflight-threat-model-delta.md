# GUG-214 threat-model delta: authority recovery preflight

## Scope

This delta covers read-only adoption of an existing platform-authority review
shell, active Change Set inventory, founder Plan race reduction and exact
DynamoDB control reads. It does not authorize seed, policy provisioning,
Change Set creation or execution, Terraform apply, customer deployment,
resource deletion or production.

| Threat | Control | Failure behavior |
|---|---|---|
| Empty stack resources are mistaken for zero Change Sets | Paginated `ListChangeSets` plus exact zero-active requirement | Deny recovery and Plan |
| First page hides a later active Change Set | Consume every page; reject malformed, empty-loop or repeated continuation tokens | Deny as ambiguous |
| Plan role gains broad CloudFormation inventory | Separate `ListChangeSets` statement on the exact stack ARN | AWS denies foreign stacks |
| A stale or foreign Change Set races founder Plan | Inventory before the Plan CAS and again immediately before `CreateChangeSet` | Deny before CAS or consume attempt as failed/uncertain; no retry |
| Operator substitutes a ReadOnly session for Plan | Exact SSO permission-set and STS checks remain mandatory | Deny before operational claim |
| ReadOnly becomes standing Scanalyze authority | Treat it as independent evidence only; never attach its managed policy to Scanalyze roles | Evidence remains non-authoritative |
| Empty shell causes guessed KMS/S3/DynamoDB reads | Resource reads require trusted physical IDs or outputs; no naming inference | Skip resource read and remain blocked |
| Missing account Public Access Block is treated as default secure | Require present all-true account control | Recovery blocks without mutation |
| Ledger PITR is assumed from table status | Exact-table `DescribeTable` plus `DescribeContinuousBackups` | Founder Plan/Apply deny |
| Exact-table metadata read expands into data access | No Scan, Query, backup mutation, restore, delete or wildcard table resources | AWS IAM deny |
| Enumeration output leaks resource locators | Emit sanitized counts and state classes only | Publication rejected |
| Recovery deletes evidence to reach a clean state | No delete or auto-remediation path; retained shell and evidence require separate review | Stop and reconcile read-only |
| Empty shell retains a broad CloudFormation service role | Shared stack contract requires `RoleARN` absent before recovery, Plan and Apply; recheck immediately before protected effect | Deny as inherited authority; quarantine shell |
| Shell routes lifecycle events to a foreign topic | Require `NotificationARNs` absent or exactly empty | Deny ambiguous/foreign notification metadata |
| Nested shell imports parent/root authority | Reject any `ParentId` or `RootId` metadata | Deny nested shell adoption |

## Residual risk

CloudFormation cannot atomically couple "zero existing Change Sets" with
`CreateChangeSet`. The second inventory is immediately before create and the
durable CAS serializes reviewed PEP clients, but a separately authorized
foreign writer could still win that interval. Exact-name IAM, post-create
readback and the one-attempt ledger bound impact; they do not eliminate the
race. Any unexpected Change Set or resource is a P0 stop and permits only
read-only reconciliation.

The metadata recheck also cannot make CloudFormation and ExecuteChangeSet
atomic. Removing service-role and nested-stack authority from the accepted
state eliminates the known confused-deputy path; a separately authorized actor
changing stack metadata after the last read remains a governance failure and
must be detected by subsequent reconciliation.

`ListChangeSets` proves only the active inventory returned by AWS at the time of
the paginated call. It is not a historical audit. Audit history and deletion
evidence must be reviewed through their separately governed sources.

## Evidence and data handling

- Store raw AWS responses, stack IDs, ARNs and Change Set names only in the
  approved private evidence location.
- Publish only sanitized counts, state classes, commit/PR identifiers and gate
  outcomes.
- Keep general ReadOnly observations separate from exact Plan/Apply evidence.
- Do not infer physical resources from placeholders, templates or expected
  naming when the shell has no trusted outputs.

## Evidence classes

- Implemented: repository implementation in the reviewed commit only.
- Locally validated: named local gates for that commit only.
- CI validated: required checks for the exact PR commit only.
- Live validated: blocked pending merged policy provisioning and an authorized
  canonical preflight under the exact role.
- Production: **NO-GO**.
