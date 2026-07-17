# GUG-208 Threat-Model Delta: Identity Center Name Contract

## Assets and trust boundaries

- canonical Plan and Apply permission-set identities;
- account-local `AWSReservedSSO_*` roles created by IAM Identity Center;
- independent initiator and approver groups;
- reviewed CloudFormation Change Set and bootstrap evidence.

The only accepted names are `ScanalyzeAuthorityBootstrapPlan` and
`ScanalyzeAuthorityBootstrapApply`; they are deliberately portable across
customer authority accounts and are not parameterized by tenant input.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Service rejects an overlength name after local validation | Runtime and tests enforce the AWS 1-to-32-character ASCII contract | Invalid name fails before caller authorization or AWS mutation |
| Operator truncates or aliases a name | Two exact canonical constants; legacy and decorated names are negative fixtures | Caller is denied |
| Apply principal enters a Plan path, or vice versa | Exact permission-set equality and distinct names/groups | Cross-role session is denied |
| Profile label is treated as identity proof | Live STS ARN must match the exact account-local `AWSReservedSSO_*` role | Spoofed/local label has no authority |
| Customer or environment input changes authority | Names contain no request, customer, account, region, or environment component | Request-selected name is unsupported |
| Rejected create is mistaken for live validation | Evidence records the atomic rejection and zero-resource readback separately | GUG-206 remains blocked |

## Residual risks

- AWS role suffixes and assignments exist only after the separately governed
  Identity Center operation. Repository tests cannot prove those live values.
- Exact names do not prove group independence. Membership and assignment
  inventory must remain a separate live gate.
- A valid permission-set name does not authorize the CloudFormation Change Set
  or any backend resource.

## Evidence boundary

The first authorized create attempt was rejected by the service before
resource creation because the former Plan name exceeded 32 characters. Apply
was not attempted and readback found no permission set or assignment. GUG-208
adds local contract enforcement only. No backend, deployment, customer
resource, or production change is authorized. Production remains **NO-GO**.
