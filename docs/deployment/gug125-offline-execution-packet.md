# GUG-125 Offline Execution Packet (GUG-366)

## Canonical Architecture
This documentation outlines the exact offline execution packet for GUG-125.
The packet is fully compatible with the existing `factory-v2` architecture and reuses:
- `live-execution-ledger.v1` (with the addition of `QUARANTINED`)
- `saved-plan.v1`
- `live-health-receipt.v1`
- `deployment-request.schema`

## Strict Network Boundaries
Execution requires strict zero-AWS offline preflight validations:
* `AWS_CLI_CALL_COUNT = 0`
* `AWS_SDK_CALL_COUNT = 0`
* `AWS_SESSION_COUNT = 0`
* `CLOUD_MUTATION_COUNT = 0`

## Rejection and Fail-Closed States
- An `UNKNOWN` or `QUARANTINED` outcome **never advances execution**.
- No `boto3` session can be created before human authorization.
- Maximum execution cost bounds are strictly enforced (`USD 50`).

## Owner Authorization
All executions are digest-bound via `gug125-owner-authorization-checkpoint.v1.schema.json`.
Any mutation to the plan, tree SHA, or inputs instantly invalidates authorization.
