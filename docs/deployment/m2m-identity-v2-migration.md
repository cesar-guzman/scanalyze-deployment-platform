# M2M Identity v2 Migration Inventory and Runbook

> **Status:** repository migration plan; no live migration authorized
> **Owner issues:** GUG-102, GUG-93, GUG-114, GUG-117
> **Production:** NO-GO

## Purpose

This runbook makes the transition from customer-only M2M mapping to an exact
customer/deployment binding repeatable across deployments. It contains no real
customer, account, client, token, ARN, task-definition, state, or plan data.

## Legacy inventory classes

| Legacy class | Detection | Required treatment | Owner |
|---|---|---|---|
| Identity v1 document with a readable customer slug | `schema_version=1` | Retain as v1; create a separately reviewed v2 record before M2M enablement | GUG-102 / deployment registry |
| `M2M_CLIENT_TENANT_MAP` or `client_id_map` mode | Legacy environment/config name | Remove; never translate implicitly or use as fallback | GUG-102 |
| Runtime without `SCANALYZE_DEPLOYMENT_ID` | Canonical variable absent | Keep M2M disabled; resolve both identities from the authoritative deployment record | GUG-93 |
| Service task input without separate customer/deployment identity | Task-definition contract v1 or missing canonical environment entry | Render and review task-definition input v2 | GUG-102 / GUG-93 |
| M2M client not available to the services layer | Services executes before edge identity or output is absent | Change the control-plane handoff/DAG through a separate reviewed PR | GUG-93 |
| API Gateway/Cognito without the M2M audience, claims, or canonical scopes | Declarative identity contract does not match runtime | Add and validate through GUG-93; do not compensate in application code | GUG-93 / GUG-92 |
| Batch or document without customer/deployment ownership | Object binding missing | Deny, quarantine, or migrate only after an approved data decision | GUG-114 |

The inventory is by class, not by live identifier. A deployment-specific
inventory must be generated and stored in the approved evidence system, never
in Git, general CI artifacts, Linear comments, or NotebookLM.

## Per-deployment migration sequence

1. Resolve the deployment record from its authoritative registry.
2. Confirm canonical customer and deployment identifiers are distinct and
   satisfy the v2 grammar.
3. Confirm the M2M client belongs to that deployment's identity control plane.
4. Approve exact, non-empty, pairwise-disjoint `read`, `write`, and `admin`
   scope sets using the canonical GUG-92/GUG-93 taxonomy.
5. Assign each M2M client complete action scope sets only. Partial sets and
   scopes outside the approved action universe are invalid.
6. Generate an identity v2 contract and validate its schema and semantic
   bindings offline.
7. Render task-definition input v2 and verify exactly one canonical customer
   and deployment environment entry, with no extension override.
8. Keep M2M disabled until Cognito, API Gateway, services handoff, and runtime
   configuration are part of one reviewed non-production change.
9. Run positive and negative tests for the exact deployment plus a second
   isolated deployment. Any cross-deployment success is a P0 failure.
10. Verify that read-only bindings cannot write, download, export, or retrieve
    full PII, and that token-only extra scopes do not elevate the binding.
11. Record sanitized evidence with commit, release, environment, test result,
   reviewer, and rollback reference.
12. Enable production only through the later production gate; this runbook does
    not grant that authority.

## Failure and rollback behavior

- Missing or mismatched binding: deny and keep M2M disabled.
- Legacy customer-only mapping: reject; do not fall back.
- Unknown or incomplete scope taxonomy: block the migration.
- Partial, overlapping, or out-of-universe action scopes: reject the contract.
- Missing object ownership: follow GUG-114; never infer from a request.
- Failed non-production rollout: revert the reviewed change or disable M2M,
  then reconcile through a new plan. Do not edit state or task definitions
  imperatively.

## Evidence checklist

- v2 identity contract validated;
- task-definition input v2 validated;
- runtime positive and negative suite passed;
- Terraform provider validation completed without AWS credentials;
- CI passed for the reviewed commit;
- non-production live validation explicitly authorized and sanitized;
- no real identifiers, tokens, sensitive data, state, or plans entered a
  prohibited evidence system; and
- GUG-117 and production remain blocked until every dependent criterion closes.
