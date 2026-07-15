# GitHub OIDC and terminal deployment identity

Production: **NO-GO**. This reference describes the GUG-123 candidate control
plane. It does not authorize GitHub configuration, AWS, Terraform, deployment,
promotion, validation, recovery, or production.

## Authorization chain

One live execution is eligible only when all of these independently sourced
values agree exactly:

```text
deployment request assertions
          +
registry target + independent registry anchor
          +
ACCOUNT_READY v2
          +
platform identity authority + independent authority anchor
          +
GitHub identity contract
          +
fresh GitHub API Environment/OIDC anchor
          +
exact OIDC trust + role/resource/session tags
          =
eligible terminal operation (not deployment success)
```

Every missing or conflicting input denies. The decision returns identifiers and
the approved subject only; it does not return credentials, API payloads,
Environment variables, role policy contents, backend coordinates, or URLs.

## Portable contract files

- `schemas/github-deployment-identity.v1.schema.json`: expected repository,
  workflow, OIDC, Environment, terminal roles, and diagnostic separation.
- `schemas/github-environment-anchor.v1.schema.json`: independent short-lived
  evidence digest obtained from the GitHub API.
- `schemas/github-platform-authority.v1.schema.json`: independently anchored
  shared-services account, OIDC provider, immutable repository IDs,
  deployment-scoped orchestrator role, and exact role tags.
- `tooling/validate_github_deployment_identity.py`: pure fail-closed decision
  and repository policy validation.
- `policies/trust/github-oidc-orchestrator-trust.json`: exact first-hop OIDC
  trust template.
- `policies/trust/{plan,apply,identity-plan,identity-apply,promotion,validation}-trust.json`:
  operation-, layer-, and resource-tag-bound terminal trust.
- `policies/iam/orchestrator-role.json`: assumes only deployment terminal roles.

The contract carries no real repository IDs, account IDs, deployment IDs,
customer IDs, role ARNs, tokens, secrets, or evidence. Per-deployment values
come from approved external systems and remain outside Git.

## Environment requirements

Each deployment and logical stage has a unique name:

```text
scanalyze-<deployment_id>-<sandbox|dev|staging|production>
```

The protection evidence must prove:

- `main` is the only deployment branch and tags are denied;
- at least one named independent user reviewer;
- self-review and admin bypass are prevented;
- reserved deployment variables are absent at repository and organization
  scope;
- the six expected non-secret variables equal the approved deployment tuple;
- no Environment secrets are present; and
- the repository OIDC claim customization is exact.

The release workflow cannot generate this proof. A separately authorized
read-only collector retrieves the GitHub configuration and emits only a
short-lived digest anchor. The raw API response and real identifiers are not
committed or sent to NotebookLM.

## Subject and sessions

The exact subject is derived from immutable repository IDs, Environment,
workflow ref, and event. AWS trust accepts the complete value with
`StringEquals`; there is no wildcard or default-subject fallback. OIDC and
terminal sessions are capped at 900 seconds.

The orchestrator passes exactly eight tags: customer, deployment, account,
region, environment, operation, layer, and change ID. Resource tags must match
the deployment tuple. `ACCOUNT_READY` v2 independently certifies the customer,
deployment, account, region, and environment resource tags on every terminal
role. Source identity is `exec_<ULID>`. Roles cannot be selected from inputs,
variables, profiles, ARNs, queue messages, or naming conventions.

Generic Plan/Apply roles cover every Terraform layer except
`identity-control-plane`. That layer is accepted only by the GUG-93
Identity-Plan/Identity-Apply roles. A prior `ACCOUNT_READY` v2 record without
those roles is migration-required and denied; there is no inferred ARN or
automatic migration.

Every `ForAllValues` tag-key allowlist is paired with `Null` checks for both
the tag-key context and every mandatory request tag. This prevents an absent
multivalued context from satisfying the allowlist vacuously.

Diagnostic and StateRecovery are excluded from the orchestrator. Their human
break-glass path requires MFA, reviewed approval, incident/operator evidence,
exact ownership tags, a principal-tagged target account, and `bg_*` source
identity. StateRecovery additionally requires `recovery_approved=true`; GUG-123
does not issue approval or perform recovery.

## Offline validation

```bash
make github-deployment-identity-check
python -m pytest -q tests/test_governance/test_gug123_terminal_identity.py
```

The gate validates schemas, fixture digest, OIDC/terminal trust, orchestrator
scope, diagnostic separation, repository-wide privilege absence, and
positive/negative authorization cases. The legacy microservices publication
job remains present only as an explicit NO-GO: it has empty permissions, no
Environment, no OIDC request, and no AWS credential action. Passing the gate
proves repository behavior only.

## Live enablement boundary

Live enablement requires the reviewed sequence in
`docs/operations/github-oidc-terminal-identity-rollout.md`, an exact approved
account/profile/region, GitHub administrative authorization, no unresolved
GUG-124/GUG-125 blocker, and retained sanitized evidence. Local or CI green is
not live evidence.
