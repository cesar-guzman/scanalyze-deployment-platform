# GUG-123 — GitHub OIDC and terminal deployment identity

This sanitized source explains the candidate GUG-123 authorization boundary.
It is not a token, Environment export, IAM policy dump, or deployment authority.

Scanalyze binds a live GitHub execution to immutable repository IDs, the exact
deployment Environment, workflow path, `main` ref, event, customer, deployment,
AWS account, region, logical stage, terminal operation, and layer. The GitHub
OIDC subject contains the immutable repository IDs plus Environment, workflow
ref, and event. AWS trust uses exact audience and subject equality; default and
wildcard subjects are denied.

An independently anchored platform authority also binds the immutable
repository IDs to the approved shared-services account, OIDC provider,
deployment-scoped orchestrator role, and exact role tags. A workflow or
Environment cannot substitute another shared-services account.

The Environment snapshot cannot certify itself. A separate read-only GitHub API
collector must provide a short-lived digest anchor for reviewers, branch/tag
policy, bypass/self-review posture, deployment variables, secret-name inventory,
and OIDC customization. Named independent users are required; unverified team
membership, generic Environments, repository/organization variable overrides,
and Environment secrets fail closed.

The orchestrator can assume only generic Plan/Apply, dedicated
Identity-Plan/Identity-Apply, Promotion, and Validation. Generic roles exclude
`identity-control-plane`; the dedicated roles accept only that GUG-93 layer.
Each role is terminal, operation/layer/resource-tag bound, uses an exact session
tag set, a 15-minute maximum, and `exec_<ULID>` source identity. Diagnostic and
StateRecovery remain human break-glass only, with MFA, approval, exact ownership,
incident/operator evidence, and explicit recovery approval. Multivalued tag-key
allowlists require a non-null tag-key context and every mandatory request tag.
All repository workflows remain unable to request OIDC or AWS credentials until
the GUG-125 engine exists. The legacy microservices publisher retains validation
only and fails explicitly if cloud publication is requested.

Evidence classification:

- Implemented: candidate contracts, validator, policy fixtures, tests, ADR,
  runbook, threat delta, and repository gate.
- Locally validated: synthetic offline tests only.
- CI validated: pending the exact PR commit.
- Live validated: no.
- Blocked: reviewed merge/main, authorized GitHub/AWS proof, GUG-124, GUG-125,
  two-deployment isolation, and GUG-117 closeout.
- Production: NO-GO.

Do not ingest repository/Environment IDs, reviewers, variables, OIDC tokens,
claims, role ARNs, IAM/API exports, registry/baseline records, plans, state,
CloudTrail, screenshots, logs, or customer data into NotebookLM.
