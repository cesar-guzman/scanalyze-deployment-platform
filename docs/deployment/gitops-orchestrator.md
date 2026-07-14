# GitOps Terraform Orchestrator

## Status

This document describes the accepted orchestration architecture and its current
implementation boundary.

| Capability | Status |
|---|---|
| Canonical layer graph and schema validation | Implemented by this change |
| Git-safe deployment request | Implemented by this change |
| Local contract resolution and envelope rendering | Implemented, dry-run only |
| Reusable layer workflow and non-production stage graph | Implemented, dry-run only |
| OIDC role chain and layer-specific AWS authorization | Target; not live validated |
| Remote backend, saved live plans, and SSM publication | Target; blocked |
| Production promotion | NO-GO |

Nothing in this change authorizes an AWS mutation or establishes production
readiness.

## Why Local `apply-all` Is Not Authoritative

Terraform plans freeze their inputs and the state observed at plan time. Before
GUG-121, the local wrapper could fill missing cross-layer values with synthetic
defaults. That path is removed: every plan now requires an exact,
content-bound resolution artifact.

The live sequence must finish one layer before the next is planned:

```text
resolve inputs
  -> plan layer N
  -> evaluate policy
  -> apply the exact saved plan
  -> validate the produced contract
  -> plan layer N+1
```

Local validation remains useful for syntax, schemas, provider validation, DAG
checks, and dry-run workflow behavior. Local responsibility ends there unless a
separate operation explicitly authorizes live access.

## Canonical DAG

`deployment/layers.yaml` is the source of truth for stage order, Terraform root,
state scope, contract dependencies, role intent, destroy policy, artifact
dependencies, and evidence requirements.

```text
account-ready-gate
  -> global
  -> network
  -> platform
  -> data-foundation
  -> cicd
  -> artifact-publication
  -> services
  -> edge-identity
  -> edge
  -> addons
  -> synthetic-validation
```

The graph deliberately places artifact publication after `cicd`, which creates
the customer-local ECR repositories and release metadata, and before `services`,
which must consume immutable image digests. Edge stages cannot run before the
services contract exists.

The validator rejects cycles, duplicate state keys, missing roots, contracts
without producers, invalid special-stage placement, destructive account-ready
operations, and services without an immutable artifact dependency.

## Deployment Request Versus Resolved Manifest

Git stores intent, not customer bindings.

### Allowed in Git

- deployment ID or non-sensitive reference ID;
- logical environment;
- immutable release digest;
- requested layer scope;
- requester and change-ticket references;
- non-sensitive selectors and approval references.

### Never stored in Git

- a real resolved deployment manifest;
- credentials, tokens, cookies, or session material;
- real tfvars, state, plans, or backend files;
- raw Terraform outputs or contract payloads;
- customer data, documents, logs, or operational evidence;
- account-specific secrets or private connection material.

The real manifest and resolved deployment record belong in encrypted,
access-controlled storage outside the repository. A future live orchestrator
will resolve them using the deployment request's reference and then revalidate
deployment, account, region, release, and role bindings before requesting any
AWS authority.

## Layer Contracts

The target contract path is:

```text
/scanalyze/deployments/{deployment_id}/contracts/{layer}/vN/releases/{release_digest}/digests/{contract_digest}
```

Each contract is one JSON envelope containing:

- schema and output-schema versions;
- deployment, account, region/scope, producer, and layer identity;
- immutable release digest;
- state key and optional module source digest;
- the layer's typed outputs;
- a SHA-256 digest of canonicalized outputs;
- production metadata that supports freshness checks.

The contract digest protects integrity, not authority. Authority comes from an
IAM writer restricted to the producer boundary; freshness comes from matching
the expected release and recorded contract version. A consumer fails closed if
any binding, schema, owner, or digest is absent or inconsistent.

GitHub outputs may carry non-sensitive control metadata such as a stage result.
They do not carry VPC IDs, subnet IDs, role ARNs, endpoints, image mappings, or
other infrastructure outputs.

`resolve-contracts.py` supports only explicitly acknowledged local test
fixtures. It writes a digested, owner-readable resolution outside the
repository. The plan wrapper validates and materializes it without defaults and
never logs its values. Live SSM resolution remains disabled until GUG-125.

`publish-contract.py` currently means "render and validate a candidate envelope
to a local file." It does not publish to AWS. SSM publication remains blocked
until the single-writer design and live authorization are implemented and
reviewed.

## Saved Plans And Evidence

The future live unit for a Terraform layer is:

1. assume the layer's Plan authorization;
2. initialize the approved remote backend;
3. resolve the exact deployment record, release, and upstream contracts;
4. create a saved plan;
5. evaluate bounds and policy without logging raw plan data;
6. record the plan digest and sanitized action counts;
7. assume the layer's Apply authorization;
8. verify plan digest and state freshness;
9. apply that exact plan once;
10. validate the produced SSM contract and health gate.

Raw plan binaries and plan JSON may contain sensitive values. They belong in an
encrypted, short-lived execution prefix outside GitHub artifacts. Durable
evidence contains only sanitized metadata: commit and release digests, layer,
action counts, approval reference, plan digest, execution identity, state object
versions, duration, and result.

This dry-run implementation does not create or upload plans.

## OIDC And Authorization

Pull-request and ordinary dry-run jobs have `contents: read` only. They do not
receive `id-token: write`.

The target live flow is:

```text
protected GitHub Environment
  -> GitHub OIDC
  -> Scanalyze orchestrator role
  -> Plan | Apply | Promotion | Validation terminal role
```

The orchestrator role must not have ambient infrastructure administration. The
terminal session is bound to deployment, release, change, layer, and operation.
Role trust, session-policy completeness, permissions boundaries, protected
Environment settings, and account binding must all be implemented and live
validated before the disabled live workflow path can be enabled.

The repository currently describes this as a target model. It does not claim
that all terminal roles or protections are deployed.

## Repository Governance And Multi-Client Authorization

Repository merge governance and deployment authorization are deliberately
separate:

```text
pull request
  -> static, client-independent required checks
  -> reviewed main branch
  -> deployment request
  -> deployment-scoped GitHub Environment
  -> deployment/account/region-bound authorization
```

The repository-wide required-check contract lives in
`governance/github-policy.json`. Matrix legs such as
`Service matrix evidence / ingest-api` are conditional evidence and must never
be configured directly as required status checks. `Microservices validation
gate` is the stable, fail-closed aggregate. Manual dispatch validates all seven
services before producing that aggregate; the service input scopes only the
publication matrix.

For non-production orchestration, `logical_environment` is the request stage
(`sandbox`, `dev`, or `staging`) and `github_environment` is a distinct protected
deployment boundary. The selected GitHub Environment must define matching
`DEPLOYMENT_ID`, `LOGICAL_ENVIRONMENT`, and `AWS_REGION` variables. A deployment
cannot borrow another client's approval or configuration boundary.

The current comparison is only a dry-run consistency guard: the merged `vars`
context does not prove that a value originated at Environment scope or that the
selected Environment has protection rules. Before live enablement, an external
governance control must verify the pre-existing Environment, reviewer and branch
policy, reserved variable scope, and registry bindings. A future live job must
target that same verified Environment itself; an earlier approval job does not
delegate OIDC authority to downstream jobs.

Operational reconciliation, drift detection, rollback, and onboarding are
defined in [GitHub governance operations](../operations/github-governance.md).

## Fail-Fast And Recovery

Every stage depends explicitly on its predecessor. A failure blocks downstream
stages and produces a sanitized failure summary. The orchestrator must not:

- auto-destroy successful upstream layers;
- reuse a stale saved plan after state or contract changes;
- force-unlock Terraform state;
- mutate ECS outside Terraform;
- convert a partial failure into a successful workflow result.

Release rollback is a new, approved forward plan that restores known-good image
digests and configuration. State restoration is reserved for state corruption
and uses a separate break-glass process.

## Non-Production And Production

The non-production workflow introduced here is an executable validation graph,
not a live deployment pipeline. All stages remain dry-run and the live branch is
fail-closed.

Production remains NO-GO until all of the following have reviewable evidence:

- successful live non-production deployment and rollback;
- OIDC and terminal-role authorization tests;
- remote-state locking and saved-plan substitution tests;
- complete contract production and consumption across every layer;
- mandatory SBOM, vulnerability, signature, and provenance gates;
- health, smoke, observability, and operational handoff gates;
- protected production approval and immutable artifact promotion.

Production must promote the exact validated release. It must not rebuild it.

## Local Validation

Run the safe checks without AWS credentials:

```bash
python scripts/deployment/validate-layer-dag.py deployment/layers.yaml
make gitops-orchestrator-check
make security-check
make docs-check
make provider-check
python -m pytest tests/ -v
```

`provider-check` initializes roots with `-backend=false` and rejects AWS
credentials in the environment. No command in this list performs an AWS write.

## Related Decisions

- [ADR-006](../../ADR/ADR-006-modules-contracts.md)
- [ADR-012](../../ADR/ADR-012-autonomous-deployment-orchestrator.md)
- [ADR-013](../../ADR/ADR-013-deployment-manifest-and-contracts.md)
- [ADR-016](../../ADR/ADR-016-release-graph-and-supply-chain.md)
- [ADR-017](../../ADR/ADR-017-github-actions-release-orchestrator.md)
- [ADR-018](../../ADR/ADR-018-stable-ci-governance.md)
- [Rollback procedures](../operations/rollback.md)
