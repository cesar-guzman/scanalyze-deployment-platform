# Bitácora de Preparación GitOps Non-Production

> **Fecha de decisión:** 2026-07-10<br>
> **Estado:** el procedimiento manual live quedó cerrado por ADR-017.

Esta bitácora ya no debe recopilar salidas live, account IDs, ARNs, Terraform
outputs, manifests, plans, logs ni capturas con datos operativos. La evidencia
durable debe ser sanitizada y generada por el orquestador protegido.

## Checklist local autorizado

- [ ] Manifest real creado fuera del repositorio con permisos `0600`.
- [ ] `make bootstrap-local` completado.
- [ ] `make repro-check` completado sin credenciales AWS.
- [ ] `make security-check` y `make provider-check` completados.
- [ ] DAG canónico validado con `validate-layer-dag.py`.
- [ ] Dry-run local completado; no se ejecutó `apply`.
- [ ] Solicitud Git-safe validada contra su schema.
- [ ] `git status` confirma que no hay manifest, tfvars, plan ni state real.
- [ ] Pull Request abierto para revisión.

## Resultado

- Validación local: `PENDING`
- Validación live non-production: `PENDING`
- Producción: `NO-GO`

## Checkpoint documental GUG-93

- **Implemented:** the original repository layer/runtime/contracts/docs were
  merged to `main` by PR #10. A separate post-merge provider-compatibility
  amendment remains candidate evidence until its own PR, CI, merge, and main
  verification complete.
- **Locally validated:** the focused Python 3.11 identity runtime suite passed
  `96` tests during implementation. Final exact-revision repository/Terraform/
  security results must be recorded separately; this log is not their authority.
- **CI validated:** PR #10 required checks passed for the original GUG-93
  revision. The amendment remains `PENDING` for its own exact PR commit.
- **Live validated:** `BLOCKED`; no AWS/Cognito, bootstrap, M2M credential,
  migration, state adoption, retirement, or two-deployment execution occurred.
- **Producción:** `NO-GO`.

The GUG-93 operational boundary is documented in
[`identity-control-plane.md`](identity-control-plane.md) and
[`identity-bootstrap-retirement.md`](../operations/identity-bootstrap-retirement.md).
No provider identifiers, user inventories, credentials, tokens, plans, state,
logs, or live evidence belong in this file.

## Checkpoint documental GUG-123

- **Implemented:** candidate GitHub deployment identity/Environment anchor
  contracts, exact OIDC and terminal trust fixtures, validator, tests, ADR-031,
  runbook, threat delta, and sanitized source exist in the isolated worktree.
- **Locally validated:** `224` focused authorization/workflow/schema tests and
  the GUG-123 gate (`78` tests) passed. Final `make
  PYTHON=.venv/bin/python preflight-m2b` passed with the pinned Python
  `3.11.14` and Terraform `1.14.6`, including the repository suite (`1005`
  passed), contract matrix (`114/114`), provider validation (`11/11`), and
  provider lock check (AWS provider `5.100.0` across `11` roots). `actionlint`
  was not installed and is classified `SKIPPED`; executable YAML contracts and
  repository workflow tests passed.
- **CI validated:** `PENDING` until checks pass for the exact PR commit.
- **Live validated:** `BLOCKED`; no GitHub Environment/OIDC setting, IAM role,
  AWS session, Terraform operation, or deployment was read or changed.
- **Producción:** `NO-GO`.

The operational boundary is documented in
[`github-oidc-terminal-identity.md`](github-oidc-terminal-identity.md) and
[`github-oidc-terminal-identity-rollout.md`](../operations/github-oidc-terminal-identity-rollout.md).
Do not add repository IDs, Environment reviewers/variables, tokens, claims,
role ARNs, IAM/API exports, CloudTrail, or live evidence to this log.

Consulta [`colleague-deployment-guide.md`](colleague-deployment-guide.md) para el
procedimiento vigente y [`gitops-orchestrator.md`](gitops-orchestrator.md) para
la arquitectura aprobada.
