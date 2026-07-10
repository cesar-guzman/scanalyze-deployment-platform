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

Consulta [`colleague-deployment-guide.md`](colleague-deployment-guide.md) para el
procedimiento vigente y [`gitops-orchestrator.md`](gitops-orchestrator.md) para
la arquitectura aprobada.
