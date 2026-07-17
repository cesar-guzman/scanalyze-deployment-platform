# GUG-125 — Non-Production Live Engine and Exact Saved Plans

## Executive source

GUG-125 defines the only eligible path from a reviewed Terraform plan to one
non-production apply. A saved-plan record binds the exact customer, deployment,
account, region, layer, release, registry, baseline, lock, backend, contracts,
toolchain, source, state, plan digest, encrypted S3 object version, and expiry.
An independent approval binds immutable GitHub repository/workflow/run IDs, the
protected Environment configuration, and distinct initiator and approver IDs to
that exact plan.

Plan storage lives in the destination account under the Plan terminal role.
The compare-and-swap execution ledger lives in shared services under the
deployment-scoped orchestrator. Apply can read only the exact version and is
single-use; it never re-plans. Health receipts bind the plan and source ledger,
and downstream layers require the resulting HEALTHY ledger. A lost apply
response becomes UNCERTAIN and permits only read-only reconciliation. Ambiguous
results require a new reviewed forward-recovery plan.

The code and synthetic tests are portable across customers, accounts, regions,
and non-production environments. Real bindings, plans, state, AWS responses,
credentials, account IDs, role ARNs, evidence, and customer data remain outside
this source.

## Evidence boundary

The offline engine is implemented and locally testable. The repository workflow
remains dry-run-only. Live execution is blocked until a separate shared-services
platform authority, exact protected Environment with an independent reviewer,
ACCOUNT_READY v2 in each destination, valid short-lived AWS sessions, and the
complete signed release are available. No Terraform plan/apply, deployment,
failure injection, health proof, two-account isolation proof, or cleanup is
claimed by this document. Production is **NO-GO**.

## Addendum: fábrica portable de platform authority

La autoridad de máquina debe vivir en una tercera cuenta dedicada, distinta de
todas las cuentas cliente. `modules/platform-authority` crea un provider GitHub
OIDC, storage KMS para registry/ledger/releases y un rol exacto
`ScanalyzeOrchestrator-<deployment_id>` por deployment. Cada rol queda ligado a
customer, deployment, cuenta destino, región, ambiente non-production,
repositorio y Environment exactos.

IAM Identity Center se usa sólo para bootstrap humano y recuperación temporal.
GitHub OIDC es la identidad normal de máquina. La autoridad nunca almacena
documentos, PII, state de clientes ni workloads. AccountVendingProvider conserva
la responsabilidad de crear roles terminales, backends y `ACCOUNT_READY` en
cada cuenta cliente.

Sin perfil/cuenta/backend autorizado de la tercera cuenta, protected
Environments y prueba secuencial de dos clientes, la activación AWS sigue
**Blocked** y producción **NO-GO**.
