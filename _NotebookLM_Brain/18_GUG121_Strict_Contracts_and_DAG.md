# GUG-121 — Strict Contracts and Canonical DAG

## Resumen

GUG-121 convierte el DAG de deployment en una frontera ejecutable y cerrada.
El defecto raíz era que el wrapper de plan completaba dependencias ausentes con
digests, IDs y ARNs sintéticos, mientras varios schemas no coincidían con los
outputs reales de Terraform.

El catálogo canónico ahora asigna a cada contrato un único productor, schema,
scope, transporte content-addressed, consumidores y bindings explícitos. El
envelope v2 liga customer, deployment, cuenta, región, versión y digest de release, productor,
state key, module source y digest de outputs. Network, platform, cicd, services,
edge y addons avanzan de forma aditiva a v2; sus schemas v1 permanecen sólo
para rollback explícito.

El resolver rechaza contratos faltantes, extra, duplicados, ajenos, alterados,
stale, futuros o dirigidos al consumer incorrecto. La resolución activa v2
contiene evidencia contractual canónica y no un mapa `variables` duplicado. Un
proyector compartido reconstruye bindings de metadata, outputs y contrato
tipado desde catálogo, schemas y digests verificados; v1 queda sólo como
evidencia histórica y la ruta activa rechaza downgrade.

El wrapper de Terraform no tiene fallback: rechaza cualquier `TF_*` ambiental
antes de backend, AWS o Terraform, materializa un tfvars 0600 fuera del repo y
ejecuta init/plan con ambiente hijo controlado. No imprime valores rechazados y
elimina artefactos temporales al terminar.

## Límites de evidencia

- **Implemented:** candidato de código, schemas, DAG, catálogo, productores,
  resolver, guard de plan, documentación y pruebas.
- **Locally validated:** únicamente pruebas sintéticas y comandos offline
  reportados para el candidato.
- **CI validated:** pendiente del PR y SHA exactos.
- **Live validated:** no.
- **AWS/SSM/backend/apply/deployment:** no ejecutado.
- **Production:** **NO-GO**.

GUG-122 sólo puede iniciar después del merge revisado y verificación en main de
GUG-121. GUG-123, GUG-124 y GUG-125 permanecen secuenciales.
