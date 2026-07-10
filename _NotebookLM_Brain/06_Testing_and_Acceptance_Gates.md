# Pruebas y puertas de aceptación

Esta fuente curada explica cómo interpretar la evidencia de calidad de
Scanalyze. Los comandos y dependencias reales permanecen en el `Makefile`, los
workflows y los tests del repositorio. No se duplican aquí para evitar drift.

## Evidence before claims

Una afirmación como "seguro", "reproducible" o "listo para producción" sólo
es válida si señala evidencia vigente, su alcance, versión y resultado. Una
gate local demuestra el comportamiento observado en ese checkout; no demuestra
que AWS, una cuenta cliente o un rollout productivo hayan sido validados.

Todo resultado debe distinguir entre:

- **pasó:** la validación terminó con éxito en el alcance declarado;
- **falló:** existe un defecto o una incompatibilidad que debe corregirse;
- **no ejecutado:** falta herramienta, entorno, acceso o autorización;
- **bloqueado:** una precondición funcional o de seguridad impide continuar.

"No ejecutado" nunca se transforma en "pasó". Una advertencia crítica tampoco
se oculta mediante filtros, excepciones genéricas o cambios a la gate.

## Capas de validación

### Seguridad del repositorio

`git-safety` y `security-check` deben comportarse fail-closed. Su alcance
incluye contenido tracked, staged y archivos untracked relevantes. Detectan
artefactos operativos, credenciales, state, planes, entornos locales y patrones
que no pueden formar parte de un PR.

La ausencia de hallazgos no autoriza el uso de datos reales. También se revisa
que el diff esté acotado, no mezcle el checkout original y no contenga bundles
de auditoría.

### Código de microservicios

`microservices-check` verifica la presencia y estructura de los siete
servicios. Las suites unitarias deben cubrir errores, reintentos, idempotencia,
DLQs, transiciones de estado y fallos de handoff. En particular, una unidad no
se marca completada antes de confirmar el siguiente paso durable y las
transiciones DynamoDB deben comprobar identidad, clave y estado previo.

### Infraestructura y contratos

`preflight-m2` reúne gates de ownership, interfaces, contratos y formato
Terraform dentro del alcance definido por el repositorio. La validación de un
root se realiza sin backend cuando sólo se evalúa sintaxis y consistencia
local. Un plan con backend real pertenece a un contexto autorizado y se revisa
como evidencia separada.

Las versiones soportadas de Terraform, Python y herramientas son parte del
resultado. Pasar con otra versión debe documentarse como desviación, no como
equivalencia automática.

### GitHub Actions

Los pull requests no publican imágenes ni escriben SSM. Los jobs de validación
operan con permisos mínimos. El permiso OIDC se limita al job de publicación,
que requiere un Environment protegido y un rol de la cuenta objetivo. La
branch, el commit y la matriz de servicios deben quedar identificables en la
evidencia de CI.

### Validación no productiva

Antes de producción se requiere una cuenta no productiva equivalente para:

- construir las siete imágenes desde el commit aprobado;
- verificar base image y digests en el ECR objetivo;
- revisar planes por capa y reconciliación sin drift;
- confirmar estabilidad de los siete servicios y sus dependencias;
- probar alarmas, DLQs, reintentos y rollback;
- ejecutar un E2E con documento sintético aprobado, sin imprimir contenido.

## Acceptance gates

Un cambio puede ser **PR-ready** con gates locales verdes, diff acotado y
riesgos documentados. Es **merge-ready** cuando la CI requerida y la revisión
humana pasan. Es **release-ready** cuando existe un artefacto identificable,
promovible y reversible. Es **production-ready** sólo después del ensayo no
productivo, cierre de gates funcionales, aprobación de cambio y handoff
operativo.

## NO-GO

La aceptación se detiene si una gate crítica falla, el índice contiene archivos
fuera del allowlist, hay drift no explicado, falta un digest, se requiere un
secreto para reproducir la prueba, o el resultado depende de deshabilitar una
protección. También es NO-GO cuando los gates de configuración frontend o
identidad siguen abiertos para el flujo que se pretende declarar listo.

## Evidencia mínima retenida

La evidencia debe registrar commit, branch o release, toolchain, fecha,
resultado de gates, plan revisado, digests, aprobadores y riesgos residuales.
Debe almacenarse en el sistema aprobado para CI/cambios, no como dumps o
bundles improvisados dentro del repositorio.

## Fuentes canónicas

- [`ARCHITECTURE_ACCEPTANCE_GATES.md`](../ARCHITECTURE_ACCEPTANCE_GATES.md)
- [`Makefile`](../Makefile)
- [`playbooks/enterprise-client-deployment.md`](../playbooks/enterprise-client-deployment.md)
- [`docs/migration/monorepo-microservices-migration.md`](../docs/migration/monorepo-microservices-migration.md)

## Exclusiones para NotebookLM

No se incorporan reportes con valores de cliente, logs, payloads, salidas de
scanners con datos sensibles, state, planes ni secretos. NotebookLM puede
resumir criterios y resultados sanitizados, pero no es el sistema de registro
de evidencia ni una gate de aceptación.
