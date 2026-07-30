# Despliegue enterprise de Scanalyze

Este documento es una fuente curada para consulta en NotebookLM. Resume el
modelo operativo sin sustituir el procedimiento ejecutable. La autoridad
canónica es
[`playbooks/enterprise-client-deployment.md`](../playbooks/enterprise-client-deployment.md),
y cualquier discrepancia debe resolverse a favor del playbook, los ADRs y el
código versionado.

## Resultado esperado

Un deployment de Scanalyze es una instalación aislada en una cuenta AWS
dedicada. Comparte el mismo código fuente que los demás clientes, pero recibe
su propia identidad, red, almacenamiento, cómputo, observabilidad y
configuración declarativa. El código fuente no se entrega a la cuenta del
cliente: se construye como imágenes OCI inmutables, se publica en ECR y se
consume por digest.

El despliegue no es una sola ejecución. Es una secuencia controlada de
preparación, planes revisados, publicación de artefactos, aplicación por capas,
validación y handoff. Terraform conserva la propiedad declarativa de los
recursos. El state registra esa propiedad, pero nunca se usa como mecanismo de
rollback.

## Secuencia operativa curada

1. **Autorizar el cambio.** Se identifica cliente, deployment, cuenta, región,
   ventana, responsables, versión fuente y criterio de rollback. Los valores
   específicos permanecen fuera de Git.
2. **Cerrar el preflight.** Se confirma identidad AWS, toolchain soportado,
   branch o release aprobado, árbol Git controlado y gates locales/CI en verde.
3. **Preparar la cuenta.** El backend de Terraform, cifrado, bloqueo y guardas
   de cuenta deben existir y estar verificados antes de cualquier mutación.
4. **Configurar contratos.** Las diferencias por cliente se expresan mediante
   variables locales protegidas, contratos y parámetros SSM. No se crean forks
   ni constantes de cliente en el código.
5. **Aplicar infraestructura base por capas.** Cada plan se genera, conserva
   fuera de Git, revisa y aplica exactamente una vez hasta `cicd`, que provisiona
   ECR y metadata. Los outputs entre capas se consumen por contratos explícitos.
6. **Construir, verificar y publicar imágenes.** GitHub Actions usa OIDC y un rol
   acotado. La imagen base y las imágenes de servicio se fijan por digest; ECR
   usa tags inmutables. Esta fase ocurre después de `cicd` y antes de `services`.
7. **Desplegar services, identity y edge mediante Terraform.** SSM registra metadatos de
   imagen, pero no despliega ECS. La capa `services` recibe los digests
   aprobados y sigue siendo dueña de task definitions y servicios; después se
   ejecutan `edge-identity`, `edge` y `addons`.
8. **Validar sin exponer datos.** Primero se prueba estabilidad de
   infraestructura; después, cuando los contratos de frontend e identidad
   estén cerrados, se ejecuta un flujo sintético no productivo de extremo a
   extremo.
9. **Entregar operaciones.** El handoff incluye evidencia, versión y digests,
   dashboards, alarmas, runbooks, contactos, rollback y riesgos aceptados.

## Flujo de imágenes del monorepo

Los siete componentes viven bajo `backend/workers/scanalyze-*`. El punto de
entrada reproducible es `scripts/microservices/build-push.sh`; el workflow
`.github/workflows/microservices-build.yml` reutiliza ese script y no duplica
la lógica de publicación.

En pull requests se permiten pruebas y builds sin publicación. La capacidad de
obtener un token OIDC sólo existe en el job de publicación y requiere el
Environment protegido del cliente. No se permiten claves AWS estáticas en
GitHub. El digest leído de ECR es la identidad desplegable; un tag es sólo una
etiqueta operativa inmutable.

## Decisión GO/NO-GO

El deployment es **NO-GO** cuando ocurra cualquiera de estas condiciones:

- la cuenta o región de la sesión no coincide con el deployment aprobado;
- existe una gate crítica fallida o una validación omitida sin aceptación;
- el plan contiene destrucción o reemplazos no autorizados;
- falta la imagen base aprobada o una imagen no puede fijarse por digest;
- se pretende usar una credencial estática, un secreto en archivos o un tfvars
  real dentro de Git;
- la configuración frontend no tiene un propietario declarativo verificable;
- el contrato de identidad no vincula de forma consistente el usuario, el
  deployment y el acceso a datos;
- el smoke test requiere documentos reales, PII o impresión de contenido;
- no existe rollback probado ni responsable operativo de guardia.

## Límite actual de evidencia

La migración al monorepo y sus gates tienen evidencia local. Esto no equivale
a evidencia de ejecución en una cuenta no productiva. Mientras sigan abiertos
los gates declarativos de configuración frontend e identidad descritos en el
playbook, sólo puede declararse readiness de infraestructura, no readiness de
aplicación ni readiness productivo.

## Fuentes relacionadas

- [`ADR-011`](../ADR/ADR-011-monorepo-microservices-source.md): fuente del
  monorepo y compatibilidad de transición.
- [`ADR-007`](../ADR/ADR-007-artifact-supply-chain.md): cadena de suministro,
  firma, scan, attestations y promoción.
- [`backend/workers/README.md`](../backend/workers/README.md): operación de los
  siete servicios.
- [`09_Production_Readiness_and_Operational_Handoff.md`](09_Production_Readiness_and_Operational_Handoff.md):
  decisión de producción y handoff.

## Exclusiones para NotebookLM

Esta fuente no debe contener ni solicitar credenciales, tokens, perfiles,
tfvars reales, state, planes, outputs de cliente, documentos, PII, payloads,
logs productivos o evidencias de auditoría sensibles. NotebookLM explica el
proceso; no autoriza, ejecuta ni valida un despliegue.
