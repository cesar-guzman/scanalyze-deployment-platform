# Agentes de IA y automatización segura

Los agentes de IA aceleran investigación, implementación, revisión y
documentación, pero no sustituyen ownership, controles de cambio ni aprobación
humana. NotebookLM funciona como una capa de consulta sobre fuentes curadas;
Codex y la CI trabajan contra el repositorio y sus gates.

## Jerarquía de autoridad

Cuando dos fuentes difieren, se usa este orden:

1. controles organizacionales y políticas de seguridad aplicables;
2. código, contratos, workflows y Terraform versionados;
3. ADRs aceptados y playbooks canónicos;
4. evidencia vigente de CI y validación operativa;
5. fuentes curadas de NotebookLM;
6. conversaciones, resúmenes o documentos históricos.

NotebookLM no se usa para reconstruir comandos desde memoria cuando existe un
script canónico. Tampoco convierte una guía histórica en procedimiento vigente.

## Uso esperado de agentes

Un agente puede inspeccionar, proponer un plan, editar archivos dentro de un
allowlist y ejecutar pruebas locales seguras. Debe detenerse ante fuentes
divergentes, secretos, PII, destrucción inesperada o necesidad de mutar AWS sin
autorización explícita.

Para trabajo de plataforma se exige:

- aislar branch y worktree antes de editar;
- preservar cambios ajenos y mantener un diff acotado;
- usar el script o target existente en lugar de duplicar lógica;
- explicar supuestos, límites de evidencia y fallos reales;
- no silenciar tests, scanners ni gates fail-closed;
- no hacer commit, push, merge o mutaciones cloud sin autorización específica.

## Automatización de build y release

La CI de microservicios usa el workflow versionado y el script
`scripts/microservices/build-push.sh`. Los pull requests sólo validan. La
publicación requiere OIDC, rol de mínimo privilegio y Environment protegido.
Un agente no introduce claves estáticas, no selecciona cuentas por defecto y
no actualiza ECS de forma imperativa.

La automatización debe dejar trazabilidad entre commit, base image, imagen de
servicio, digest ECR, metadatos SSM y plan Terraform. Si esa cadena no puede
reconstruirse, el release no es promovible.

## NotebookLM Brain

El Brain contiene narrativas compactas para arquitectura, seguridad,
despliegue, pruebas y operación. Cada fuente debe incluir referencias al
repositorio, fecha o versión cuando sea relevante, límites de evidencia y
condiciones NO-GO. No debe duplicar bloques extensos de comandos porque éstos
envejecen fuera del playbook canónico.

### Contenido permitido

- decisiones y consecuencias de ADRs;
- modelos de amenaza y controles a alto nivel;
- secuencias operativas, criterios de aceptación y handoff;
- glosarios, ownership y referencias entre documentos;
- resultados sanitizados sin identificadores ni datos de cliente.

### Contenido excluido

- access keys, tokens, cookies, contraseñas, perfiles o credenciales;
- tfvars reales, state, planes, outputs o configuraciones generadas;
- account IDs, ARNs, dominios o identificadores de clientes reales;
- documentos, PII, datos bancarios, gubernamentales o personales;
- logs productivos, payloads, dumps, fixtures reales o bundles de auditoría;
- instrucciones destructivas, bypasses o pasos mutating sin control humano.

Las fuentes que no puedan sanitizarse de forma confiable no se cargan en
NotebookLM. Se conserva únicamente un enlace o descripción de su autoridad.

## Human-in-the-loop

Las decisiones de aplicar Terraform, publicar imágenes, escribir SSM, promover
a producción, ejecutar rollback o dar acceso a usuarios pertenecen a un humano
autorizado. La automatización puede preparar una vista previa y verificar
precondiciones; la aprobación debe ocurrir en el sistema de control
correspondiente y quedar registrada.

## NO-GO para automatización

Se detiene la automatización si el contexto de cuenta es ambiguo, el objetivo
no está allowlisted, una fuente contradice el código, se requiere un secreto en
texto, aparece contenido sensible o una acción excede la autorización vigente.
La falta de permisos nunca se resuelve ampliando privilegios automáticamente.

## Mantenimiento del Brain

El Brain debe revisarse en el mismo PR cuando cambien arquitectura, contratos,
workflows, gates, secuencia de despliegue o responsabilidades operativas. Una
fuente histórica se marca como tal o se elimina del conjunto curado; nunca se
presenta junto a la guía vigente sin advertir la diferencia.

## Fuentes canónicas

- [`playbooks/enterprise-client-deployment.md`](../playbooks/enterprise-client-deployment.md)
- [`.github/workflows/microservices-build.yml`](../.github/workflows/microservices-build.yml)
- [`scripts/microservices/build-push.sh`](../scripts/microservices/build-push.sh)
- [`ADR-009`](../ADR/ADR-009-threat-model.md)
- [`ADR-010`](../ADR/ADR-010-testing-rollout.md)
