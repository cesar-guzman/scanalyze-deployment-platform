# Readiness productivo y handoff operativo

Production readiness es una decisión explícita basada en evidencia, no una
propiedad implícita de un merge o de un `terraform apply`. Este documento
resume los criterios de decisión; el procedimiento vigente permanece en
[`playbooks/enterprise-client-deployment.md`](../playbooks/enterprise-client-deployment.md).

## Estados que no deben confundirse

- **PR-ready:** diff seguro, acotado, reproducible y con gates locales verdes.
- **Merge-ready:** CI requerida y revisión humana aprobadas.
- **Release-ready:** imágenes, digests, metadata, changelog y rollback
  identificables.
- **Infrastructure-ready:** capas desplegadas, servicios estables y plan de
  reconciliación sin drift inesperado.
- **Application-ready:** autenticación, configuración frontend y pipeline E2E
  funcionan con contratos vigentes.
- **Production-ready:** se completaron ensayo no productivo, observabilidad,
  seguridad, continuidad, aprobación de cambio y handoff.

Pasar un estado no implica pasar los siguientes.

## Estado de evidencia del monorepo

La consolidación de los siete microservicios y las gates de seguridad cuentan
con evidencia local. El workflow de publicación, OIDC, escritura de metadata y
rollout todavía requieren ejecución controlada en una cuenta no productiva.

Además, el playbook mantiene como bloqueantes el propietario declarativo de la
configuración frontend y el contrato consistente de identidad del cliente.
Hasta cerrar y validar ambos, el veredicto para onboarding y producción es
**NO-GO**, aunque la infraestructura alcance estabilidad.

## Paquete de decisión GO/NO-GO

La reunión de cambio debe revisar un paquete sanitizado que incluya:

- commit o release aprobado y diff revisado;
- resultados de CI y toolchain utilizado;
- cuenta, región y deployment confirmados por los controles de identidad;
- planes por capa, cambios esperados y aprobación de destrucciones si aplica;
- base image y siete digests de servicio;
- resultado de scans y controles de supply chain disponibles;
- prueba de rollback no productiva;
- evidencia de estabilidad, alarmas y ausencia de drift;
- E2E sintético y resultado de aislamiento;
- riesgos residuales, excepciones con vencimiento y aprobadores;
- responsables de despliegue, seguridad, aplicación y guardia.

No se adjuntan secrets, state, planes binarios, documentos o logs sensibles al
Brain ni al repositorio.

## Criterios de readiness operativo

### Plataforma y seguridad

La cuenta está aislada, el acceso usa identidad federada, KMS y retención están
definidos, el acceso público corresponde al diseño, y las políticas de mínimo
privilegio fueron revisadas. No existen claves estáticas ni dependencias de
runtime en registries públicos.

### Aplicación y datos

Los siete servicios ejecutan los digests aprobados. SQS, DLQs, S3 y DynamoDB
pertenecen al deployment correcto. Reintentos e idempotencia fueron ejercitados
sin pérdida ni doble completion. Los logs no contienen documentos, texto
extraído, tokens ni PII.

### Observabilidad

Dashboards, alarmas, retención y rutas de escalamiento están activos. Se han
definido SLOs, señales de saturación, backlog de colas, edad de mensajes,
errores, latencia y costos. Cada alarma tiene owner y runbook.

### Continuidad

RTO y RPO están aceptados. Backups, restauración, retención, replay de DLQ y
rollback de release fueron probados en no-producción. La estrategia multi-
región o su exclusión está documentada según ADR-008.

### Cliente y cumplimiento

El onboarding usa el flujo de identidad aprobado, no contraseñas transmitidas
fuera de banda. El cliente recibe alcance de soporte, canales, responsabilidades,
ventanas, retención, clasificación de datos y criterios de aceptación.

## NO-GO de producción

La decisión es NO-GO ante cualquiera de estas condiciones:

- configuración frontend o identidad aún bloqueadas;
- CI, seguridad, plan o E2E fallidos o no ejecutados;
- imagen sin digest, proveniencia insuficiente o scan crítico no aceptado;
- drift, destrucción inesperada o cuenta objetivo ambigua;
- ausencia de alarmas, runbooks, guardia o rollback probado;
- uso de datos reales en pruebas o fuga de contenido en logs;
- excepción sin owner, vencimiento o aprobación;
- falta de aceptación del responsable de plataforma y del owner de aplicación.

## Handoff operativo

El handoff no es una transferencia informal. Debe registrar:

- inventario lógico del deployment y enlaces a contratos autoritativos;
- release, digests, fecha y aprobadores;
- matriz RACI y contactos de escalamiento;
- dashboards, alarmas, SLOs y horarios de soporte;
- procedimientos de incidente, rollback, DLQ replay y restauración;
- límites de capacidad, cuotas, presupuestos y tags de costo;
- riesgos aceptados y trabajo pendiente con fechas;
- acta de aceptación del cliente interno o externo.

El equipo receptor confirma acceso de sólo lectura y capacidad de ejecutar los
runbooks en un ejercicio controlado. Las credenciales nunca forman parte del
documento de handoff.

## Rollback y cierre de incidente

El rollback normal restaura digests aprobados mediante un nuevo plan Terraform.
El state no es rollback y ECS no se actualiza imperativamente. Después de un
rollback se valida estabilidad, drift, colas y ausencia de pérdida, y se abre
un análisis de causa antes de reintentar la promoción.

La destrucción de un ambiente pertenece a un runbook independiente, vigente y
aprobado. No se deriva automáticamente de esta guía ni de un documento
histórico.

## Exclusiones para NotebookLM

El Brain conserva criterios, ownership y referencias. Excluye detalles de
cuenta, artefactos de cambio, planes, state, secretos, datos de cliente, logs y
evidencia operativa sin sanitizar. La aprobación GO/NO-GO sólo es válida en el
sistema formal de cambios, nunca en una respuesta generada por IA.

## Fuentes relacionadas

- [`05_Enterprise_Deployment_Playbook.md`](05_Enterprise_Deployment_Playbook.md)
- [`06_Testing_and_Acceptance_Gates.md`](06_Testing_and_Acceptance_Gates.md)
- [`08_Monorepo_Microservices_and_Supply_Chain.md`](08_Monorepo_Microservices_and_Supply_Chain.md)
- [`ADR-008`](../ADR/ADR-008-region-ha-dr.md)
- [`ADR-010`](../ADR/ADR-010-testing-rollout.md)
