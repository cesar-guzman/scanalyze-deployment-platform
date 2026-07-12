# Scanalyze — Foundation de Production Readiness (Fase 0)

> **Fuente derivada y sanitizada**\
> **Programa:** GUG-115\
> **Gate:** GUG-116\
> **Última revisión:** 2026-07-11\
> **Producción:** **NO-GO**

## Límite de esta fuente

Este documento explica decisiones de arquitectura y gobierno. No es un runbook
ejecutable, no concede autorizaciones y no contiene evidencia AWS. No incluye
credenciales, identificadores operativos reales, manifests resueltos, variables
reales, state, planes, outputs, logs, datos de clientes ni PII.

Las fuentes canónicas siguen siendo el código y tests del commit revisado, los
ADR aceptados, el DAG declarativo, los playbooks y los registros formales de
cambio. Una respuesta de NotebookLM no reemplaza una aprobación ni crea
evidencia.

## Estado actual

Scanalyze tiene una base local considerable:

- un monorepo común para todos los clientes, sin forks;
- un modelo account-per-deployment;
- un DAG GitOps declarativo;
- schemas, fixtures, tests y controles locales;
- workflows que pueden validar el DAG en dry-run; y
- decisiones aceptadas para orquestación, required checks estables, contratos,
  identidad y artefactos inmutables.

El path Terraform live permanece deshabilitado. No existe evidencia revisable
en esta Fase 0 de un backend remoto live, roles terminales completos, contratos
SSM live, saved-plan apply, promoción completa, runtime estable o rollback
ejercitado. Por lo tanto, producción continúa **NO-GO**.

## Vocabulario de evidencia

| Estado | Significado |
|---|---|
| **Implemented** | El comportamiento o documento existe en una revisión identificada. No implica validación. |
| **Locally validated** | Pasaron checks locales identificados. No implica CI, AWS ni deployment. |
| **CI validated** | Pasaron checks de CI para un commit y workflow identificados. No implica AWS salvo evidencia explícita y autorizada. |
| **Live validated** | Evidencia sanitizada prueba ejecución en un deployment no productivo, ambiente y release explícitos. |
| **Target** | Diseño o control deseado todavía incompleto. |
| **Blocked** | Falta una dependencia o existe una condición que obliga detenerse. |

Un ADR aceptado describe una decisión; no demuestra implementación. Un
Terraform validate, un test, un mock o un dry-run no demuestra que exista una
infraestructura desplegada.

## Identidad y fail-closed

`customer_id` identifica al cliente. `deployment_id` identifica una instancia
operativa aislada y no es intercambiable con el cliente. Antes de cualquier
autoridad privilegiada deben coincidir de forma exacta:

- cliente;
- deployment;
- cuenta objetivo;
- región;
- ambiente lógico;
- GitHub Environment protegido;
- release inmutable;
- change;
- capa; y
- operación.

Si falta un binding, dos fuentes discrepan o no se puede demostrar su autoridad,
el flujo se detiene antes de solicitar OIDC o ejecutar cualquier mutación. El
estado correcto es **Blocked**. Nunca se completa un binding por inferencia.

## Modelo GitOps objetivo

GitHub Actions es el control plane live objetivo. La ejecución local sirve para
validación y dry-run; no es un path autoritativo de apply.

```text
source y request revisados
  -> registry y account-ready
  -> GitHub Environment del deployment
  -> OIDC
  -> Plan
  -> policy y aprobación del saved plan exacto
  -> Apply de ese plan
  -> contrato de la capa
  -> Promotion del release inmutable
  -> Validation y evidencia sanitizada
```

Las autoridades están separadas:

- **Plan** lee y crea un saved plan; no modifica infraestructura.
- **Apply** verifica y aplica sólo el plan aprobado; no re-planifica.
- **Promotion** copia y verifica artefactos; no construye ni aplica Terraform.
- **Validation** lee salud/contratos y produce evidencia sanitizada; no muta.
- **Diagnostic** y **StateRecovery** existen sólo para incidentes definidos.

Cada job privilegiado debe apuntar por sí mismo al GitHub Environment protegido
y revalidar sus bindings. Una aprobación anterior no transfiere autoridad OIDC
a otro job.

## Política de saved plan exacto

El plan elegible para apply es exactamente el que revisó el aprobador, unido a
su digest, identidad del deployment, release, estado y contratos vigentes,
policy result, expiración y change.

Cualquier cambio o duda invalida el plan. Apply no crea otro plan ni sustituye
inputs. Se genera un plan nuevo y una aprobación nueva.

Los artefactos sensibles de ejecución permanecen cifrados, con mínimo privilegio
y vida corta fuera de Git, Linear y NotebookLM. La evidencia durable conserva
solamente metadata sanitizada y digests.

## Build once, promote, no rebuild

Un release completo une por digest todas las imágenes, la base image y la
evidencia requerida de SBOM, scanning, firma y provenance. La promoción copia y
verifica el mismo grafo.

Staging y producción deben usar exactamente los mismos digests. Producción no
reconstruye imágenes. Un tag mutable, una firma inválida, un artefacto faltante,
un gate `SKIPPED` o un digest distinto obliga **NO-GO**.

## Estrategia multi-cliente

Todos los clientes consumen el mismo source, schemas, módulos, workflows y
release train. Las diferencias se expresan en registros y contratos externos
validados. No se aceptan forks, ramas, copias de workflow ni cambios de source
por cliente.

Cada deployment tiene límites separados de cuenta, Environment, roles, state,
contratos y destino de artefactos. Una aprobación o identidad de un deployment
no sirve para otro.

## Región, DR y producción

El primer piloto productivo, si alguna vez recibe autorización explícita, queda
limitado a una sola región aprobada por deployment. Multi-región, failover y
write fencing permanecen **Blocked** hasta que exista una decisión posterior y
evidencia no productiva revisable. Fase 0 no afirma RTO ni RPO.

GUG-128, Production Pilot, permanece manualmente bloqueado. Requiere todos los
gates previos, staging certificado, resolución del riesgo single-maintainer y
aprobación humana independiente. Ningún merge, dry-run o resultado anterior lo
desbloquea de forma implícita.

## Secuencia de Fases 0–11

1. Foundation.
2. Identity y aislamiento multi-cliente.
3. Runtime, FIFO, idempotencia y DLQ.
4. Contratos estrictos y DAG canónico.
5. Registry, account baseline, backend y locking.
6. GitHub Environments, OIDC y roles terminales.
7. Build once y supply chain fail-closed.
8. Motor live sólo no productivo con saved plans exactos.
9. Observabilidad, resiliencia y operaciones.
10. Certificación de staging.
11. Piloto productivo limitado y manualmente bloqueado.
12. Factory de onboarding multi-cliente.

La lista incluye Fase 0 y Fases 1–11. Los issues de riesgo single-maintainer y
evidence hygiene son transversales, no fases adicionales. Un GO habilita sólo
el siguiente work package cuyos entry criteria estén completos.

GUG-116 es el gate de Fase 0 por su título, objetivo y alcance. Su frase final
contradictoria, que dice que no inicia Fase 0, se interpreta como que este gate
de planificación no inicia implementación de Fase 1 ni ejecución live. Si el
owner de Linear rechaza esa reconciliación, GUG-116 vuelve a **Blocked**.

Un riesgo High asignado a una fase posterior bloquea el exit y cualquier uso
live de esa capacidad, además de producción. No bloquea el work package local,
no privilegiado, cuyo propósito explícito es corregirlo; ese trabajo no puede
presentar el riesgo como cerrado antes de producir la evidencia del gate.

## Threat model resumido

Las amenazas prioritarias incluyen:

- bypass de required checks o revisión;
- Action, workflow, dependencia o runner comprometido;
- confused deputy OIDC;
- privilegios IAM demasiado amplios;
- mismatch de cliente, deployment, cuenta, región o ambiente;
- sustitución o replay de contratos;
- sustitución o expiración de saved plan;
- disclosure, manipulación o recovery indebido de state;
- tampering de registry o manifest;
- publicación ECR al cliente equivocado;
- sustitución de artefactos o rebuild en producción;
- gate de supply chain incompleto o `SKIPPED`;
- drift ECS fuera de Terraform;
- release parcial presentado como completo;
- evidencia local presentada como live;
- material sensible publicado en sistemas no autorizados; y
- concentración de autor, aprobador y ejecutor en una sola persona.

Los controles preventivos, detectivos y de recuperación deben tener un owner.
Los controles Target no reducen el riesgo actual hasta tener evidencia adecuada.
El riesgo single-maintainer permanece High y bloquea producción.

## Evidencia, retención y sanitización

Git, Linear y NotebookLM aceptan solamente source revisado, decisiones,
clasificaciones, referencias opacas, resultados sanitizados y digests no
sensibles. La evidencia operativa real vive en almacenamiento externo cifrado,
con mínimo privilegio, versionado, auditoría y retención definida.

Antes de publicar, un productor usa un schema allowlist, elimina payloads y
logs, sustituye identificadores por referencias opacas, escanea el resultado y
falla si aparece un campo desconocido o el scanner no termina.

Los saved plans y datos temporales de resolución son efímeros. Los metadatos de
release/deployment y las decisiones tienen retención mayor y trazabilidad hacia
su evidencia externa. Retener no concede permiso para publicar.

## Rollback y state recovery

Hay tres paths distintos:

1. **Application rollback:** un nuevo plan lleva los servicios a los digests de
   un release conocido y aprobado.
2. **Infrastructure rollback:** un nuevo plan lleva la infraestructura desde el
   state actual a una configuración revisada.
3. **Break-glass state recovery:** sólo después de demostrar corrupción o
   pérdida de state, con incidente, doble aprobación, identidad dedicada,
   alarma, auditoría y reconciliación posterior.

Terraform state restore no es rollback rutinario. Un timeout o resultado
incierto obliga detenerse, hacer readback y reconciliar antes de reintentar.

## Respuestas fail-closed obligatorias

### ¿Producción continúa NO-GO?

Sí. Producción continúa **NO-GO** y el piloto GUG-128 permanece bloqueado hasta
cumplir todos sus prerequisitos y recibir aprobación independiente explícita.

### ¿Fase 0 constituye evidencia AWS o live?

No. Fase 0 produce decisiones, documentación y validación local. No demuestra
recursos, configuración ni comportamiento en AWS.

### ¿Un dry-run demuestra un deployment?

No. Un dry-run puede demostrar validación y ausencia de mutación prevista, pero
no demuestra plan aplicado, recursos desplegados, salud runtime ni controles
AWS.

### ¿Se permiten rebuilds en producción?

No. Producción promueve exactamente el release inmutable certificado y verifica
sus digests. Un rebuild es NO-GO.

### ¿Qué ocurre ante un binding ambiguo o faltante?

El flujo falla antes de OIDC o cualquier mutación, registra **Blocked** y exige
reconciliar las fuentes autoritativas. No completa valores por inferencia.

### ¿Terraform state restore es rollback rutinario?

No. Es una operación break-glass para corrupción o pérdida demostrada, con
incidente, doble aprobación, auditoría y un plan posterior de reconciliación.
