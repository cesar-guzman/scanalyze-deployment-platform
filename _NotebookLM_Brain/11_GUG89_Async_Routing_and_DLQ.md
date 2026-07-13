# GUG-89 — routing asíncrono, ownership y DLQ

> **Fuente sanitizada para NotebookLM**
>
> **Fecha editorial:** 2026-07-12
>
> **Fuentes canónicas:** ADR-022, contrato de topología, runbook de DLQ, código y
> tests del commit revisado
>
> **Evidencia live:** no existe en esta fuente
>
> **Producción:** **NO-GO**

## Qué problema resuelve GUG-89

Autenticar una solicitud y autorizar un documento en la API no garantiza que la
misma identidad se conserve en cada mensaje asíncrono. Un worker tampoco puede
suponer que un mensaje es autorizado porque llegó a su cola.

GUG-89 define un contrato fail-closed para que cada salto transporte la identidad
canónica y vuelva a compararla con el documento autoritativo antes de usar S3,
Textract, DynamoDB, extracción, persistencia, notificación o una cola posterior.
También define una cola y una DLQ por stage para que un mensaje inválido o poison
no desaparezca como si hubiera sido procesado correctamente.

El tuple de ownership es exactamente:

```text
customer_id
deployment_id
ownership_schema_version = 1
```

Los dos identificadores deben ser válidos y coincidir exactamente con el registro
autoritativo. No existe fallback por `tenantId`, route, metadata, nombre de cola,
customer stack, prefijo S3, batch, header o payload.

## Los nueve stages canónicos

| Stage | Productor | Consumidor y modo |
|---|---|---|
| `ingest` | `ingest-api` | `ocr-worker:INGEST` |
| `ocr` | `ocr-worker` | `ocr-worker:OCR_POLL` |
| `classify` | `ocr-worker` | `classifier-worker:CLASSIFY` |
| `bank-extract` | `ocr-worker` o `classifier-worker` | `bank-worker:BANK_EXTRACT` |
| `personal-extract` | `ocr-worker` o `classifier-worker` | `personal-worker:PERSONAL_EXTRACT` |
| `gov-extract` | `ocr-worker` o `classifier-worker` | `gov-worker:GOV_EXTRACT` |
| `validate` | workers de dominio | `postprocess-worker:VALIDATE` |
| `persist` | `postprocess-worker` | `postprocess-worker:PERSIST` |
| `notify` | `postprocess-worker` | `postprocess-worker:NOTIFY` |

La topología contiene exactamente nueve colas fuente Standard y nueve DLQ
Standard. Cada cola fuente tiene visibility timeout de 300 segundos y máximo de
tres receives antes de la DLQ. Cada DLQ usa una política `byQueue` que permite
únicamente su fuente exacta.

Standard significa entrega at-least-once: pueden existir duplicados. Por ello un
worker necesita idempotencia y condiciones ligadas al mismo owner; recibir el
mismo mensaje otra vez no concede permiso para repetir el efecto.

## Flujo de autoridad

Para cada mensaje, el orden conceptual es:

1. parsear sin registrar el body;
2. validar la versión v2 y el stage exactos;
3. rechazar campos extra que puedan introducir autoridad;
4. cargar el documento mínimo desde la tabla seleccionada por configuración del
   deployment;
5. comparar customer, deployment y ownership schema;
6. comparar stage, processing domain y locators almacenados cuando apliquen;
7. verificar idempotencia bajo el mismo binding;
8. ejecutar el efecto protegido;
9. publicar el mensaje completo al siguiente stage y exigir `MessageId`;
10. registrar el handoff con condición de ownership; y
11. reconocer el mensaje sólo cuando el resultado quede probado.

Si cualquiera de esas pruebas falla, el worker no adopta el mensaje, no infiere
campos y no lo trata como éxito.

## Contratos v2

| Schema | Stage | Prueba adicional |
|---|---|---|
| `scanalyze.ingest.v2` | `ingest` | locator raw almacenado; el dominio puede estar ausente antes de clasificar |
| `scanalyze.ocr-poll.v2` | `ocr` | job de Textract y locators source/OCR reconciliados |
| `scanalyze.classify.v2` | `classify` | locators raw y OCR autorizados; el mensaje no elige autoridad de dominio |
| `scanalyze.extract.v2` | uno de los tres extract | `processing_domain` exacto y locators raw/OCR autorizados |
| `scanalyze.validate.v2` | `validate` | dominio y locator structured autorizados |
| `scanalyze.persist.v2` | `persist` | validation result consistente y locator structured autorizado |
| `scanalyze.notify.v2` | `notify` | resultado terminal consistente con validation |

Cada schema es estricto. Una versión desconocida o un campo de autoridad no
reconocido no se transforma silenciosamente a una forma conocida.

## Qué sí puede transportar `_metadata`

Sólo metadata de trazabilidad allowlisted, como referencias sintéticas de
correlación o trace. Esa metadata ayuda a observar el flujo, pero nunca decide:

- customer o deployment;
- ownership version;
- processing domain;
- pipeline stage;
- bucket, key o prefix;
- tabla, queue o worker; ni
- autorización o idempotencia.

No se publican bodies, contenido documental, PII, identificadores de clientes,
JWT, claves S3, resultados OCR, datos financieros extraídos, URLs prefirmadas,
tokens ni credenciales en NotebookLM, Linear, Git, chat o evidencia general.

## Cómo falla cerrado

| Caso | Resultado esperado |
|---|---|
| Ownership ausente o malformado | deny antes del primer efecto protegido; retry y DLQ exacta |
| Mismo customer y otro deployment | deny; no revelar si el documento existe |
| Mismo deployment y otro customer | deny; no revelar si el documento existe |
| Ownership parcial o conflictivo | deny y clasificación de cuarentena/investigación |
| Mensaje legacy v1 | deny; no migración o coerción automática |
| Stage o dominio inconsistente | deny antes de leer artifacts |
| Bucket/key distinto del registro | deny antes de S3/Textract |
| SQS sin `MessageId` | handoff no probado; no avanzar como éxito |
| Duplicado con efecto exacto probado | resultado idempotente revisado |
| Duplicado con efecto ajeno o incierto | conflicto; no adoptar el efecto |
| Excepción inesperada | diagnóstico sanitizado; retry y DLQ, no ack silencioso |

“Cuarentena” describe una disposición revisada. Esta fuente no afirma que exista
un recurso live de cuarentena ni autoriza mover mensajes.

Un `HeadObject` exitoso en el key canónico sólo prueba que existe un objeto. No
prueba quién lo escribió, su schema o digest, el checkpoint del stage ni el
handoff posterior. La optimización local de retry de los workers de dominio no
es evidencia durable de idempotencia y no habilita producción ni redrive. Esa
prueba continúa bloqueada para GUG-118 mediante un binding de contenido/checkpoint
o un ledger durable revisado.

## DLQ no significa replay autorizado

Un mensaje en DLQ puede haber producido un efecto parcial. También puede ser
malicioso, foreign, stale, legacy o ambiguo. Antes de cualquier redrive futuro se
requieren:

- inventario report-only en un workspace protegido;
- clasificación sin copiar datos sensibles a evidencia general;
- misma cuenta, región, deployment, stage y source/DLQ pair;
- revalidación del schema, owner, documento, dominio y locators;
- evidencia de idempotencia y reconciliación de efectos parciales;
- dry-run sin writes ni downstream calls;
- aprobación independiente y candidate manifest inmutable;
- límites de count, rate, concurrency, tiempo y costo;
- alarmas y stop conditions verificadas; y
- rollback entendido como detener y reconciliar, nunca purgar.

No se cambia el body para hacerlo elegible. No se infiere ownership. No se brinca
el stage que falló. No se redrive entre deployments. No se purga una cola o DLQ.

GUG-89 no ejecuta inventario live, migración, redrive, purge ni deployment.

SQS no ofrece un `peek` no destructivo del body. Métricas, atributos y alarmas de
cola pueden revisarse con APIs read-only autorizadas, pero clasificar schema u
ownership requiere recibir el mensaje y cambiar temporalmente su visibility.
Esa inspección permanece **Blocked** hasta un procedimiento protegido separado;
sin él no se puede declarar ningún mensaje `eligible_candidate`.

## Inventario de legacy y mensajes problemáticos

| Clase | Definición | Tratamiento |
|---|---|---|
| `eligible_candidate` | v2, binding completo, mismo deployment, documento/locators autorizados, fix e idempotencia probados | sólo puede avanzar a dry-run |
| `legacy` | v1 o schema no soportado | deny y cuarentena/investigación |
| `unbound` | owner ausente o malformado | deny y cuarentena/investigación |
| `partial` | sólo una parte del tuple | deny y cuarentena/investigación |
| `ambiguous` | alias, stage, domain o locators contradictorios | deny; no inferencia |
| `foreign` | owner distinto del documento/deployment autoritativo | deny y security review |
| `orphaned` | documento o artifact requerido ausente | deny; no reconstrucción inferida |
| `inconsistent` | estado, schema, stage, domain o locator no coincide | deny y preserve evidence |
| `partial_effect_unknown` | puede existir un efecto previo que no se puede probar | redrive bloqueado |

La mayoría, similitud, antigüedad o conocimiento del operador no convierten un
mensaje en `eligible_candidate`.

## Separación de paquetes

GUG-89 es dueño del contrato de mensajes, producer/consumer routing, checks de
ownership, handoff y topología source/DLQ en el repositorio.

Los nombres `scanalyze.*.v2` versionan bodies de mensajes. El cambio también
autora un contrato aditivo `data-foundation/v2` para las nueve colas por stage,
mientras preserva el schema, fixture, recursos y outputs legacy de
`data-foundation/v1`. Código v2 en el repositorio no prueba apply, publication,
activación de task definitions, cutover de productores ni contenido de colas
live.

GUG-108 sigue siendo una dependencia separada del programa. Esta fuente no
absorbe sus acceptance criteria ni afirma que task definitions o consumidores
live estén activados.

GUG-118 es el gate posterior de runtime topology, FIFO, idempotency y DLQ. Debe
resolver o aceptar con evidencia:

- decisión/migración FIFO;
- ledger idempotente durable;
- outbox, leases o heartbeat según el diseño aprobado;
- failure injection;
- alarmas y backpressure;
- implementación de cuarentena;
- redrive controlado; y
- prueba de no loss/no duplicate y steady-state recovery.

Que GUG-89 use Standard queues de forma explícita no significa que la decisión
FIFO de GUG-118 esté cerrada.

## Estados de evidencia

| Estado | Significado exacto para GUG-89 |
|---|---|
| **Implemented** | El commit revisado contiene contratos v2, checks de ownership, topología exacta y políticas DLQ. Un ADR solo no basta. |
| **Locally validated** | Tests sintéticos y gates offline identificados pasan para ese commit. No prueba AWS. |
| **CI validated** | Required checks del PR pasan para el SHA exacto. No prueba queues ni workers live. |
| **Live validated** | Evidencia non-production autorizada demuestra wiring, aislamiento, retry, DLQ y recovery. No existe en esta fuente. |
| **Blocked** | Provider/AWS, deployment, inventario live, failure injection, redrive, migration, purge, aislamiento runtime entre dos deployments y producción. |

Un check `SKIPPED` o `BLOCKED` nunca se registra como `PASSED`. Un merge futuro
no convierte por sí solo el control en live validated.

## Riesgo residual

El riesgo sigue alto hasta que existan revisión, CI, wiring y evidencia
non-production autorizada. Es crítico si un consumidor acepta ownership foreign
o ambiguo, confía en locators del mensaje sin reconciliación, reconoce poison
messages como éxito o permite redrive no controlado.

Producción permanece **NO-GO**.

## Preguntas que esta fuente debe responder fail-closed

1. ¿El mensaje contiene customer y deployment canónicos completos?
2. ¿Ambos coinciden con el documento autoritativo del mismo deployment?
3. ¿El schema y pipeline stage son exactamente los esperados por la cola?
4. ¿El processing domain proviene de configuración o clasificación autorizada?
5. ¿Los locators coinciden con metadata almacenada antes de S3 o Textract?
6. ¿El worker exige `MessageId` antes de aceptar el handoff?
7. ¿El mensaje se reconoce sólo después del efecto y handoff probados?
8. ¿Un duplicado demuestra el mismo owner, document, stage y efecto?
9. ¿Un poison message queda retenido en la DLQ exacta?
10. ¿Se está intentando inferir, reescribir, migrar, purgar o redrive sin
    aprobación?
11. ¿La evidencia es repo, local, CI o realmente live?
12. ¿GUG-108 y GUG-118 siguen separados de GUG-89?
13. ¿Producción continúa NO-GO?

Si falta cualquiera de estas pruebas, la respuesta operativa es **Blocked** o
**Denied**, nunca una inferencia optimista.
