# Seguridad, identidad y cadena de suministro

> **Fuentes:** [ADR-004](../ADR/ADR-004-cross-account-identity.md),
> [ADR-007](../ADR/ADR-007-artifact-supply-chain.md),
> [ADR-009](../ADR/ADR-009-threat-model.md) y
> [ADR-011](../ADR/ADR-011-monorepo-microservices-source.md),
> [ADR-020](../ADR/ADR-020-versioned-m2m-identity-binding.md),
> [ADR-021](../ADR/ADR-021-object-level-authorization.md) y
> [ADR-023](../ADR/ADR-023-enterprise-authorization-and-user-lifecycle.md)

## Frontera de seguridad

La cuenta AWS dedicada es el límite de cada deployment. Documentos, PII,
resultados de extracción, cómputo, storage, identidad, cifrado y observabilidad
de un cliente deben permanecer dentro de ese límite.

El repositorio contiene source y configuración declarativa segura. Las cuentas
cliente reciben artefactos inmutables; no deben recibir clones del source.

## Identidad: decisión, implementación y evidencia

ADR-004 describe un modelo objetivo de roles terminales separados para plan,
apply, promotion, validation y operaciones break-glass. Su estado es
**DRAFT rev3**. No se debe afirmar que los seis roles, session policies,
SourceIdentity, boundaries y trust conditions están desplegados en todas las
cuentas sin revisar IaC y evidencia live.

Los invariantes son:

- identidad y región se proporcionan explícitamente;
- caller account se verifica antes de cualquier mutación;
- least privilege por operación y layer;
- una sesión de deployment no puede escapar a otro deployment;
- trust policies evitan confused deputy;
- break-glass es humano, excepcional, auditable y no automatizado;
- producción es read-only por defecto.

## GitHub Actions y OIDC

El flujo monorepo implementa GitHub OIDC como mecanismo de automatización. Las
reglas son:

- pull requests no reciben credenciales AWS ni permiso id-token;
- el job de publicación recibe id-token únicamente cuando publica;
- el trust debe bindear repositorio, branch/Environment y rol exactos;
- el Environment protegido contiene account, región, deployment, ECR prefix y
  base image aprobados;
- el workflow y el script comparan identidad esperada con caller account;
- ninguna AWS access key estática pertenece en secrets, variables o archivos.

Este diseño está **Implemented** y **Locally validated**. El nuevo flujo
monorepo no está **Live validated** hasta ejecutar y leer de vuelta una
publicación autorizada en non-production.

## Datos sensibles

Nunca versionar, imprimir ni usar como fixture:

- documentos o uploads de clientes;
- PII real, datos bancarios, personales o gubernamentales;
- tokens, passwords, cookies o credenciales;
- private keys, certificados privados o archivos de entorno;
- Terraform state, planes o backups;
- logs de producción, dumps o extracted payloads;
- generated config con identificadores reales.

Los tests usan datos sintéticos mínimos. Un valor con forma de identidad sólo
es aceptable cuando está documentado como sintético y cubierto por una
allowlist estrecha. Una allowlist no convierte datos reales en seguros.

La observabilidad registra IDs técnicos, estados y errores sanitizados; no
registra documentos, texto extraído, JWT ni secretos.

## Cadena de suministro implementada

| Control | Estado |
|---|---|
| Source canónico único en GitHub | **Implemented** en la branch, pendiente de merge |
| Dockerfiles con BASE_IMAGE explícita | **Implemented**, **Locally validated** |
| Base image enterprise en ECR objetivo por digest | **Implemented** como requisito del flujo |
| ECR customer-local con tags inmutables | **Implemented** en IaC; validar cada deployment |
| Lectura de digest después del push | **Implemented**, **Locally validated** |
| Escritura de image_digest al final | **Implemented**, **Locally validated** |
| ECS actualizado sólo por Terraform | **Implemented** como separación de ownership |
| Build/push real del monorepo | No **Live validated** |

## Cadena de suministro objetivo

ADR-007 describe capacidades adicionales:

- SBOM por artefacto;
- signing y verificación;
- provenance/attestation;
- vulnerability scan gate con política definida;
- dependencias lockeadas y verificadas;
- builder y egress controlados;
- build central firmado y promoción verificable.

Estas capacidades son **Target** salvo evidencia específica. ADR-011 registra
que el flujo actual hace builds customer-scoped, mantiene dependencias no
completamente deterministas y aún no implementa todas las etapas de ADR-007.

## Controles fail-closed

Una operación se detiene cuando:

- la cuenta o región no coincide;
- falta BASE_IMAGE o no está identificada por digest para publicación;
- se intenta usar latest;
- el repositorio ECR no existe o el tag inmutable ya representa bytes distintos;
- el contract deployment/account/route no coincide;
- falta una precondición de estado o identidad;
- el payload productivo está degradado o ambiguo;
- un security gate encuentra secretos, PII no autorizada, state o planes;
- se solicita write-ssm sin una publicación verificada;
- un cambio CI legado produciría destrucción no revisada.

Los errores no se silencian para continuar una release.

## Identidad de aplicación

La plataforma ya tiene decisiones y contratos de repositorio para binding M2M,
ownership de objetos y autorización enterprise. Todavía no tiene evidencia
integrada de que Cognito, token claims, Terraform, configuración ECS, todas las
rutas y onboarding consuman esos contratos en runtime.

Estado: **Blocked**.

Hasta cerrarlo:

- no crear ni entregar usuarios;
- no debilitar validación tenant/customer;
- no derivar identidad de campos no confiables;
- no afirmar login, API protegida o pipeline E2E como listos para producción.

El frontend también está **Blocked** hasta que una capa Terraform tenga
ownership único de config.json y bindings exactos de CloudFront, API y S3.

### Binding M2M versionado

GUG-102 WP1 introduce en el repositorio un camino M2M fail-closed y versionado.
No cambia silenciosamente el contrato v1 que todavía acepta customer slugs.
El contrato v2 exige identidades sintácticamente separadas:

- `cust_<ULID>` para el cliente;
- `dep_<ULID>` para el deployment; y
- un binding explícito de client ID, customer, deployment y scopes requeridos;
- conjuntos versionados, exactos y disjuntos de scopes para las acciones
  `read`, `write` y `admin`.

La decisión de autorización M2M debe comprobar el issuer y firma ya verificados,
el client permitido, `token_use=access`, todos los scopes del binding, el
customer esperado y el deployment esperado. Las acciones autorizadas se
derivan sólo del binding: scopes adicionales presentes únicamente en el token
no elevan permisos. Cada ruta M2M declara lectura, escritura o exportación
(`read+admin`). Un claim firmado opcional también debe coincidir. Un header o
payload nunca selecciona identidad.

Terraform entrega `SCANALYZE_DEPLOYMENT_CUSTOMER_ID` y
`SCANALYZE_DEPLOYMENT_ID` como valores distintos y bloquea overrides desde
configuración adicional del servicio. El mapa customer-only legado no prueba
autorización de deployment.

Esta capacidad sólo puede clasificarse como **Implemented** y **Locally
validated** después de que pasen los tests del commit revisado. No es **Live
validated**. La habilitación real continúa **Blocked** hasta que GUG-93 resuelva
el handoff del DAG y Cognito/API Gateway, implemente los scopes canónicos de
ADR-023 y sus versiones, y GUG-117 demuestre aislamiento entre dos deployments
no productivos. Producción continúa **NO-GO**.

### Autorización enterprise y lifecycle

GUG-92 / ADR-023 define un contrato portable de RBAC+ABAC. Los roles humanos
cerrados son `customer_admin`, `document_operator`, `document_reviewer` y
`auditor`; las acciones cerradas `read`, `write` y `admin` se vinculan a
`scanalyze.api.v1/read`, `scanalyze.api.v1/write` y
`scanalyze.api.v1/admin`. Un scope en el token es necesario donde aplica OAuth,
pero no basta para autorizar.

Cada decisión humana elige exactamente un path: membership activo con un rol,
o grant temporal activo/versionado de soporte o break-glass ligado al subject.
Ambos exigen versiones vigentes, operación/recurso/acción/data class cerrados,
`customer_id` y `deployment_id` exactos, ownership ADR-021, clasificación de
datos, assurance requerida y precedencia de deny. Un
rol nunca cruza deployment ni ownership. `results.read_full`,
`exports.execute` y `artifacts.download` conservan `read+admin` y requieren
step-up phishing-resistant para humanos.

El lifecycle es `invited`, `active`, `suspended`, `expired` o `revoked`; los dos
últimos son terminales. Cambiar rol, suspender o revocar incrementa la versión
de membership y los cambios sensibles revocan sesiones. No hay self-signup,
self-promotion, self-approval ni remoción del último admin sin reemplazo
aprobado en el mismo deployment.

Bootstrap es single-use, expira, exige dos aprobadores y MFA resistente a
phishing. Soporte es JIT con aprobación del cliente, operaciones exactas y
auto-revocación. Break-glass es humano, ligado a incidente, dual-approved,
temporal, auditado y revisado posteriormente. Ninguno crea un rol standing; en
v1 niegan incondicionalmente full PII, export y artifact protegido. Los service principals no
pueden heredar roles humanos, administrar lifecycle ni recibir soporte o
break-glass.

El contrato source no contiene IDs de cliente/deployment, cuentas, regiones,
pools, clients o recursos reales. Un adapter de provider traduce claims
firmados al contexto interno y puede reducir autoridad, nunca ampliarla o
inferir valores ausentes. GUG-93 implementa provider/IaC, GUG-153 el PDP/PEP
backend, GUG-94 las APIs administrativas, GUG-95 UI/E2E y GUG-117 la evidencia
integrada. GUG-92 no está **Live
validated** y no autoriza Cognito, AWS, migración ni producción.

### Autorización de documentos y batches

GUG-114 define autorización de objeto además de autenticación y policy de ruta.
Cada documento y batch nuevo necesita dos campos canónicos e inmutables:
`customer_id` y `deployment_id`. Ambos proceden únicamente del `AuthContext`
validado. La autorización requiere igualdad exacta con el customer y deployment
autenticados; `tenantId`, headers, parámetros, payload, metadata, mapas legacy y
prefijos S3 nunca crean autoridad.

Un registro con ownership faltante, parcial, malformado, ambiguo, inconsistente o
sólo legacy se rechaza y requiere clasificación de migración o cuarentena. No se
infiere el owner actual, no se elige automáticamente entre valores conflictivos y
no se copian los datos del batch a todos sus documentos.

El batch y cada documento miembro se autorizan de forma independiente. Un
documento extranjero dentro de un batch autorizado bloquea membership, lectura y
export completos; no se entrega un resultado parcial. Lista, búsqueda, índices y
paginación deben conservar customer y deployment en el boundary de consulta. Un
scan o filtrar después de recuperar datos no constituye aislamiento.

Una URL prefirmada sólo se genera después de autorizar el documento. Bucket y key
se obtienen de metadata almacenada bajo el contrato revisado, nunca de una ruta o
prefijo enviado por el cliente. Export, full PII, result y downloads protegidos
conservan `read+admin`. Las respuestas no distinguen un objeto extranjero de uno
ausente cuando esa diferencia permitiría enumeración, y los logs no contienen
contenido, PII, JWTs, S3 keys, URLs prefirmadas ni payloads.

El contrato transitorio de artifacts admite solamente las claves exactas que
producen hoy los workers, vinculadas al document id y al bucket configurado del
deployment; no acepta prefijos libres. Employee Profiles autoriza estado
preexistente aun con `force=true` y usa precondiciones de versión S3. El consumidor
OCR todavía no reconcilia obligatoriamente el tuple de ownership antes de usar el
locator del mensaje: esa frontera asíncrona continúa **Blocked** para GUG-89 y no
forma parte de una afirmación end-to-end o live de GUG-114.

ADR-021 y el runbook de ownership son decisiones de repositorio. La capacidad es
**Implemented** sólo cuando el commit revisado contiene enforcement central,
rutas y storage protegidos. Es **Locally validated** sólo con tests sintéticos y
gates verdes identificados, y **CI validated** sólo con checks verdes del commit
exacto. No existe evidencia **Live validated** de inventario legacy, migración ni
aislamiento entre dos deployments. Esas actividades siguen **Blocked** por
GUG-117 y autorización non-production separada. Producción continúa **NO-GO**.

## Rollback y respuesta

- Una release se revierte seleccionando digests previamente aprobados mediante
  un nuevo plan Terraform.
- State no es rollback.
- Un tag inmutable no se sobreescribe ni se borra para “reparar” metadata.
- Reconciliación usa lectura de digest y comparación exacta.
- Break-glass y destrucción siguen procesos separados y aprobados.

## Preguntas de revisión

1. ¿La acción cruza una frontera de cuenta o datos?
2. ¿La identidad proviene de una fuente confiable y está vinculada al deployment?
3. ¿Los permisos son mínimos para esa fase?
4. ¿La imagen, base image y release están identificadas de forma inmutable?
5. ¿Hay evidencia local o live, y para qué ambiente?
6. ¿La operación revela PII o secretos en logs?
7. ¿Existe un blocker que se está intentando eludir?

Si alguna respuesta es desconocida, no autorizar la mutación.
