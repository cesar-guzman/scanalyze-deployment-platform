# GUG-95 — Enterprise User Console

## Resumen

GUG-95 implementa una consola portable de usuarios y privilegios sobre las APIs
recuperables de GUG-94 y el PDP/PEP de GUG-153. La UI nunca se convierte en
autoridad: las claims del access token sólo deciden qué controles mostrar y
cada llamada vuelve a autorizarse en backend con customer, deployment,
membership, versión de policy y estado actual exactos.

`customer_admin` puede listar membresías opacas y ejecutar invitación,
reenvío, activación, cambio de rol, suspensión, reactivación, revocación y
revocación de sesiones. `auditor` sólo recibe eventos de auditoría sanitizados.
Operadores, revisores, M2M, ID tokens, membresías inactivas, versiones
desconocidas y bindings ajenos fallan cerrados sin llamadas administrativas.

La lista no contiene correo, subject ni identificadores del provider. El correo
de invitación sólo existe en el formulario y request protegido. La telemetría
es un ring en memoria con operaciones/resultados allowlisted y referencias
opacas; no admite payloads ni campos arbitrarios.

## Reenvío y recuperación

GUG-95 agrega el contrato faltante de reenvío de invitación sin crear un scope o
rol nuevo. Reutiliza el PEP de creación de invitación, requiere aprobación
independiente, reconciliación exacta del provider y un checkpoint durable antes
de incrementar condicionalmente la versión y renovar la expiración de la
membresía. Antes del efecto, todas las `Idempotency-Key` para la misma
membresía y versión compiten por una sola reserva durable. Después, el store
devuelve un resultado explícito `applied_here` para el checkpoint de la
operación: sólo el caller que ganó ambas escrituras condicionales puede llamar
`RESEND`. Ver la etapa `provider_effect_reserved` no prueba ownership; losers,
replays y resultados ambiguos quedan en cuarentena sin reenvío automático.

## Browser y edge

El edge permite `Idempotency-Key` y expone solamente las referencias sanitarias
de correlación, request y trace. La UI tiene estados loading, empty, denied,
conflict, session expired, rate limited y degraded; no muestra el body de error.

## Evidencia

- **Implemented:** candidato local con UI, cliente tipado, resend recuperable,
  schemas, CORS, ADR, threat model y pruebas.
- **Locally validated:** sólo los comandos nombrados para el commit candidato.
- **Resultados locales:** repo `852`, ingest API `688`, lifecycle enfocado `47`,
  frontend unit `36`, browser `13`, edge Terraform mock `7`, contract matrix
  `114/114` y provider offline `11/11`, todos aprobados.
- **CI validated:** pendiente del PR y SHA exactos.
- **Live validated:** no.
- **AWS/Cognito/deployment:** no ejecutado.
- **Production:** **NO-GO**.

La corrección single-winner se validó con stores/providers fake, incluyendo
carreras con claves iguales y distintas para una misma membresía y versión.
La clasificación local de sesión expirada y la paginación `nextCursor`
continúan abiertas como P2 de GUG-95.

Después de CI/review/merge/main todavía falta una prueba autorizada de
aislamiento entre dos deployments y los restantes gates de GUG-117.
