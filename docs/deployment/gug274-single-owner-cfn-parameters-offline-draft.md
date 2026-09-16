# GUG-274 — borrador offline de parámetros CFN (`single_owner_v1`)

Estado: **BORRADOR OFFLINE / NO INSTALABLE**. Tip de `main` al redactar:
`6e08a14462176fb02c1abc372ed2b0646a653b87` (Merge `#117`).

## Propósito

Empaquetar la superficie pública de parámetros del template
`bootstrap/cfn-platform-authority-bootstrap-artifact-authority.yaml` **después**
de `#117` (`OperatorPolicyMode` / JWT v2) para que un operador humano pueda
rellenar únicamente los campos que ya existen como evidencia revisada, sin
inventar UserIds, TTI, issuer ni audience.

Este archivo **no** autoriza CreateChangeSet, Execute, Apply, READY, Deny-all
bypass, habilitar `apl-722313749a62e03b`, ni crear Grants/TTI.

Producción permanece **NO-GO**.

## Conteo

- **28** parámetros totales.
- **6** NoEcho de identidad (conservar solo en custodia privada `0600`).
- **7** parámetros añadidos/expuestos por la vía JWT + `single_owner_v1`
  (`IdentityGrantVersion`, `OperatorPolicyMode`, `SingleOwnerAuthorizedAt`,
  `SingleOwnerExpiresAt`, `JwtTrustedTokenIssuerArn`, `JwtIssuerUrl`,
  `JwtAudience`).

## Valores fijos ya anclados en fuente (seguros de citar)

| Parámetro | Valor anclado en template/fuente |
| --- | --- |
| `AuthorityAccountId` | `042360977644` |
| `DestinationAccountIds` | `905418363887` |
| `IdentityRedirectUri` | `http://127.0.0.1:38271/callback` (operación; grant instalado **no** verificado) |
| `IdentityGrantVersion` | `2` para `single_owner_v1` |
| `OperatorPolicyMode` | `single_owner_v1` |
| `SecondPartyIdentityStoreUserId` | `""` (vacío; Rules + `Fn::If`) |
| `AuthoritySigningProfileName` | `scanalyze_gug274_bootstrap_artifact_authority` |
| `AuthoritySigningProfileVersionId` | `fo5PB1XOji` |
| `AuthoritySigningTrustRootContractDigest` | `sha256:2909fb75ecb695b9891062ac4dafcba664128658d2351690557e0708c2de4bef` |
| `AuthoritySigningTrustRootConfigured` | `true` |
| `ExpectedBoto3Version` / `ExpectedBotocoreVersion` | `1.42.57` / `1.42.97` |
| `SourceCommit` (paquete limpio) | debe ser el commit **firmado/publicado** real; el tip de wiring es `6e08a144…` pero no sustituye un receipt firmado |

## Placeholders obligatorios (NO inventar)

Usar literales exactamente así en borradores públicos; sustituir solo en custodia
privada tras readback conectado revisado:

- `<NOECHO_IDENTITY_CENTER_APPLICATION_ARN>`
- `<NOECHO_IDENTITY_CENTER_INSTANCE_ARN>`
- `<NOECHO_IDENTITY_STORE_ARN>`
- `<NOECHO_PLAN_IDENTITY_STORE_USER_ID>`
- `<PLACEHOLDER_JWT_TRUSTED_TOKEN_ISSUER_ARN>`
- `<PLACEHOLDER_JWT_ISSUER_URL>`
- `<PLACEHOLDER_JWT_AUDIENCE>`
- `<PLACEHOLDER_SINGLE_OWNER_AUTHORIZED_AT>` / `<PLACEHOLDER_SINGLE_OWNER_EXPIRES_AT>`
- `<PLACEHOLDER_BOOTSTRAP_CHANGE_SET_NAME>`
- `<PLACEHOLDER_AUTHORITY_ARTIFACT_BUCKET|KEY|VERSION>`
- `<PLACEHOLDER_SIGNED_AUTHORITY_ARTIFACT_CODE_SHA256>`
- `<PLACEHOLDER_AUTHORITY_SIGNING_RECEIPT_DIGEST>`
- `<PLACEHOLDER_PACKAGE_SOURCE_COMMIT_40HEX>`

## JSON de borrador (no es request de CreateChangeSet)

Ver `examples/deployment/gug274-single-owner-cfn-parameters.DRAFT.json`.

## Bloqueos humanos restantes (Change Set / prod GO)

1. App IdC `apl-722313749a62e03b` sigue **DISABLED**; Grants/TTI históricamente
   vacíos — habilitar/crear requiere aceptación conectada revisada.
2. Receipt de artefacto firmado fresco en el tip (o commit de paquete limpio)
   + VersionId S3 real.
3. Custodia privada de los 6 NoEcho + ventana `single_owner` revisada (≤24h).
4. CreateChangeSet / Execute / Apply / READY y cualquier bypass Deny-all siguen
   fuera de alcance autónomo.
5. DNS/ALB/registry/MFA de express production siguen como gaps de producto
   separados (`docs/deployment/express-production-*.md`); no desbloquean GUG-274
   Change Set.

## Relación con el playbook

Actualiza la tabla de
`docs/operations/normal-authority-installation-20260914.md` (§ identidad /
parámetros) para que el conteo 28 y la vía `single_owner_v1` no queden a la
deriva respecto de `#117`.
