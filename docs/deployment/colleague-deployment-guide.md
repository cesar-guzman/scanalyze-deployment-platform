# Guía de Preparación GitOps Non-Prod

> **Estado:** preparación y dry-run local solamente. El operador local no ejecuta
> `terraform apply`, no publica imágenes y no escribe en SSM/ECR/ECS. El workflow
> non-production de esta etapa también permanece bloqueado para operaciones live.

## Principio de operación

Git contiene una solicitud de despliegue no sensible. El manifest real y el
deployment record resuelto viven cifrados y con control de acceso fuera del
repositorio.

La responsabilidad local termina después de:

1. validar herramientas y código;
2. crear y validar el manifest real fuera del repositorio;
3. ejecutar gates y dry-runs sin mutaciones;
4. crear una solicitud Git-safe revisable;
5. abrir un Pull Request.

## Requisitos previos

### Herramientas

| Herramienta | Versión requerida |
|---|---|
| Python | 3.11.x, según `.tool-versions` |
| Terraform | 1.14.6, según `.terraform-version` |
| Make | Versión disponible en el sistema |
| AWS CLI | v2, sólo para identidad/read-only cuando se autorice |
| Docker | No requerido para este dry-run |

Verifica el toolchain:

```bash
python3.11 --version
terraform --version
aws --version
```

### Clonar un ref revisado

No fijes una rama de coaching como fuente operativa. Usa el commit o ref indicado
en el cambio aprobado:

```bash
git clone https://github.com/cesar-guzman/scanalyze-deployment-platform.git
cd scanalyze-deployment-platform
git checkout <reviewed-ref>
```

### Instalar dependencias locales

```bash
make bootstrap-local
```

Si aparece `BLOCKED_TOOLING`, corrige las versiones antes de continuar.

## Fase de preparación

### Paso 1: crear el manifest real fuera de Git

El manifest resuelto puede contener account IDs, ARNs, backend bindings y otros
valores específicos del deployment. Nunca debe crearse bajo el checkout ni
subirse a Git.

Cuando una verificación read-only requiera AWS, usa exclusivamente el perfil y
la región aprobados para non-production:

```bash
export AWS_PROFILE=<approved-nonprod-profile>
export AWS_REGION=<approved-region>
aws sts get-caller-identity
```

Después genera el archivo en una ubicación privada fuera del repositorio:

```bash
mkdir -p "$HOME/.config/scanalyze/manifests"
chmod 700 "$HOME/.config/scanalyze/manifests"

# El registry/bootstrap aprobado debe haber exportado ambos valores exactos.
: "${SCANALYZE_DEPLOYMENT_ID:?falta deployment_id del registry aprobado}"
: "${SCANALYZE_GITHUB_ENVIRONMENT:?falta Environment protegido del deployment}"

./scripts/deployment/generate-dev-manifest.sh mi-nonprod \
  --deployment-id "$SCANALYZE_DEPLOYMENT_ID" \
  --github-environment "$SCANALYZE_GITHUB_ENVIRONMENT" \
  --output "$HOME/.config/scanalyze/manifests/mi-nonprod.yaml"

chmod 600 "$HOME/.config/scanalyze/manifests/mi-nonprod.yaml"
export SCANALYZE_MANIFEST="$HOME/.config/scanalyze/manifests/mi-nonprod.yaml"
```

El generador no crea identidades: falla si no recibe el `deployment_id`
preasignado o el nombre operativo del GitHub Environment. Registra ese nombre en
`github.environment`, campo admitido por el schema; no agrega un campo superior
`github_environment`. El control externo descrito en
`docs/operations/github-governance.md` sigue siendo responsable de comprobar que
el Environment existe, es exclusivo, está protegido y coincide con el registry.

Confirma que `$SCANALYZE_MANIFEST` no esté dentro del repositorio antes de
continuar.

### Paso 2: validar el manifest sin imprimirlo

```bash
python scripts/deployment/validate-manifest.py "$SCANALYZE_MANIFEST"
```

El validador puede mostrar identificadores de resumen. No copies el manifest, el
output completo ni valores reales a commits, issues, chats o evidencia pública.

### Paso 3: ejecutar gates locales sin AWS

Abre una shell nueva sin credenciales AWS para los gates reproducibles:

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE
unset AWS_WEB_IDENTITY_TOKEN_FILE

make repro-check
make security-check
make provider-check
python scripts/deployment/validate-layer-dag.py deployment/layers.yaml
```

`provider-check` usa `terraform init -backend=false`; no consulta ni modifica
state remoto.

### Paso 4: ejecutar solamente el dry-run del orquestador

```bash
mkdir -p ../scanalyze-plans

./scripts/deployment/scanalyze-deploy.sh plan-all \
  --manifest "$SCANALYZE_MANIFEST" \
  --plan-dir ../scanalyze-plans \
  --dry-run
```

No exportes `SCANALYZE_ALLOW_LIVE`. No uses `--no-dry-run`, `--approve` ni
`apply-all`. Los mocks locales pueden ayudar a validar interfaces, pero nunca son
inputs autorizados para un apply.

### Paso 5: crear una solicitud Git-safe

La solicitud declarativa puede incluir:

- `deployment_id` o reference ID no sensible;
- ambiente lógico non-production;
- release digest inmutable;
- alcance de capas;
- requester y change-ticket;
- selectores y aprobación no sensibles.

No puede incluir:

- el manifest real o contenido copiado de él;
- account IDs o ARNs reales;
- credenciales o tokens;
- tfvars, backend config, outputs, plans o state;
- documentos, PII o datos del cliente.

Valida la solicitud contra `schemas/deployment-request.schema.json` antes de
subirla. Usa un nombre explícito bajo el directorio GitOps que el equipo haya
aprobado; nunca agregues el manifest real.

```bash
git status --short
git add <git-safe-deployment-request>
git commit -m "feat(release): request nonprod deployment"
git push origin <feature-branch>
```

No uses `git add .`.

### Paso 6: revisar el Pull Request y el workflow

El PR debe ejecutar validación de schemas, DAG, seguridad, provider y estructura
del workflow. En esta fase `nonprod-release.yml` sólo demuestra la orquestación
dry-run y debe rechazar cualquier solicitud live.

La protección de `main` debe requerir únicamente los contextos estáticos
declarados en `governance/github-policy.json`. Los jobs dinámicos
`Service matrix evidence / <service>` no son checks requeridos; su resultado se
consolida en `Microservices validation gate`. Una ejecución manual valida los
siete servicios antes de producir ese mismo gate, aunque `service` siga
limitando cuáles imágenes se publican. Si GitHub espera un nombre diagnóstico
como check requerido, hay drift de branch protection: no esperes ni omitas
controles, ejecuta el procedimiento de
`docs/operations/github-governance.md`.

Para ejecutar el dry-run manual selecciona por separado:

- `logical_environment`: `sandbox`, `dev` o `staging` del request Git-safe;
- `github_environment`: Environment protegido y exclusivo del deployment.

Ese GitHub Environment debe declarar `DEPLOYMENT_ID`, `LOGICAL_ENVIRONMENT` y
`AWS_REGION` con valores que coincidan exactamente. El workflow falla cerrado
si falta un binding o si se intenta reutilizar el Environment de otro cliente.
En este dry-run la comparación es sólo una verificación de consistencia: no
demuestra el scope de `vars` ni que el Environment tenga reviewers o política de
ramas. Antes de habilitar OIDC/live, un control externo debe auditar el
Environment contra el registry aprobado y confirmar que esos nombres no existen
como variables de organización o repositorio.

Una ejecución verde significa **Locally validated**, no **Live validated** y no
autoriza producción.

## Detenciones obligatorias

Detén el proceso si ocurre cualquiera de estas condiciones:

- el manifest real está dentro del checkout o aparece en `git status`;
- aparece un `.tfstate`, `.tfplan`, `.env`, tfvars real o backend generado;
- el DAG, schema, security check o provider check falla;
- el workflow solicita OIDC o credenciales durante un dry-run;
- el GitHub Environment no está vinculado al deployment, ambiente lógico y región;
- se intenta publicar artefactos o escribir en AWS;
- se propone producción sin evidencia live non-production aprobada.

## Siguiente hito

El siguiente hito, en un cambio separado, será una primera ejecución live
non-production con:

- manifest real fuera de Git;
- OIDC y roles terminales revisados;
- backend y locking aprobados;
- saved plans revisados;
- contratos SSM completos;
- evidencia sanitizada;
- rollback ensayado.

Producción permanece **NO-GO**.
