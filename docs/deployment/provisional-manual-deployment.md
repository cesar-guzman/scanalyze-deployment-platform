# Guía Provisional: Despliegue Manual Non-Production

> [!WARNING]
> **USO PROVISIONAL ÚNICAMENTE.** Esta guía bypasses the CI/CD pipeline (GitHub Actions) y el mecanismo de OIDC. Se asume que estás ejecutando los comandos con tus credenciales AWS locales activas. Nunca usar este flujo para producción.

## Requisitos previos

1. **Autenticación en AWS:** Debes tener tus credenciales locales activas y apuntando a la cuenta non-prod (ej: `aws sso login`).
2. **Dependencias:** Python 3.11+, Terraform, Docker y las herramientas de línea de comandos estándar.
3. **Manifiesto:** Un archivo `manifest.yaml` válido para tu entorno non-prod.

---

## 1. Preparar el entorno

Activa el entorno virtual y autoriza la ejecución "live" (non-dry-run) exportando la variable de seguridad.

```bash
source .venv/bin/activate

# DESACTIVA EL DRY-RUN GLOBAL
export SCANALYZE_ALLOW_LIVE=1
```

Crea directorios temporales fuera del repositorio para los planes de Terraform y la evidencia.

```bash
mkdir -p ../scanalyze-plans ../scanalyze-evidence
```

---

## 2. Validar credenciales y cuenta

Asegúrate de que estás en la cuenta correcta y que el manifiesto es válido.

```bash
./scripts/deployment/scanalyze-deploy.sh account-preflight \
  --manifest ./examples/deployments/synthetic-nonprod.yaml \
  --no-dry-run
```

---

## 3. Planificar toda la infraestructura

Ejecuta el plan de todas las capas de Terraform en orden (global, network, platform, data-foundation, etc.). 

```bash
./scripts/deployment/scanalyze-deploy.sh plan-all \
  --manifest ./examples/deployments/synthetic-nonprod.yaml \
  --plan-dir ../scanalyze-plans \
  --no-dry-run
```

> [!IMPORTANT]
> Revisa los planes generados en la terminal o en la carpeta `../scanalyze-plans`. Si todo está correcto, procede a aplicar.

---

## 4. Aplicar la infraestructura (Infra Layer)

Aplica los planes generados anteriormente. Esto creará la VPC, bases de datos, ECR, ECS clusters y KMS keys.

```bash
./scripts/deployment/scanalyze-deploy.sh apply-all \
  --manifest ./examples/deployments/synthetic-nonprod.yaml \
  --plan-dir ../scanalyze-plans \
  --no-dry-run \
  --approve
```

---

## 5. Compilar y publicar imágenes de Docker

Una vez que el registro ECR existe, compila y empuja las imágenes de los microservicios.

```bash
./scripts/deployment/scanalyze-deploy.sh publish-images \
  --manifest ./examples/deployments/synthetic-nonprod.yaml \
  --no-dry-run
```
*(Nota: Si usas la base image `CI_BASE_IMAGE`, asegúrate de tenerla exportada en tu shell).*

---

## 6. Desplegar los servicios (App Layer)

Esto tomará los digests de las imágenes recién publicadas (registrados en SSM) y aplicará la capa `services` de Terraform para actualizar ECS.

```bash
./scripts/deployment/scanalyze-deploy.sh deploy-services \
  --manifest ./examples/deployments/synthetic-nonprod.yaml \
  --plan-dir ../scanalyze-plans \
  --no-dry-run \
  --approve
```

---

## 7. Validar el entorno (Smoke Test)

Ejecuta las pruebas de humo para asegurar que los microservicios levantan correctamente y tienen conectividad.

```bash
./scripts/deployment/scanalyze-deploy.sh smoke-e2e \
  --manifest ./examples/deployments/synthetic-nonprod.yaml \
  --no-dry-run
```

Si este paso es exitoso, el despliegue manual non-prod está completo.
