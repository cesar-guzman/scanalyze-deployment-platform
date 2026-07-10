# Guía de Despliegue Manual Non-Prod (Para el Ejecutor)

> **Contexto:** Esta es la guía rápida para ejecutar el primer despliegue manual en AWS (Non-Prod) desde tu máquina local. Durante este proceso, estarás compartiendo pantalla o reportando los resultados a tu *coach*.

---

## 🛑 Requisitos Previos (Haz esto antes de empezar)

### A. Versiones de herramientas requeridas

| Herramienta | Versión requerida | Cómo instalar |
|---|---|---|
| Python | **3.11.x** | `brew install python@3.11` |
| Terraform | **1.14.6** | `brew install tfenv && brew unlink terraform && brew link tfenv && tfenv install 1.14.6 && tfenv use 1.14.6` |
| Docker | Última estable | [Docker Desktop](https://www.docker.com/products/docker-desktop/) |
| Make | Cualquiera | Ya viene con macOS (Xcode CLI tools) |
| AWS CLI | v2 | `brew install awscli` |

> ⚠️ **Si tienes versiones diferentes** (ej. Python 3.9), el bootstrap fallará con `BLOCKED_TOOLING`. Instala las versiones correctas antes de continuar.

Verifica tus versiones:
```bash
python3.11 --version   # debe decir 3.11.x
terraform --version     # debe decir v1.14.6
docker --version
aws --version
```

### B. Clonar el repositorio

```bash
git clone https://github.com/cesar-guzman/scanalyze-deployment-platform.git
cd scanalyze-deployment-platform
git checkout docs/manual-deployment-coaching
```

### C. Instalar dependencias locales

```bash
make bootstrap-local
```
> Si el bootstrap muestra `BLOCKED_TOOLING`, revisa la tabla de versiones del Paso A.

### D. Autenticarte en AWS

**Opción 1 — Si tu organización usa AWS SSO:**
```bash
aws sso login --profile TU_PERFIL
export AWS_PROFILE=TU_PERFIL
```

**Opción 2 — Si usas credenciales temporales (Access Key + Session Token):**
Copia las credenciales desde la consola de AWS y expórtalas como variables de entorno. **Nunca compartas estas credenciales por chat o correo.**
```bash
export AWS_ACCESS_KEY_ID="tu-access-key"
export AWS_SECRET_ACCESS_KEY="tu-secret-key"
export AWS_SESSION_TOKEN="tu-session-token-completo"
```

Verifica que estés conectado:
```bash
aws sts get-caller-identity
```
Debes ver tu Account ID y ARN. **Anota tu Account ID** — lo necesitarás en el siguiente paso.

---

## 🚀 Fase de Ejecución

Sigue estos pasos en orden. Después de cada paso, **pausa y confirma con tu coach** antes de avanzar al siguiente.

### Paso 1: Generar tu manifiesto de despliegue

El repositorio incluye un script que detecta tu cuenta de AWS y genera un manifiesto válido de forma automática.

Ejecuta este comando (puedes cambiar `mi-nonprod` por tu nombre):
```bash
./scripts/deployment/generate-dev-manifest.sh mi-nonprod
```

> **Check con tu coach:** Revisa que el output del comando haya mostrado tu Account ID correcto y que el archivo `mi-nonprod.generated.yaml` se haya creado exitosamente.

A partir de este momento, usaremos el archivo generado (`examples/deployments/mi-nonprod.generated.yaml`) para todos los comandos.

### Paso 2: Preparar el Entorno
Activa el entorno virtual de Python y habilita la bandera de seguridad.
```bash
# 1. Activar el entorno virtual
source .venv/bin/activate

# 2. Desactivar el candado de seguridad (Dry-Run)
export SCANALYZE_ALLOW_LIVE=1

# 3. Crear carpetas temporales para guardar evidencia
mkdir -p ../scanalyze-plans ../scanalyze-evidence
```

### Paso 3: Validación Preflight (Prueba de conexión)
Valida que el manifiesto es correcto y que tus credenciales de AWS coinciden con la cuenta declarada.
```bash
./scripts/deployment/scanalyze-deploy.sh account-preflight \
  --manifest ./examples/deployments/mi-nonprod.generated.yaml \
  --no-dry-run
```
> **Check con tu coach:** Debe terminar con `PASS` sin errores de account mismatch.

### Paso 4: Terraform Plan (Simulación de cambios)
Calcula todo lo que se va a crear en AWS. **No hace cambios reales todavía.**
```bash
./scripts/deployment/scanalyze-deploy.sh plan-all \
  --manifest ./examples/deployments/mi-nonprod.generated.yaml \
  --plan-dir ../scanalyze-plans \
  --no-dry-run
```
> **Check con tu coach:** Revisen juntos el resumen del plan (ej. *Plan: 45 to add, 0 to change, 0 to destroy*).

> **Check con tu coach:** Revisen juntos el resumen del plan (ej. *Plan: 45 to add, 0 to change, 0 to destroy*).

### Paso 5: Push a GitHub (GitOps)
¡Has validado exitosamente de manera local que tu contrato de infraestructura y tu manifiesto son correctos! En este repositorio, **no ejecutamos `terraform apply` desde las computadoras locales**. 

El paso final es subir tus cambios y dejar que el pipeline de GitHub Actions se encargue de orquestar el despliegue real en AWS, garantizando trazabilidad y seguridad.

```bash
git add examples/deployments/mi-nonprod.generated.yaml
git commit -m "feat: deploy mi-nonprod environment"
git push origin tu-rama
```
> **Check con tu coach:** Abran el Pull Request en GitHub y revisen juntos la ejecución del pipeline `nonprod-release.yml`.

---
🎉 **¡Felicidades!** Has completado el ciclo de preparación y validación local de un entorno bajo las mejores prácticas de la plataforma.
