# Guía de Despliegue Manual Non-Prod (Para el Ejecutor)

> **Contexto:** Esta es la guía rápida para ejecutar el primer despliegue manual en AWS (Non-Prod) desde tu máquina local. Durante este proceso, estarás compartiendo pantalla o reportando los resultados a tu *coach*.

---

## 🛑 Requisitos Previos (Haz esto antes de empezar)

1. **Clonar el repositorio:** (Asegúrate de estar en la rama `docs/manual-deployment-coaching`).
   ```bash
   git clone https://github.com/cesar-guzman/scanalyze-deployment-platform.git
   cd scanalyze-deployment-platform
   git checkout docs/manual-deployment-coaching
   ```
2. **Instalar dependencias locales:**
   ```bash
   make bootstrap-local
   ```
3. **Autenticarte en AWS:** Inicia sesión en la cuenta Non-Prod de AWS con tus credenciales.
   ```bash
   aws sso login
   # Verifica que estés conectado:
   aws sts get-caller-identity
   ```

---

## 🚀 Fase de Ejecución

Sigue estos pasos en orden. Después de cada paso, **pausa y confirma con tu coach** antes de avanzar al siguiente.

### Paso 1: Preparar el Entorno
Activa el entorno virtual de Python y habilita la bandera de seguridad que permite modificar infraestructura real.
```bash
# 1. Activar el entorno virtual
source .venv/bin/activate

# 2. Desactivar el candado de seguridad (Dry-Run)
export SCANALYZE_ALLOW_LIVE=1

# 3. Crear carpetas temporales para guardar evidencia
mkdir -p ../scanalyze-plans ../scanalyze-evidence
```

### Paso 2: Validación Preflight (Prueba de conexión)
Este comando valida que el manifiesto es correcto y que tienes los permisos necesarios en AWS.
```bash
./scripts/deployment/scanalyze-deploy.sh account-preflight \
  --manifest ./examples/deployments/synthetic-nonprod.yaml \
  --no-dry-run
```
> **Check con tu coach:** ¿El comando terminó exitosamente sin errores de permisos?

### Paso 3: Terraform Plan (Simulación de cambios)
Calcula todo lo que se va a crear en AWS (Redes, Bases de datos, Clusters). **No hace cambios reales todavía.**
```bash
./scripts/deployment/scanalyze-deploy.sh plan-all \
  --manifest ./examples/deployments/synthetic-nonprod.yaml \
  --plan-dir ../scanalyze-plans \
  --no-dry-run
```
> **Check con tu coach:** Revisen juntos el resumen del plan (ej. *Plan: 45 to add, 0 to change, 0 to destroy*).

### Paso 4: Terraform Apply (Creación de Infraestructura)
Aplica los planes generados en el paso anterior. Esto creará la infraestructura base en AWS.
```bash
./scripts/deployment/scanalyze-deploy.sh apply-all \
  --manifest ./examples/deployments/synthetic-nonprod.yaml \
  --plan-dir ../scanalyze-plans \
  --no-dry-run
```
> **Check con tu coach:** Este paso puede tardar varios minutos (bases de datos, clusters). Avisa cuando termine exitosamente.

### Paso 5: Construcción y Publicación Docker
Construye las imágenes de los 7 microservicios de Scanalyze y las sube al ECR (Elastic Container Registry) de AWS recién creado.
```bash
./scripts/deployment/scanalyze-deploy.sh publish-images \
  --manifest ./examples/deployments/synthetic-nonprod.yaml \
  --no-dry-run \
  --approve
```
> ⚠️ **Nota:** El flag `--approve` es obligatorio aquí porque subir imágenes es una operación destructiva/mutante.

### Paso 6: Sincronización de Configuración (SSM)
Sube los parámetros de configuración y secretos al AWS Systems Manager Parameter Store.
```bash
./scripts/deployment/scanalyze-deploy.sh sync-ssm \
  --manifest ./examples/deployments/synthetic-nonprod.yaml \
  --no-dry-run
```

---
🎉 **¡Felicidades!** Si llegaste hasta aquí, toda la infraestructura, las imágenes de los microservicios y la configuración están desplegadas en AWS.
