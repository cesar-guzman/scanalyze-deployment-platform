# Guía Provisional de Validación Manual Non-Production

> [!WARNING]
> Esta guía histórica fue reemplazada por
> [`colleague-deployment-guide.md`](colleague-deployment-guide.md) y ADR-017.
> El flujo local ya no autoriza `terraform apply`, publicación de imágenes ni
> escrituras en SSM/ECR/ECS.

## Estado

El intento de usar `apply-all` desde localhost demostró que los planes de capas
downstream se construían con mocks antes de que existieran los outputs reales de
las capas upstream. Esos planes no son artefactos válidos para un apply.

Por lo tanto:

- GitHub Actions es el orquestador live objetivo;
- `deployment/layers.yaml` define el orden canónico;
- contratos SSM versionados serán el bus autoritativo entre capas;
- el manifest real permanece cifrado fuera de Git;
- la terminal local termina en validación y dry-run;
- producción permanece **NO-GO**.

## Ruta autorizada actual

Sigue la [guía de preparación GitOps](colleague-deployment-guide.md) para:

1. crear el manifest real fuera del checkout;
2. ejecutar validaciones offline;
3. validar el DAG y los schemas;
4. ejecutar sólo el dry-run local;
5. crear una solicitud de despliegue Git-safe;
6. abrir un Pull Request.

No exportes `SCANALYZE_ALLOW_LIVE` y no ejecutes `apply-all`, `apply-layer`,
`publish-images` ni `deploy-services` desde esta guía.

La primera ejecución live non-production requiere un cambio separado, OIDC y
roles revisados, protected Environment, backend/locking aprobado, saved plans,
contratos reales y autorización explícita.
