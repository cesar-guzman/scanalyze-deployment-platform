# GUG-95 Prerequisite — Frontend Source Consolidation

## Resumen

Scanalyze no podía iniciar GUG-95 de forma reproducible porque el monorepo no
contenía el SPA y el frontend identificado vivía en un repositorio separado con
un checkout sucio. ADR-027 define `frontend/scanalyze-frontend-ui` como la fuente
canónica portable y registra el último commit remoto disponible sólo en cache
local. No hubo consulta ni cambio AWS.

La importación usa una lista positiva de código, pruebas y configuración de
toolchain. Excluye archivos de ambiente, `config.json`, automatización de
despliegue, build output, evidencia operativa y todo contenido modificado o no
trackeado. La procedencia se valida con un esquema cerrado.

El SPA ahora consume exclusivamente `frontend-config.v2`. Debe coincidir en
customer, deployment, account, region, issuer, PKCE, token use, scopes y digest
de policy. La configuración nunca establece autoridad backend; si falta o es
ambigua la aplicación no inicia. La sesión debe contener un access token vigente
o la llamada API se bloquea antes de salir del navegador.

## Evidencia

- **Implemented:** candidato local con importación, contrato, CI, pruebas y docs.
- **Locally validated:** sólo los comandos nombrados en el PR.
- **CI validated:** pendiente del commit exacto del PR.
- **Live validated:** no.
- **AWS/CodeCommit live:** no ejecutado.
- **Production:** **NO-GO**.

GUG-95 funcional sólo empieza después del merge revisado y verificación de
`main`, en su branch/worktree independiente. Este paquete no publica assets,
habilita usuarios, despliega ni retira el repositorio legado.
