# `php-migrator`

CLI en Rust para analizar, mapear la lógica y migrar proyectos PHP (7.4–8.x hacia 8.5) por módulos de forma determinista primero, preservando HTML/CSS/JS intactos, con soporte opcional de IA BYOK (*Bring Your Own Key*) optimizado para gasto mínimo de tokens y verificación opcional en Docker.

---

## Características principales

- **Análisis 100% determinista (0% IA):**
  - Detección automática de versión PHP, framework (`Vanilla PHP`, `Laravel`, `WordPress`, `CodeIgniter`, `Symfony`), dependencias (`composer.json`, `composer.lock`, librerías embebidas en carpetas locales y extensiones PHP como `ext-oci8`).
  - **Radar de Seguridad PHP2Shell / RCE:** detecta `eval()`, `shell_exec()`, `unserialize()` inseguros, LFI/RFI e interpolación SQL.
  - **Grafo de lógica y módulos:** mapea `include`/`require`, entrypoints y operaciones de BD, exportando diagramas Mermaid (`logic-map.md`) y orden recomendado de migración.
  - **Reporte ultracondensado (`analysis-compact.toon`):** resume el diagnóstico completo en pocos cientos de tokens junto a `analysis-report.md` y `analysis.json`.
- **Migración modular y segura:**
  - Clasifica cada hallazgo en **Verde** (auto-fix determinista por rango exacto de bytes con respaldos en `.php-migrator/backups/`), **Amarillo** (decisión/IA) y **Rojo** (bloqueante).
  - **Aislamiento en rama Git:** crea una rama dedicada (`migration/php-<destino>`) antes de editar código y genera comandos listos para `git diff` / `git merge`.
  - **Modo sin conexión a BD (`--no-db`):** migra únicamente el código PHP sin ejecutar consultas SQL ni abrir conexiones a base de datos, generando `post-migration-test-guide.md`.
  - **Piloto automático con IA (`--auto-ai`):** aplica fixes Verdes, resuelve Amarillos/Rojos con IA usando caché persistente (`ai-cache.json`), lotes por archivo y contexto condensado/sanitizado (`redact_secrets`), y valida cada cambio con `php -l` aplicando rollback automático ante errores de sintaxis.
- **Catálogo BYOK de proveedores IA:**
  - Soporta `gemini`, `anthropic`, `openai`, `deepseek`, `openrouter`, `groq`, `xai`, `ollama` (local sin token) y `custom`.
  - Incluye guía embebida en consola para obtener tokens (`docs/COMO_OBTENER_TOKENS_IA.md`).

---

## Comandos principales

```bash
# 1. Análisis de solo lectura (sin IA ni modificación de archivos)
php-migrator analyze <RUTA_PROYECTO> --target 8.5

# 2. Migración interactiva en rama Git aislada y sin tocar la BD
php-migrator migrate <RUTA_PROYECTO> --target 8.5 --no-db

# 3. Modo piloto automático con IA por módulo + validación offline php -l
php-migrator migrate <RUTA_PROYECTO> --target 8.5 --module lib --auto-ai --no-db --create-branch

# 4. Consultar catálogo de proveedores IA y guía paso a paso para obtener tokens
php-migrator ai-catalog --help-tokens
php-migrator ai-catalog --configure

# 5. Verificación dual opcional en Docker (PHP origen vs destino)
php-migrator sandbox <RUTA_PROYECTO> --source 7.4 --target 8.5
```

---

## Licencia

Este proyecto es software libre publicado bajo la licencia **GNU General Public License v3.0 o posterior (`GPL-3.0-or-later`)** — consulta el archivo [LICENSE](LICENSE) para conocer todos los términos.

Cualquier persona o entidad que modifique, mejore o distribuya obras derivadas basadas en `php-migrator` debe licenciar y distribuir el código fuente correspondiente bajo los mismos términos de la **GNU GPLv3** (*copyleft* fuerte), garantizando que el software y sus mejoras permanezcan libres y abiertas para siempre.
