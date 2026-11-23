# `php-migrator`

**Herramienta Open Source en Rust creada para combatir la desactualización de sistemas PHP vulnerables a ataques PHP2Shell / RCE**, permitiendo analizar, comprender la lógica y migrar proyectos desde versiones legadas e inseguras (PHP 7.4–8.x) hacia **PHP 8.5** de forma modular, segura y sin romper la lógica del negocio.

---

## ¿Por qué nace `php-migrator`?

Miles de sitios web, sistemas internos y aplicaciones legacy permanecen atrapados en versiones obsoletas e inseguras de PHP (como 7.4 o inferiores) por miedo a romper la lógica en producción. Esa desactualización expone los servidores a amenazas crecientes como **PHP2Shell**, ejecución remota de código (**RCE**), deserialización insegura y webshells.

`php-migrator` ataca el problema de raíz combinando **análisis estático determinista ultrarrápido (0% IA)**, mapeo previo de dependencias, parcheo quirúrgico que preserva HTML/CSS/JS intactos, asistencia opcional con **IA BYOK** (*Bring Your Own Key*) optimizada para consumir el mínimo de tokens, y verificación opcional en Docker.

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

## 🤝 Buscamos Colaboradores

Este proyecto busca activamente **colaboradores de la comunidad** para convertir `php-migrator` en una herramienta robusta y referente contra la deuda técnica y vulnerabilidades en sistemas PHP desactualizados.

Si quieres sumar fuerzas, puedes contribuir en áreas clave como:
- **Seguridad y Radar PHP2Shell / RCE:** nuevas firmas de detección (webshells, LFI/RFI, `unserialize`, inyección de comandos y SQLi) y reglas de mitigación automática.
- **Motor de Reglas PHP (AST):** ampliar reglas deterministas entre versiones (`7.x → 8.5`), detección de casos borde y soporte de extensiones.
- **Adaptadores de Frameworks:** fortalecer los *playbooks* de **Laravel** y sumar adaptadores dedicados para **WordPress**, **CodeIgniter** y **Symfony**.
- **Pruebas en entornos reales y Sandbox Docker:** perfiles adicionales para Docker (Apache/Nginx/PHP-FPM) y pruebas sobre proyectos legacy reales.
- **Optimización de IA / Tokens y CLI:** mejorar la condensación de contexto, soporte de nuevos proveedores locales/cloud y experiencia de usuario en consola.

### Cómo contribuir

1. Haz un **Fork** de este repositorio (`https://github.com/DarkUnknowKnigth/php_migrator`).
2. Crea una rama para tu mejora (`git checkout -b feat/mi-mejora`).
3. Ejecuta las pruebas con `cargo test` para verificar que todo pase sin regresiones.
4. Abre un **Pull Request** describiendo el problema que resuelves o la nueva regla/adaptador agregado.

---

## Licencia

Este proyecto es software libre publicado bajo la licencia **GNU General Public License v3.0 o posterior (`GPL-3.0-or-later`)** — consulta el archivo [LICENSE](LICENSE) para conocer todos los términos.

Cualquier persona o entidad que modifique, mejore o distribuya obras derivadas basadas en `php-migrator` debe licenciar y distribuir el código fuente correspondiente bajo los mismos términos de la **GNU GPLv3** (*copyleft* fuerte), garantizando que el software y sus mejoras permanezcan libres y abiertas para siempre.
