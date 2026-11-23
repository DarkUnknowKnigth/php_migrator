use crate::models::{
    DecisionBucket, DependencyInfo, DependencySource, FrameworkKind, MigrationFinding, ModuleSlice,
    PhpVersion, ProjectAnalysis, SecurityFinding, Severity,
};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Calcula un orden recomendado de migración para los módulos lógicos detectados.
///
/// Prioriza módulos sin dependencias pendientes entre sí y con menor puntaje de riesgo,
/// rompiendo ciclos de forma determinista por menor riesgo, menor cantidad de archivos e ID.
pub fn recommended_migration_order(modules: &[ModuleSlice]) -> Vec<&ModuleSlice> {
    if modules.is_empty() {
        return Vec::new();
    }

    let known_ids: HashSet<&str> = modules.iter().map(|m| m.id.as_str()).collect();
    let mut completed: HashSet<&str> = HashSet::with_capacity(modules.len());
    let mut remaining: Vec<usize> = (0..modules.len()).collect();
    let mut ordered = Vec::with_capacity(modules.len());

    while !remaining.is_empty() {
        let best_pos = remaining
            .iter()
            .enumerate()
            .min_by_key(|&(_, &idx)| {
                let m = &modules[idx];
                let unresolved_deps = m
                    .depends_on_modules
                    .iter()
                    .filter(|dep| {
                        let dep_str = dep.as_str();
                        dep_str != m.id
                            && known_ids.contains(dep_str)
                            && !completed.contains(dep_str)
                    })
                    .count();
                (
                    unresolved_deps,
                    m.risk_score,
                    m.red_count,
                    m.yellow_count,
                    m.files.len(),
                    m.id.as_str(),
                )
            })
            .map(|(pos, _)| pos);

        if let Some(pos) = best_pos {
            let idx = remaining.remove(pos);
            let module = &modules[idx];
            completed.insert(module.id.as_str());
            ordered.push(module);
        } else {
            break;
        }
    }

    ordered
}

/// Genera un informe técnico completo en español y formato Markdown del análisis del proyecto.
pub fn render_markdown_report(
    analysis: &ProjectAnalysis,
    graph: &crate::graph::LogicGraphReport,
) -> String {
    let mut out = String::with_capacity(8192);

    let _ = writeln!(
        out,
        "# Informe Técnico de Migración PHP ({} → {})\n",
        analysis.detected_php_version, analysis.target_php_version
    );

    append_project_summary_section(&mut out, analysis);
    append_dependencies_section(&mut out, &analysis.dependencies);
    append_security_radar_section(&mut out, &analysis.security_findings);
    append_modules_section(&mut out, &analysis.modules, graph);
    append_migration_findings_section(&mut out, analysis);

    if matches!(analysis.framework, FrameworkKind::Laravel { .. }) {
        append_laravel_playbook_section(&mut out, &analysis.framework);
    }

    out
}

/// Genera una representación ultracondensada (`analysis-compact.toon`) orientada a
/// minimizar el consumo de tokens al compartir el diagnóstico del proyecto con un LLM.
pub fn render_compact_toon_report(
    analysis: &ProjectAnalysis,
    graph: &crate::graph::LogicGraphReport,
) -> String {
    let mut out = String::with_capacity(2048);

    let green = analysis
        .migration_findings
        .iter()
        .filter(|f| f.bucket == DecisionBucket::GreenAutoFix)
        .count();
    let yellow = analysis
        .migration_findings
        .iter()
        .filter(|f| f.bucket == DecisionBucket::YellowNeedsDecision)
        .count();
    let red = analysis
        .migration_findings
        .iter()
        .filter(|f| f.bucket == DecisionBucket::RedBlocker)
        .count();

    let crit = analysis
        .security_findings
        .iter()
        .filter(|s| s.severity == Severity::Critical)
        .count();
    let high = analysis
        .security_findings
        .iter()
        .filter(|s| s.severity == Severity::High)
        .count();

    let _ = writeln!(
        out,
        "META|{}|PHP {}->{}|{}|files:{}/{}/{}|lines:{}|findings(V/A/R):{}/{}/{}|sec(C/H):{}/{}",
        analysis.root_path.display(),
        analysis.detected_php_version,
        analysis.target_php_version,
        analysis.framework,
        analysis.php_files_count,
        analysis.mixed_html_files_count,
        analysis.total_files,
        analysis.total_lines,
        green,
        yellow,
        red,
        crit,
        high
    );

    let incompat_deps: Vec<&DependencyInfo> = analysis
        .dependencies
        .iter()
        .filter(|d| d.target_compatible == Some(false))
        .collect();
    if !incompat_deps.is_empty() {
        let _ = writeln!(out, "INCOMPAT_DEPS[{}]:", incompat_deps.len());
        for d in incompat_deps {
            let _ = writeln!(
                out,
                "  {}|{}|{}",
                d.name,
                d.detected_version.as_deref().unwrap_or("-"),
                d.notes
            );
        }
    }

    let sec_top: Vec<&SecurityFinding> = analysis
        .security_findings
        .iter()
        .filter(|s| matches!(s.severity, Severity::Critical | Severity::High))
        .collect();
    if !sec_top.is_empty() {
        let _ = writeln!(out, "SECURITY_CRIT_HIGH[{}]:", sec_top.len());
        for s in sec_top.iter().take(25) {
            let _ = writeln!(
                out,
                "  {}|{}|{}:{}",
                s.severity,
                s.category,
                s.file.display(),
                s.line
            );
        }
    }

    let ordered = recommended_migration_order(&analysis.modules);
    if !ordered.is_empty() {
        let order_str: Vec<&str> = ordered.iter().map(|m| m.id.as_str()).collect();
        let _ = writeln!(
            out,
            "MODULES[{}]|order:{}|edges:{}",
            ordered.len(),
            order_str.join("->"),
            graph.edges.len()
        );
        for m in ordered {
            let _ = writeln!(
                out,
                "  {}|f:{}|db:{}|dyn:{}|VAR:{}/{}/{}|{}",
                m.id,
                m.files.len(),
                m.db_ops_count,
                m.dynamic_includes_count,
                m.green_count,
                m.yellow_count,
                m.red_count,
                m.risk_level
            );
        }
    }

    let mut grouped: BTreeMap<(&str, PhpVersion, DecisionBucket), (usize, String)> =
        BTreeMap::new();
    for f in &analysis.migration_findings {
        let key = (f.rule_id.as_str(), f.target_step, f.bucket);
        grouped
            .entry(key)
            .and_modify(|(cnt, _)| *cnt += 1)
            .or_insert_with(|| (1, format!("{}:{}", f.file.display(), f.span.start_line)));
    }
    if !grouped.is_empty() {
        let _ = writeln!(out, "RULES_SUMMARY[{}]:", grouped.len());
        for ((rule_id, step, bucket), (cnt, sample)) in grouped {
            let tag = match bucket {
                DecisionBucket::GreenAutoFix => "V",
                DecisionBucket::YellowNeedsDecision => "A",
                DecisionBucket::RedBlocker => "R",
            };
            let _ = writeln!(
                out,
                "  {}|PHP{}|{}|x{}|ex:{}",
                rule_id, step, tag, cnt, sample
            );
        }
    }

    out
}

/// Escribe los artefactos de análisis (`analysis-report.md`, `logic-map.md`, `analysis.json`
/// y la vista condensada `analysis-compact.toon`) dentro de `output_dir` y devuelve las 3 rutas principales.
pub fn write_analysis_artifacts(
    output_dir: &Path,
    analysis: &ProjectAnalysis,
    graph: &crate::graph::LogicGraphReport,
) -> Result<(PathBuf, PathBuf, PathBuf)> {
    std::fs::create_dir_all(output_dir).with_context(|| {
        format!(
            "No se pudo crear el directorio de artefactos '{}'",
            output_dir.display()
        )
    })?;

    let report_path = output_dir.join("analysis-report.md");
    let logic_map_path = output_dir.join("logic-map.md");
    let json_path = output_dir.join("analysis.json");
    let compact_path = output_dir.join("analysis-compact.toon");

    let report_md = render_markdown_report(analysis, graph);
    std::fs::write(&report_path, report_md).with_context(|| {
        format!(
            "No se pudo escribir el reporte Markdown en '{}'",
            report_path.display()
        )
    })?;

    let mermaid_md = crate::graph::export_mermaid_markdown(graph);
    std::fs::write(&logic_map_path, mermaid_md).with_context(|| {
        format!(
            "No se pudo escribir el mapa lógico Mermaid en '{}'",
            logic_map_path.display()
        )
    })?;

    let analysis_json = serde_json::to_string_pretty(analysis)
        .context("No se pudo serializar ProjectAnalysis a JSON")?;
    std::fs::write(&json_path, analysis_json).with_context(|| {
        format!(
            "No se pudo escribir el análisis JSON en '{}'",
            json_path.display()
        )
    })?;

    let compact_toon = render_compact_toon_report(analysis, graph);
    std::fs::write(&compact_path, compact_toon).with_context(|| {
        format!(
            "No se pudo escribir el resumen compacto en '{}'",
            compact_path.display()
        )
    })?;

    Ok((report_path, logic_map_path, json_path))
}

/// Genera una guía de pruebas manuales post-migración cuando el código se migra
/// sin conectarse ni ejecutar consultas sobre la base de datos.
pub fn write_post_migration_test_guide(
    output_dir: &Path,
    analysis: &ProjectAnalysis,
    applied_diffs: &[crate::patcher::FilePatchDiff],
    git_branch: Option<(&str, &str)>,
) -> Result<PathBuf> {
    std::fs::create_dir_all(output_dir).with_context(|| {
        format!(
            "No se pudo crear el directorio de guía post-migración '{}'",
            output_dir.display()
        )
    })?;

    let guide_path = output_dir.join("post-migration-test-guide.md");
    let mut out = String::with_capacity(4096);

    let total_patches: usize = applied_diffs.iter().map(|d| d.applied_count).sum();
    let pending_yellow = analysis
        .migration_findings
        .iter()
        .filter(|f| {
            f.bucket == DecisionBucket::YellowNeedsDecision
                && f.status == crate::models::ResolutionStatus::Pending
        })
        .count();
    let pending_red = analysis
        .migration_findings
        .iter()
        .filter(|f| {
            f.bucket == DecisionBucket::RedBlocker
                && f.status == crate::models::ResolutionStatus::Pending
        })
        .count();

    let _ = writeln!(
        out,
        "# Guía de Pruebas Post-Migración (PHP {} → {})\n",
        analysis.detected_php_version, analysis.target_php_version
    );
    let _ = writeln!(
        out,
        "> **Modo sin conexión a BD:** Esta migración modificó únicamente sintaxis/compatibilidad en código PHP. **No se ejecutaron consultas SQL ni se abrieron conexiones a la base de datos.** Las consultas y la lógica de negocio SQL permanecen intactas.\n"
    );

    let _ = writeln!(out, "## 1. Resumen de Cambios Aplicados\n");
    let _ = writeln!(out, "- **Proyecto:** `{}`", analysis.root_path.display());
    let _ = writeln!(out, "- **Archivos modificados:** {}", applied_diffs.len());
    let _ = writeln!(out, "- **Parches aplicados en código:** {}", total_patches);
    let _ = writeln!(
        out,
        "- **Respaldos originales:** `{}`",
        analysis.root_path.join(".php-migrator/backups").display()
    );
    let _ = writeln!(
        out,
        "- **Hallazgos aún pendientes:** Amarillo: {}, Rojo: {}\n",
        pending_yellow, pending_red
    );

    if !applied_diffs.is_empty() {
        let _ = writeln!(out, "| Archivo modificado | Parches | Respaldo |");
        let _ = writeln!(out, "| --- | ---: | --- |");
        for diff in applied_diffs {
            let backup_disp = diff
                .backup_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".to_string());
            let _ = writeln!(
                out,
                "| `{}` | {} | `{}` |",
                escape_md_cell(&diff.file.display().to_string()),
                diff.applied_count,
                escape_md_cell(&backup_disp)
            );
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "## 2. Puntos de Conexión y Extensiones de BD Intactas\n");
    let db_extensions: Vec<&DependencyInfo> = analysis
        .dependencies
        .iter()
        .filter(|d| {
            d.source == DependencySource::PhpExtension
                && matches!(
                    d.name.as_str(),
                    "ext-oci8" | "ext-mysql" | "ext-mysqli" | "ext-pdo"
                )
        })
        .collect();

    if db_extensions.is_empty() {
        let _ = writeln!(
            out,
            "- No se detectaron extensiones de BD específicas que requieran configuración adicional."
        );
    } else {
        for ext in db_extensions {
            let _ = writeln!(out, "- **`{}`:** {}", ext.name, ext.notes);
        }
    }

    let db_conn_findings: Vec<&MigrationFinding> = analysis
        .migration_findings
        .iter()
        .filter(|f| matches!(f.rule_id.as_str(), "PHP84-PECL-EXTENSION" | "PHP80-MYSQL-EXT"))
        .collect();
    if !db_conn_findings.is_empty() {
        let _ = writeln!(out, "\n**Ubicaciones donde se detectó apertura/uso de conexión BD:**");
        for f in db_conn_findings.iter().take(25) {
            let _ = writeln!(
                out,
                "- `{}:{}` (`{}`)",
                f.file.display(),
                f.span.start_line,
                escape_inline_code(&crate::ai::redact_secrets(&f.original_code))
            );
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## 3. Checklist para Pruebas Manuales del Usuario\n");
    let _ = writeln!(
        out,
        "1. [ ] **Validación de sintaxis offline (`php -l`):** Ejecuta `php -l` sobre los archivos modificados con el binario de PHP {} (esto valida sintaxis sin ejecutar consultas).",
        analysis.target_php_version
    );
    let _ = writeln!(
        out,
        "2. [ ] **Extensiones activas en PHP {}:** Verifica con `php -m` que estén cargadas las extensiones requeridas (por ejemplo `oci8` + Oracle Instant Client vía PECL si el sistema conecta a Oracle).",
        analysis.target_php_version
    );
    let _ = writeln!(
        out,
        "3. [ ] **Confirmar entorno TEST antes de abrir rutas:** Revisa los archivos de conexión (ej. `includes/sesiones.php` / configuración de entorno) para asegurar que apunten al usuario/esquema `TEST` y no a producción."
    );
    let _ = writeln!(
        out,
        "4. [ ] **Revisar hallazgos Amarillos/Rojos pendientes:** Consulta `analysis-report.md` para atender funciones eliminadas (`each()`, etc.), parámetros `null` en funciones string o comparaciones `== 0` en lógica crítica."
    );
    let _ = writeln!(
        out,
        "5. [ ] **Pruebas funcionales en navegador:** Prueba primero pantallas/peticiones de **solo lectura (`GET`)** sobre tus entrypoints principales y después flujos con escritura en el entorno `TEST`.\n"
    );

    let entrypoints: Vec<String> = analysis
        .modules
        .iter()
        .flat_map(|m| m.entrypoints.iter())
        .take(15)
        .map(|p| format!("`{}`", p.display()))
        .collect();
    if !entrypoints.is_empty() {
        let _ = writeln!(
            out,
            "**Muestra de entrypoints detectados para iniciar pruebas:** {}\n",
            entrypoints.join(", ")
        );
    }

    if let Some((original_branch, migration_branch)) = git_branch {
        let _ = writeln!(out, "## 4. Flujo Git (Rama Aislada y Merge)\n");
        let _ = writeln!(
            out,
            "Las modificaciones y pruebas se aislaron en la rama **`{migration_branch}`** (creada desde **`{original_branch}`**).\n"
        );
        let _ = writeln!(out, "- **Inspeccionar cambios aplicados:**");
        let _ = writeln!(out, "  ```bash");
        let _ = writeln!(out, "  git status");
        let _ = writeln!(out, "  git diff {original_branch}..{migration_branch}");
        let _ = writeln!(out, "  ```\n");
        let _ = writeln!(
            out,
            "- **Si estás conforme tras tus pruebas y quieres integrar a `{original_branch}`:**"
        );
        let _ = writeln!(out, "  ```bash");
        let _ = writeln!(out, "  git add -A");
        let _ = writeln!(
            out,
            "  git commit -m \"chore(php): migrar módulos a PHP {}\"",
            analysis.target_php_version
        );
        let _ = writeln!(out, "  git checkout {original_branch}");
        let _ = writeln!(out, "  git merge {migration_branch}");
        let _ = writeln!(out, "  ```\n");
        let _ = writeln!(
            out,
            "- **Si deseas volver a `{original_branch}` sin conservar la prueba:**"
        );
        let _ = writeln!(out, "  ```bash");
        let _ = writeln!(out, "  git checkout {original_branch}");
        let _ = writeln!(out, "  ```");
    }

    std::fs::write(&guide_path, out).with_context(|| {
        format!(
            "No se pudo escribir la guía post-migración en '{}'",
            guide_path.display()
        )
    })?;

    Ok(guide_path)
}

fn append_project_summary_section(out: &mut String, analysis: &ProjectAnalysis) {
    let green_total = analysis
        .migration_findings
        .iter()
        .filter(|f| f.bucket == DecisionBucket::GreenAutoFix)
        .count();
    let yellow_total = analysis
        .migration_findings
        .iter()
        .filter(|f| f.bucket == DecisionBucket::YellowNeedsDecision)
        .count();
    let red_total = analysis
        .migration_findings
        .iter()
        .filter(|f| f.bucket == DecisionBucket::RedBlocker)
        .count();

    let crit_sec = analysis
        .security_findings
        .iter()
        .filter(|s| s.severity == Severity::Critical)
        .count();
    let high_sec = analysis
        .security_findings
        .iter()
        .filter(|s| s.severity == Severity::High)
        .count();
    let med_sec = analysis
        .security_findings
        .iter()
        .filter(|s| s.severity == Severity::Medium)
        .count();
    let low_sec = analysis
        .security_findings
        .iter()
        .filter(|s| s.severity == Severity::Low)
        .count();

    let _ = writeln!(out, "## 1. Ficha Técnica del Proyecto\n");
    let _ = writeln!(out, "| Propiedad | Valor |");
    let _ = writeln!(out, "| --- | --- |");
    let _ = writeln!(
        out,
        "| Ruta del proyecto | `{}` |",
        escape_md_cell(&analysis.root_path.display().to_string())
    );
    let _ = writeln!(
        out,
        "| Versión PHP detectada | **PHP {}** |",
        analysis.detected_php_version
    );
    let _ = writeln!(
        out,
        "| Versión PHP destino | **PHP {}** |",
        analysis.target_php_version
    );
    let _ = writeln!(out, "| Framework / Stack | {} |", analysis.framework);
    let _ = writeln!(out, "| Archivos totales | {} |", analysis.total_files);
    let _ = writeln!(out, "| Archivos PHP | {} |", analysis.php_files_count);
    let _ = writeln!(
        out,
        "| Archivos mixtos HTML+PHP | {} |",
        analysis.mixed_html_files_count
    );
    let _ = writeln!(out, "| Líneas totales analizadas | {} |", analysis.total_lines);
    let _ = writeln!(
        out,
        "| Módulos lógicos identificados | {} |",
        analysis.modules.len()
    );
    let _ = writeln!(
        out,
        "| Hallazgos de migración | {} (Verde: {}, Amarillo: {}, Rojo: {}) |",
        analysis.migration_findings.len(),
        green_total,
        yellow_total,
        red_total
    );
    let _ = writeln!(
        out,
        "| Alertas Radar Seguridad | {} (Crítica: {}, Alta: {}, Media: {}, Baja: {}) |\n",
        analysis.security_findings.len(),
        crit_sec,
        high_sec,
        med_sec,
        low_sec
    );

    let _ = writeln!(out, "### Evidencias de versión PHP detectada\n");
    if analysis.version_evidence.is_empty() {
        let _ = writeln!(
            out,
            "- Sin marcadores explícitos; versión inferida por análisis heurístico.\n"
        );
    } else {
        for ev in &analysis.version_evidence {
            let _ = writeln!(out, "- {ev}");
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "### Carpetas estructurales (`includes/` y `vendor/`)\n");
    let _ = write!(out, "- **Carpetas `includes` / equivalentes:** ");
    if analysis.include_dirs.is_empty() {
        let _ = writeln!(out, "Ninguna detectada.");
    } else {
        let joined: Vec<String> = analysis
            .include_dirs
            .iter()
            .map(|p| format!("`{}`", p.display()))
            .collect();
        let _ = writeln!(out, "{}", joined.join(", "));
    }

    let _ = write!(out, "- **Carpetas `vendor` / dependencias externas:** ");
    if analysis.vendor_dirs.is_empty() {
        let _ = writeln!(out, "Ninguna detectada.\n");
    } else {
        let joined: Vec<String> = analysis
            .vendor_dirs
            .iter()
            .map(|p| format!("`{}`", p.display()))
            .collect();
        let _ = writeln!(out, "{}\n", joined.join(", "));
    }
}

fn append_dependencies_section(out: &mut String, dependencies: &[DependencyInfo]) {
    let _ = writeln!(out, "## 2. Dependencias Detectadas\n");

    if dependencies.is_empty() {
        let _ = writeln!(
            out,
            "No se detectaron dependencias en `composer.json`, carpetas locales embebidas ni extensiones PHP explícitas.\n"
        );
        return;
    }

    let composer_deps: Vec<&DependencyInfo> = dependencies
        .iter()
        .filter(|d| {
            matches!(
                d.source,
                DependencySource::Composer | DependencySource::ComposerDev
            )
        })
        .collect();
    let bundled_deps: Vec<&DependencyInfo> = dependencies
        .iter()
        .filter(|d| d.source == DependencySource::BundledFolder)
        .collect();
    let extension_deps: Vec<&DependencyInfo> = dependencies
        .iter()
        .filter(|d| d.source == DependencySource::PhpExtension)
        .collect();

    render_dependency_group(out, "### Dependencias Composer", &composer_deps);
    render_dependency_group(out, "### Carpetas locales / librerías embebidas", &bundled_deps);
    render_dependency_group(out, "### Extensiones PHP requeridas o usadas", &extension_deps);
}

fn render_dependency_group(out: &mut String, heading: &str, deps: &[&DependencyInfo]) {
    let _ = writeln!(out, "{heading}\n");
    if deps.is_empty() {
        let _ = writeln!(out, "_Ninguna detectada en esta categoría._\n");
        return;
    }

    let _ = writeln!(
        out,
        "| Nombre | Origen | Versión detectada | Ruta | Compatible con destino | Notas |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- |");

    for dep in deps {
        let version = dep.detected_version.as_deref().unwrap_or("-");
        let path = dep.path.as_deref().unwrap_or("-");
        let compat = match dep.target_compatible {
            Some(true) => "Sí",
            Some(false) => "**No**",
            None => "Por verificar",
        };
        let notes = if dep.notes.is_empty() {
            "-"
        } else {
            dep.notes.as_str()
        };

        let _ = writeln!(
            out,
            "| `{}` | {} | `{}` | `{}` | {} | {} |",
            escape_md_cell(&dep.name),
            escape_md_cell(&dep.source.to_string()),
            escape_md_cell(version),
            escape_md_cell(path),
            compat,
            escape_md_cell(notes),
        );
    }
    let _ = writeln!(out);
}

fn append_security_radar_section(out: &mut String, findings: &[SecurityFinding]) {
    let _ = writeln!(out, "## 3. Radar de Seguridad PHP2Shell / RCE\n");

    if findings.is_empty() {
        let _ = writeln!(
            out,
            "No se detectaron alertas de seguridad PHP2Shell, RCE o patrones de alto riesgo en el análisis estático.\n"
        );
        return;
    }

    let mut sorted: Vec<&SecurityFinding> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    let _ = writeln!(
        out,
        "| Severidad | Categoría | Archivo:Línea | Descripción | Remediación |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- |");

    for f in &sorted {
        let location = format!("{}:{}", f.file.display(), f.line);
        let _ = writeln!(
            out,
            "| **{}** | {} | `{}` | {} | {} |",
            f.severity,
            escape_md_cell(&f.category.to_string()),
            escape_md_cell(&location),
            escape_md_cell(&f.description),
            escape_md_cell(&f.remediation),
        );
    }
    let _ = writeln!(out);

    let high_or_crit: Vec<&&SecurityFinding> = sorted
        .iter()
        .filter(|f| f.severity >= Severity::High && !f.snippet.trim().is_empty())
        .collect();
    if !high_or_crit.is_empty() {
        let _ = writeln!(out, "### Fragmentos relevantes de alertas Críticas / Altas\n");
        for f in high_or_crit {
            let _ = writeln!(
                out,
                "- **[{}] {}** (`{}:{}:{}`):",
                f.severity,
                f.id,
                f.file.display(),
                f.line,
                f.column
            );
            let _ = writeln!(out, "  ```php\n  {}\n  ```", f.snippet.trim());
        }
        let _ = writeln!(out);
    }
}

fn append_modules_section(
    out: &mut String,
    modules: &[ModuleSlice],
    graph: &crate::graph::LogicGraphReport,
) {
    let _ = writeln!(out, "## 4. Módulos Lógicos Detectados y Orden de Migración\n");

    if modules.is_empty() {
        let _ = writeln!(
            out,
            "No se segmentaron módulos lógicos en el proyecto.\n"
        );
    } else {
        let _ = writeln!(
            out,
            "| ID | Módulo | Archivos | Entrypoints | Dependencias | Ops BD | Includes Dinámicos | Riesgo | Verde / Amarillo / Rojo |"
        );
        let _ = writeln!(
            out,
            "| --- | --- | ---: | ---: | --- | ---: | ---: | --- | --- |"
        );

        for m in modules {
            let deps = if m.depends_on_modules.is_empty() {
                "-".to_string()
            } else {
                m.depends_on_modules.join(", ")
            };
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} | {} | {} | {} | {} ({}) | {}/{}/{} |",
                escape_md_cell(&m.id),
                escape_md_cell(&m.name),
                m.files.len(),
                m.entrypoints.len(),
                escape_md_cell(&deps),
                m.db_ops_count,
                m.dynamic_includes_count,
                m.risk_level,
                m.risk_score,
                m.green_count,
                m.yellow_count,
                m.red_count,
            );
        }
        let _ = writeln!(out);

        let ordered = recommended_migration_order(modules);
        let _ = writeln!(out, "### Orden recomendado de migración\n");
        for (idx, m) in ordered.iter().enumerate() {
            let deps_note = if m.depends_on_modules.is_empty() {
                "sin dependencias previas".to_string()
            } else {
                format!("depende de: {}", m.depends_on_modules.join(", "))
            };
            let entry_note = if m.entrypoints.is_empty() {
                "sin entrypoints HTTP directos".to_string()
            } else {
                let sample: Vec<String> = m
                    .entrypoints
                    .iter()
                    .take(3)
                    .map(|p| format!("`{}`", p.display()))
                    .collect();
                format!("entrypoints: {}", sample.join(", "))
            };
            let _ = writeln!(
                out,
                "{}. **{}** (`{}`) — Riesgo **{}** (score {}), {} archivos, V/A/R: {}/{}/{} ({}; {}).",
                idx + 1,
                m.name,
                m.id,
                m.risk_level,
                m.risk_score,
                m.files.len(),
                m.green_count,
                m.yellow_count,
                m.red_count,
                deps_note,
                entry_note
            );
        }
        let _ = writeln!(out);
    }

    let mermaid_md = crate::graph::export_mermaid_markdown(graph);
    if !mermaid_md.trim().is_empty() {
        let _ = writeln!(
            out,
            "<details>\n<summary>Ver mapa de lógica y dependencias (Mermaid — guardado también en <code>logic-map.md</code>)</summary>\n\n{}\n\n</details>\n",
            mermaid_md.trim()
        );
    }
}

fn append_migration_findings_section(out: &mut String, analysis: &ProjectAnalysis) {
    let _ = writeln!(
        out,
        "## 5. Desglose de Hallazgos de Migración por Salto de Versión\n"
    );

    if analysis.migration_findings.is_empty() {
        let _ = writeln!(
            out,
            "No se detectaron incompatibilidades de migración hacia PHP {}.\n",
            analysis.target_php_version
        );
        return;
    }

    let mut hops = PhpVersion::all_hops_between(
        analysis.detected_php_version,
        analysis.target_php_version,
    );
    for finding in &analysis.migration_findings {
        if !hops.contains(&finding.target_step) {
            hops.push(finding.target_step);
        }
    }
    hops.sort();
    hops.dedup();

    let buckets = [
        DecisionBucket::GreenAutoFix,
        DecisionBucket::YellowNeedsDecision,
        DecisionBucket::RedBlocker,
    ];

    for step in hops {
        let step_findings: Vec<&MigrationFinding> = analysis
            .migration_findings
            .iter()
            .filter(|f| f.target_step == step)
            .collect();

        let g = step_findings
            .iter()
            .filter(|f| f.bucket == DecisionBucket::GreenAutoFix)
            .count();
        let y = step_findings
            .iter()
            .filter(|f| f.bucket == DecisionBucket::YellowNeedsDecision)
            .count();
        let r = step_findings
            .iter()
            .filter(|f| f.bucket == DecisionBucket::RedBlocker)
            .count();

        let _ = writeln!(
            out,
            "### Salto a PHP {} (Total: {} | Verde: {}, Amarillo: {}, Rojo: {})\n",
            step,
            step_findings.len(),
            g,
            y,
            r
        );

        if step_findings.is_empty() {
            let _ = writeln!(
                out,
                "_Sin incompatibilidades detectadas para este salto de versión._\n"
            );
            continue;
        }

        let mut by_bucket: BTreeMap<DecisionBucket, Vec<&MigrationFinding>> = BTreeMap::new();
        for f in step_findings {
            by_bucket.entry(f.bucket).or_default().push(f);
        }

        for bucket in buckets {
            if let Some(items) = by_bucket.get(&bucket) {
                let _ = writeln!(out, "#### {} ({})\n", bucket, items.len());
                for f in items {
                    let _ = writeln!(
                        out,
                        "- **[`{}`]** `{}:{}:{}` — *{}* | Estado: **{}** (ID: `{}`)",
                        f.rule_id,
                        f.file.display(),
                        f.span.start_line,
                        f.span.start_col,
                        f.category,
                        f.status,
                        f.id
                    );
                    if !f.original_code.trim().is_empty() {
                        let _ = writeln!(
                            out,
                            "  - **Código original:** `{}`",
                            escape_inline_code(&crate::ai::redact_secrets(&f.original_code))
                        );
                    }
                    if let Some(replacement) = &f.suggested_replacement {
                        let _ = writeln!(
                            out,
                            "  - **Sugerencia determinista:** `{}`",
                            escape_inline_code(replacement)
                        );
                    }
                    let _ = writeln!(out, "  - **Explicación:** {}", f.explanation);
                    if !f.logic_impact.trim().is_empty() {
                        let _ = writeln!(out, "  - **Impacto en lógica:** {}", f.logic_impact);
                    }
                }
                let _ = writeln!(out);
            }
        }
    }
}

fn append_laravel_playbook_section(out: &mut String, framework: &FrameworkKind) {
    let _ = writeln!(out, "## 6. Guía de Actualización de Laravel\n");
    if let FrameworkKind::Laravel { version } = framework {
        let detected = version.as_deref().unwrap_or("versión no determinada");
        let _ = writeln!(out, "**Versión detectada en el proyecto:** `{detected}`\n");
    }

    let playbooks = crate::frameworks::laravel::laravel_playbooks();
    if playbooks.is_empty() {
        let _ = writeln!(out, "_No hay playbooks de Laravel disponibles._\n");
        return;
    }

    for pb in playbooks.iter() {
        let _ = writeln!(
            out,
            "### {} ({} → {}, PHP mínimo requerido: {})\n",
            pb.title, pb.from_version, pb.to_version, pb.min_php
        );
        let _ = writeln!(out, "- **Impacto:** {}", pb.impact);
        let _ = writeln!(out, "- **Guía oficial:** {}\n", pb.doc_url);
        if !pb.checklist.is_empty() {
            let _ = writeln!(out, "**Pasos recomendados:**");
            for (idx, step) in pb.checklist.iter().enumerate() {
                let _ = writeln!(out, "{}. {step}", idx + 1);
            }
            let _ = writeln!(out);
        }
        if !pb.code_patterns.is_empty() {
            let _ = writeln!(out, "**Patrones de cambio frecuentes:**");
            for (before, after) in pb.code_patterns.iter() {
                let _ = writeln!(
                    out,
                    "- `{}` → `{}`",
                    escape_inline_code(before),
                    escape_inline_code(after)
                );
            }
            let _ = writeln!(out);
        }
    }
}

fn escape_md_cell(input: &str) -> String {
    input
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
        .trim()
        .to_string()
}

fn escape_inline_code(input: &str) -> String {
    input
        .replace('`', "'")
        .replace(['\r', '\n'], " ")
        .trim()
        .to_string()
}
