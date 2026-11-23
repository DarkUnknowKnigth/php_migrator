use crate::ai::{
    ask_ai_batch_for_file, ask_ai_for_finding, build_context_snippet,
    build_merged_file_batch_context, builtin_catalog, condense_context_for_finding,
    estimate_tokens, find_provider, load_saved_config, resolve_api_key_from_env,
    save_config_metadata, AiConfig, AiPatternCache, AiProviderInfo, TokenOptimizationStats,
};
use crate::models::{
    DbEngine, DbIsolationMode, DecisionBucket, MigrationFinding, ModuleSlice, PhpVersion,
    ProjectAnalysis, ResolutionStatus, SecurityFinding, Severity,
};
use crate::patcher::{
    apply_findings, apply_green_fixes_for_module, preview_patch, FilePatchDiff, PatchInstruction,
};
use crate::sandbox::{
    check_docker_available, run_dual_verification, write_sandbox_files, SandboxConfig,
    SandboxReport,
};
use anyhow::{anyhow, Context, Result};
use console::style;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use std::path::{Path, PathBuf};

/// Contexto de rama Git dedicada para aislar cambios y pruebas de migración.
#[derive(Debug, Clone)]
pub struct GitBranchContext {
    pub original_branch: String,
    pub migration_branch: String,
    pub branch_active: bool,
}

/// Ejecuta el asistente interactivo (o automático con `--non-interactive` / `--auto-ai`) de migración por módulos.
#[allow(clippy::too_many_arguments)]
pub async fn run_migrate_wizard(
    path: PathBuf,
    target: Option<PhpVersion>,
    module_filter: Option<String>,
    auto_green: bool,
    non_interactive: bool,
    no_db: bool,
    output: Option<PathBuf>,
    auto_ai: bool,
    create_branch: bool,
    branch_name: Option<String>,
) -> Result<()> {
    // Paso 1: Escaneo inicial y selección de versión destino
    let mut scan = match target {
        Some(target_php) => {
            println!(
                "{} Escaneando proyecto en {} hacia PHP {}...",
                style("==>").cyan().bold(),
                style(path.display()).white().bold(),
                style(target_php).green().bold()
            );
            crate::scanner::scan_project(&path, target_php)
                .context("Error al escanear el proyecto")?
        }
        None => {
            println!(
                "{} Ejecutando escaneo inicial en {}...",
                style("==>").cyan().bold(),
                style(path.display()).white().bold()
            );
            let initial_scan = crate::scanner::scan_project(&path, PhpVersion::Php85)
                .context("Error al ejecutar el escaneo inicial del proyecto")?;
            print_initial_discovery_overview(&initial_scan.analysis);

            if non_interactive {
                initial_scan
            } else {
                let chosen_target =
                    prompt_target_version(initial_scan.analysis.detected_php_version)?;
                if chosen_target == PhpVersion::Php85 {
                    initial_scan
                } else {
                    println!(
                        "{} Recalculando hallazgos para PHP {}...",
                        style("==>").cyan().bold(),
                        style(chosen_target).green().bold()
                    );
                    crate::scanner::scan_project(&path, chosen_target)
                        .context("Error al escanear hacia la versión destino seleccionada")?
                }
            }
        }
    };

    // Paso 2: Guardar reporte y mapa lógico en `<path>/.php-migrator/` o `--output`
    let artifacts_dir = output.unwrap_or_else(|| path.join(".php-migrator"));
    let (report_path, map_path, json_path) = crate::reporter::write_analysis_artifacts(
        &artifacts_dir,
        &scan.analysis,
        &scan.logic_graph,
    )?;
    println!(
        "{} Artefactos iniciales guardados en {}:",
        style("✔").green().bold(),
        style(artifacts_dir.display()).cyan()
    );
    println!("  - {}", report_path.display());
    println!("  - {}", map_path.display());
    println!("  - {}", json_path.display());

    // Paso 3: Destacar alertas críticas PHP2Shell / RCE al inicio
    let critical_or_high = highlight_critical_security_alerts(&scan.analysis.security_findings);
    if critical_or_high > 0 && !non_interactive {
        let proceed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(
                "Se detectaron alertas de seguridad Críticas/Altas (PHP2Shell / RCE). ¿Deseas continuar con la migración?",
            )
            .default(true)
            .interact()
            .context("Error al leer confirmación de seguridad")?;
        if !proceed {
            println!(
                "{} Migración pausada por revisión de seguridad. Revisa el informe en '{}'.",
                style("!").yellow().bold(),
                report_path.display()
            );
            return Ok(());
        }
    }

    if scan.analysis.modules.is_empty() {
        println!(
            "{} No se detectaron módulos lógicos con código PHP migrable.",
            style("ℹ").cyan().bold()
        );
        return Ok(());
    }

    // Paso 4: Preparación de rama Git aislada y selección de modo de migración
    let git_ctx = prepare_git_migration_branch(
        &scan.analysis.root_path,
        scan.analysis.target_php_version,
        branch_name.as_deref(),
        create_branch,
        non_interactive,
    )?;

    let mut effective_auto_ai = auto_ai;
    let mut effective_auto_green = auto_green;
    let mut effective_only_green = false;

    if !non_interactive && !effective_auto_ai && !effective_auto_green {
        let mode_options = [
            "Interactivo paso a paso (aplicar Verdes y decidir cada Amarillo/Rojo)",
            "Piloto Automático con IA (--auto-ai: aplica Verdes + corrige Amarillos/Rojos con IA + valida sintaxis php -l con auto-rollback)",
            "Solo correcciones automáticas seguras (Verde)",
        ];
        let mode_choice = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Selecciona el modo de ejecución para la migración de código")
            .items(&mode_options)
            .default(0)
            .interact()
            .context("Error al seleccionar modo de migración")?;

        match mode_choice {
            1 => {
                effective_auto_ai = true;
                effective_auto_green = true;
            }
            2 => {
                effective_auto_green = true;
                effective_only_green = true;
            }
            _ => {}
        }
    }

    let mut cached_ai_config: Option<AiConfig> = None;
    let mut ai_cache = AiPatternCache::load_or_new(&artifacts_dir.join("ai-cache.json"));
    if effective_auto_ai {
        let _ = ensure_ai_config_interactive(&mut cached_ai_config)?;
    }

    let mut all_applied_diffs: Vec<FilePatchDiff> = Vec::new();
    let git_pair = git_ctx
        .as_ref()
        .filter(|g| g.branch_active)
        .map(|g| (g.original_branch.as_str(), g.migration_branch.as_str()));

    if non_interactive || effective_auto_ai {
        let targets: Vec<ModuleSlice> = if let Some(filter) = module_filter.as_deref() {
            match find_module(&scan.analysis.modules, filter) {
                Some(m) => vec![m.clone()],
                None => {
                    return Err(anyhow!(
                        "No se encontró el módulo '{}'. Disponibles: {}",
                        filter,
                        available_module_ids(&scan.analysis.modules)
                    ));
                }
            }
        } else if non_interactive {
            crate::reporter::recommended_migration_order(&scan.analysis.modules)
                .into_iter()
                .cloned()
                .collect()
        } else {
            let selected = select_module_interactive(&scan.analysis.modules, None)?;
            selected.into_iter().collect()
        };

        for module in targets {
            let mut diffs = if effective_auto_ai {
                run_auto_ai_for_module(
                    &mut scan.analysis,
                    &scan.logic_graph,
                    &module,
                    &mut cached_ai_config,
                    &mut ai_cache,
                )
                .await?
            } else {
                process_module_findings(
                    &mut scan.analysis,
                    &scan.logic_graph,
                    &module,
                    effective_auto_green,
                    true,
                    &mut cached_ai_config,
                    &mut ai_cache,
                )
                .await?
            };
            all_applied_diffs.append(&mut diffs);
        }

        let _ = crate::reporter::write_analysis_artifacts(
            &artifacts_dir,
            &scan.analysis,
            &scan.logic_graph,
        )?;
        let guide_path = crate::reporter::write_post_migration_test_guide(
            &artifacts_dir,
            &scan.analysis,
            &all_applied_diffs,
            git_pair,
        )?;
        print_post_migration_user_notice(
            &scan.analysis,
            &all_applied_diffs,
            &report_path,
            &guide_path,
            git_ctx.as_ref(),
        );
        return Ok(());
    }

    // Flujo interactivo por módulo
    let single_module_run = module_filter.is_some();
    let mut pending_filter = module_filter;

    loop {
        let selected_opt = select_module_interactive(
            &scan.analysis.modules,
            pending_filter.as_deref(),
        )?;
        pending_filter = None;

        let Some(selected_module) = selected_opt else {
            break;
        };

        // Paso 5: Resolver hallazgos Verde / Amarillo / Rojo del módulo
        let mut diffs = process_module_findings(
            &mut scan.analysis,
            &scan.logic_graph,
            &selected_module,
            effective_auto_green,
            effective_only_green,
            &mut cached_ai_config,
            &mut ai_cache,
        )
        .await?;
        all_applied_diffs.append(&mut diffs);

        // Persistir estado actualizado de los hallazgos en los artefactos
        let _ = crate::reporter::write_analysis_artifacts(
            &artifacts_dir,
            &scan.analysis,
            &scan.logic_graph,
        )?;

        // Paso 6: Finalización sin BD (por defecto) o verificación dual en Docker
        if !no_db {
            let post_options = [
                "Finalizar sin conectar a BD y generar Guía de Pruebas para el usuario (Recomendado para Oracle / lógica SQL fija)",
                "Lanzar verificación dual en Docker (PHP origen vs PHP destino)",
            ];
            let post_choice = Select::with_theme(&ColorfulTheme::default())
                .with_prompt(format!(
                    "Módulo '{}' finalizado. ¿Cómo deseas validar?",
                    selected_module.name
                ))
                .items(&post_options)
                .default(0)
                .interact()
                .context("Error al consultar modo de validación post-migración")?;

            if post_choice == 1 {
                let default_routes =
                    infer_routes_from_module(&scan.analysis.root_path, &selected_module);
                run_docker_verification_flow(
                    &scan.analysis.root_path,
                    scan.analysis.detected_php_version,
                    scan.analysis.target_php_version,
                    None,
                    "mysql",
                    default_routes,
                    false,
                )
                .await?;
            }
        }

        if single_module_run {
            break;
        }

        let continue_other = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("¿Deseas seleccionar otro módulo lógico para continuar migrando?")
            .default(false)
            .interact()
            .context("Error al consultar continuación con otro módulo")?;
        if !continue_other {
            break;
        }
    }

    let guide_path = crate::reporter::write_post_migration_test_guide(
        &artifacts_dir,
        &scan.analysis,
        &all_applied_diffs,
        git_pair,
    )?;
    print_post_migration_user_notice(
        &scan.analysis,
        &all_applied_diffs,
        &report_path,
        &guide_path,
        git_ctx.as_ref(),
    );
    Ok(())
}

fn print_post_migration_user_notice(
    analysis: &ProjectAnalysis,
    applied_diffs: &[FilePatchDiff],
    report_path: &Path,
    guide_path: &Path,
    git_ctx: Option<&GitBranchContext>,
) {
    let total_patches: usize = applied_diffs.iter().map(|d| d.applied_count).sum();
    println!();
    println!(
        "{}",
        style("══════════════════════════════════════════════════════════════")
            .green()
    );
    println!(
        "{}",
        style("MIGRACIÓN DE CÓDIGO COMPLETADA (SIN CONEXIÓN A BD)")
            .green()
            .bold()
    );
    println!(
        "{}",
        style("══════════════════════════════════════════════════════════════")
            .green()
    );
    println!(
        "  Archivos modificados:  {} ({} parches aplicados)",
        applied_diffs.len(),
        total_patches
    );
    println!("  Consultas SQL / BD:    0 consultas modificadas · 0 conexiones ejecutadas");
    println!(
        "  Respaldos originales:  {}",
        analysis.root_path.join(".php-migrator/backups").display()
    );
    println!("  Reporte actualizado:   {}", report_path.display());
    println!(
        "  Guía de pruebas:       {}",
        style(guide_path.display()).cyan().bold()
    );

    if let Some(git) = git_ctx {
        if git.branch_active {
            println!();
            println!(
                "{}",
                style("Flujo Git (Rama de pruebas aislada):").cyan().bold()
            );
            println!(
                "  Rama activa actual:    {} (creada desde '{}')",
                style(&git.migration_branch).green().bold(),
                git.original_branch
            );
            println!("  Revisar cambios:       git diff {}..{}", git.original_branch, git.migration_branch);
            println!(
                "  Si todo funciona bien: git add -A && git commit -m \"chore(php): migrar a PHP {}\" && git checkout {} && git merge {}",
                analysis.target_php_version, git.original_branch, git.migration_branch
            );
        }
    }

    println!();
    println!("{}", style("Siguientes pasos recomendados para probar manualmente:").yellow().bold());
    println!("  1. Valida sintaxis offline con `php -l` sobre los archivos modificados.");
    println!("  2. Verifica extensiones requeridas en PHP {} (ej. `oci8` si usas Oracle).", analysis.target_php_version);
    println!("  3. Confirma que tu archivo de conexión apunte al entorno TEST y prueba las rutas en navegador.");
    println!();
}

/// Flujo interactivo para seleccionar un proveedor BYOK, modelo, endpoint opcional y API key oculta.
pub fn configure_ai_interactive() -> Result<AiConfig> {
    let catalog = builtin_catalog();
    if catalog.is_empty() {
        return Err(anyhow!("El catálogo de proveedores IA está vacío"));
    }

    let theme = ColorfulTheme::default();
    let provider_labels: Vec<String> = catalog
        .iter()
        .map(|p| {
            let token_hint = if p.requires_token {
                format!("token: {}", p.env_var.unwrap_or("API Key"))
            } else {
                "local / sin token".to_string()
            };
            format!(
                "{} ({}) [{} | {}]",
                p.display_name, p.id, p.protocol, token_hint
            )
        })
        .collect();

    let provider_idx = Select::with_theme(&theme)
        .with_prompt("Selecciona el proveedor de IA (BYOK)")
        .items(&provider_labels)
        .default(0)
        .interact()
        .context("Error al seleccionar proveedor IA")?;
    let provider = &catalog[provider_idx];

    let model = prompt_model_for_provider(provider)?;

    let custom_base_url: String = Input::with_theme(&theme)
        .with_prompt(format!(
            "Endpoint base (Enter para usar '{}')",
            provider.default_base_url
        ))
        .allow_empty(true)
        .interact_text()
        .context("Error al leer endpoint base")?;
    let base_url = if custom_base_url.trim().is_empty() {
        provider.default_base_url.to_string()
    } else {
        custom_base_url.trim().to_string()
    };

    let api_key = prompt_api_key_for_provider(provider)?;

    let config = AiConfig {
        provider_id: provider.id.to_string(),
        model,
        base_url,
        protocol: provider.protocol,
        api_key,
    };

    Ok(config)
}

/// Flujo dedicado del subcomando `sandbox` con confirmación explícita de Docker y selección de BD.
pub async fn run_sandbox_cli(
    path: PathBuf,
    source: PhpVersion,
    target: PhpVersion,
    db_dump: Option<PathBuf>,
    db_engine: String,
    routes: Vec<String>,
    auto_confirm: bool,
) -> Result<()> {
    println!(
        "{} Configurando Sandbox Docker dual: {} → {}",
        style("==>").cyan().bold(),
        style(format!("PHP {source}")).yellow().bold(),
        style(format!("PHP {target}")).green().bold()
    );

    run_docker_verification_flow(
        &path,
        source,
        target,
        db_dump,
        &db_engine,
        routes,
        auto_confirm,
    )
    .await
}

fn print_initial_discovery_overview(analysis: &ProjectAnalysis) {
    println!();
    println!(
        "{}",
        style("── Diagnóstico inicial del proyecto ──────────────────────────").cyan()
    );
    println!(
        "  PHP detectado:  {} (evidencias: {})",
        style(analysis.detected_php_version).yellow().bold(),
        if analysis.version_evidence.is_empty() {
            "heurística por defecto".to_string()
        } else {
            analysis.version_evidence.join(", ")
        }
    );
    println!("  Framework:      {}", analysis.framework);
    println!(
        "  Archivos:       {} totales ({} PHP, {} mixtos HTML+PHP)",
        analysis.total_files, analysis.php_files_count, analysis.mixed_html_files_count
    );
    println!(
        "  Dependencias:   {} detectadas",
        analysis.dependencies.len()
    );
    println!(
        "  Módulos:        {} detectados",
        analysis.modules.len()
    );
    if !analysis.modules.is_empty() {
        for m in crate::reporter::recommended_migration_order(&analysis.modules) {
            println!(
                "    • {} ({}) — {} archivos | Riesgo: {} | V/A/R: {}/{}/{}",
                m.name,
                m.id,
                m.files.len(),
                m.risk_level,
                m.green_count,
                m.yellow_count,
                m.red_count
            );
        }
    }
    println!();
}

fn prompt_target_version(detected: PhpVersion) -> Result<PhpVersion> {
    let mut candidates: Vec<PhpVersion> = PhpVersion::all()
        .iter()
        .copied()
        .filter(|&v| v > detected && v >= PhpVersion::Php82)
        .collect();

    if candidates.is_empty() {
        candidates = PhpVersion::all()
            .iter()
            .copied()
            .filter(|&v| v > detected)
            .collect();
    }
    if candidates.is_empty() {
        candidates.push(PhpVersion::Php85);
    }

    let labels: Vec<String> = candidates
        .iter()
        .map(|v| {
            if *v == PhpVersion::Php85 {
                format!("PHP {v} (Recomendada / última soportada)")
            } else {
                format!("PHP {v}")
            }
        })
        .collect();

    let default_idx = candidates.len().saturating_sub(1);
    let idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("¿A qué versión de PHP deseas migrar el proyecto?")
        .items(&labels)
        .default(default_idx)
        .interact()
        .context("Error al seleccionar la versión PHP destino")?;

    Ok(candidates[idx])
}

fn highlight_critical_security_alerts(findings: &[SecurityFinding]) -> usize {
    let critical_high: Vec<&SecurityFinding> = findings
        .iter()
        .filter(|f| f.severity >= Severity::High)
        .collect();

    if critical_high.is_empty() {
        return 0;
    }

    println!();
    println!(
        "{}",
        style("╔══════════════════════════════════════════════════════════════╗")
            .red()
            .bold()
    );
    println!(
        "{}",
        style("║   ALERTA RADAR PHP2SHELL / RCE — RIESGOS DE ALTA SEVERIDAD   ║")
            .red()
            .bold()
    );
    println!(
        "{}",
        style("╚══════════════════════════════════════════════════════════════╝")
            .red()
            .bold()
    );

    for f in &critical_high {
        println!(
            "  {} [{}] {} ({}:{}:{})",
            style("▲").red().bold(),
            style(f.severity).red().bold(),
            style(f.category).yellow().bold(),
            f.file.display(),
            f.line,
            f.column
        );
        println!("    Descripción: {}", f.description);
        println!("    Remediación: {}", style(&f.remediation).cyan());
    }
    println!();

    critical_high.len()
}

fn find_module<'a>(modules: &'a [ModuleSlice], filter: &str) -> Option<&'a ModuleSlice> {
    modules
        .iter()
        .find(|m| m.id.eq_ignore_ascii_case(filter) || m.name.eq_ignore_ascii_case(filter))
}

fn available_module_ids(modules: &[ModuleSlice]) -> String {
    modules
        .iter()
        .map(|m| m.id.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn select_module_interactive(
    modules: &[ModuleSlice],
    filter: Option<&str>,
) -> Result<Option<ModuleSlice>> {
    if let Some(id_or_name) = filter {
        let found = find_module(modules, id_or_name).ok_or_else(|| {
            anyhow!(
                "No existe ningún módulo con ID o nombre '{}'. Disponibles: {}",
                id_or_name,
                available_module_ids(modules)
            )
        })?;
        return Ok(Some(found.clone()));
    }

    let ordered = crate::reporter::recommended_migration_order(modules);
    let mut items: Vec<String> = ordered
        .iter()
        .enumerate()
        .map(|(idx, m)| {
            format!(
                "{}. [{}] {} — {} archivos | Riesgo: {} | V:{} / A:{} / R:{}",
                idx + 1,
                m.id,
                m.name,
                m.files.len(),
                m.risk_level,
                m.green_count,
                m.yellow_count,
                m.red_count
            )
        })
        .collect();
    items.push("Salir del asistente de migración".to_string());

    let choice = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Selecciona el módulo lógico a migrar (ordenados por menor dependencia y riesgo)")
        .items(&items)
        .default(0)
        .interact()
        .context("Error al seleccionar módulo")?;

    if choice >= ordered.len() {
        Ok(None)
    } else {
        Ok(Some(ordered[choice].clone()))
    }
}

async fn process_module_findings(
    analysis: &mut ProjectAnalysis,
    logic_graph: &crate::graph::LogicGraphReport,
    module: &ModuleSlice,
    auto_green: bool,
    non_interactive: bool,
    cached_ai_config: &mut Option<AiConfig>,
    ai_cache: &mut AiPatternCache,
) -> Result<Vec<FilePatchDiff>> {
    let mut collected_diffs: Vec<FilePatchDiff> = Vec::new();
    let pending_green = count_module_findings(
        &analysis.migration_findings,
        &analysis.root_path,
        module,
        DecisionBucket::GreenAutoFix,
        true,
    );
    let pending_yellow = count_module_findings(
        &analysis.migration_findings,
        &analysis.root_path,
        module,
        DecisionBucket::YellowNeedsDecision,
        true,
    );
    let pending_red = count_module_findings(
        &analysis.migration_findings,
        &analysis.root_path,
        module,
        DecisionBucket::RedBlocker,
        true,
    );

    println!();
    println!(
        "{}",
        style("══════════════════════════════════════════════════════════════")
            .cyan()
    );
    println!(
        "  Módulo: {} ({})",
        style(&module.name).bold(),
        style(&module.id).dim()
    );
    println!(
        "  Archivos: {} | Riesgo: {} (score {}) | DB ops: {} | Includes dinámicos: {}",
        module.files.len(),
        module.risk_level,
        module.risk_score,
        module.db_ops_count,
        module.dynamic_includes_count
    );
    println!(
        "  Conteo del módulo -> {} | {} | {} (pendientes V/A/R: {}/{}/{})",
        style(format!("Verde: {}", module.green_count)).green().bold(),
        style(format!("Amarillo: {}", module.yellow_count))
            .yellow()
            .bold(),
        style(format!("Rojo: {}", module.red_count)).red().bold(),
        pending_green,
        pending_yellow,
        pending_red
    );
    println!(
        "{}",
        style("══════════════════════════════════════════════════════════════")
            .cyan()
    );

    // Parte A: Fixes automáticos seguros (Verde)
    if pending_green > 0 {
        let should_apply_green = if auto_green {
            true
        } else if non_interactive {
            println!(
                "{} Modo no interactivo sin `--auto-green`: omitiendo {} fixes Verdes.",
                style("ℹ").dim(),
                pending_green
            );
            false
        } else {
            Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt(format!(
                    "¿Aplicar {pending_green} correcciones automáticas seguras (Verde) en '{}'?",
                    module.name
                ))
                .default(true)
                .interact()
                .context("Error al confirmar fixes verdes")?
        };

        if should_apply_green {
            let diffs = apply_green_fixes_for_module(
                &analysis.root_path,
                &mut analysis.migration_findings,
                &module.files,
            )
            .with_context(|| {
                format!(
                    "Error al aplicar correcciones automáticas en el módulo '{}'",
                    module.id
                )
            })?;

            if diffs.is_empty() {
                println!(
                    "{} No se requirieron escrituras nuevas para fixes Verdes.",
                    style("ℹ").dim()
                );
            } else {
                println!(
                    "{} Correcciones Verdes aplicadas ({} archivos modificados):",
                    style("✔").green().bold(),
                    diffs.len()
                );
                print_patch_diffs(&diffs);
                collected_diffs.extend(diffs);
            }
        }
    } else {
        println!(
            "{} No hay hallazgos Verdes pendientes en este módulo.",
            style("✔").green()
        );
    }

    if non_interactive {
        return Ok(collected_diffs);
    }

    // Parte B: Hallazgos Amarillo (Decisión/IA) y Rojo (Bloqueante)
    let decision_indices: Vec<usize> = analysis
        .migration_findings
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            f.status == ResolutionStatus::Pending
                && matches!(
                    f.bucket,
                    DecisionBucket::YellowNeedsDecision | DecisionBucket::RedBlocker
                )
                && finding_belongs_to_module(f, &analysis.root_path, module)
        })
        .map(|(idx, _)| idx)
        .collect();

    if decision_indices.is_empty() {
        println!(
            "{} No hay hallazgos Amarillos o Rojos pendientes en este módulo.",
            style("✔").green()
        );
        return Ok(collected_diffs);
    }

    let total_decisions = decision_indices.len();
    for (pos, finding_idx) in decision_indices.into_iter().enumerate() {
        let root_path = analysis.root_path.clone();
        let mut diffs = handle_decision_finding(
            &root_path,
            logic_graph,
            &mut analysis.migration_findings,
            finding_idx,
            pos + 1,
            total_decisions,
            cached_ai_config,
            ai_cache,
        )
        .await?;
        collected_diffs.append(&mut diffs);
    }

    Ok(collected_diffs)
}

#[allow(clippy::too_many_arguments)]
async fn handle_decision_finding(
    root_path: &Path,
    logic_graph: &crate::graph::LogicGraphReport,
    all_findings: &mut [MigrationFinding],
    finding_idx: usize,
    ordinal: usize,
    total: usize,
    cached_ai_config: &mut Option<AiConfig>,
    ai_cache: &mut AiPatternCache,
) -> Result<Vec<FilePatchDiff>> {
    let mut applied_diffs: Vec<FilePatchDiff> = Vec::new();
    println!();
    let finding_snapshot = all_findings[finding_idx].clone();
    let bucket_badge = match finding_snapshot.bucket {
        DecisionBucket::YellowNeedsDecision => style("AMARILLO").yellow().bold(),
        DecisionBucket::RedBlocker => style("ROJO").red().bold(),
        DecisionBucket::GreenAutoFix => style("VERDE").green().bold(),
    };

    println!(
        "{} [{}/{}] {} | Salto PHP {} | Regla `{}` ({})",
        style("▶").cyan().bold(),
        ordinal,
        total,
        bucket_badge,
        finding_snapshot.target_step,
        finding_snapshot.rule_id,
        finding_snapshot.category
    );
    println!(
        "  Ubicación:   {}:{}:{}",
        style(finding_snapshot.file.display()).white().bold(),
        finding_snapshot.span.start_line,
        finding_snapshot.span.start_col
    );
    println!("  Explicación: {}", finding_snapshot.explanation);
    if !finding_snapshot.logic_impact.trim().is_empty() {
        println!(
            "  Impacto:     {}",
            style(&finding_snapshot.logic_impact).yellow()
        );
    }
    if !finding_snapshot.original_code.trim().is_empty() {
        println!(
            "  Original:    {}",
            style(finding_snapshot.original_code.trim()).red()
        );
    }
    if let Some(sug) = &finding_snapshot.suggested_replacement {
        println!("  Sugerencia:  {}", style(sug.trim()).green());
    }

    loop {
        let deterministic_label = if finding_snapshot.suggested_replacement.is_some() {
            "[1] Aplicar sugerencia determinista"
        } else {
            "[1] Aplicar sugerencia determinista (no disponible)"
        };

        let options = [
            deterministic_label,
            "[2] Consultar a la IA (BYOK)",
            "[3] Marcar TODO en reporte",
            "[4] Saltar",
        ];

        let choice = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Elige cómo resolver este hallazgo")
            .items(&options)
            .default(if finding_snapshot.suggested_replacement.is_some() {
                0
            } else {
                1
            })
            .interact()
            .context("Error en menú de decisión de hallazgo")?;

        match choice {
            0 => {
                let Some(replacement) = all_findings[finding_idx].suggested_replacement.clone()
                else {
                    println!(
                        "{} Este hallazgo no cuenta con una sugerencia determinista automática. Usa IA (BYOK) o márcalo como TODO.",
                        style("!").yellow().bold()
                    );
                    continue;
                };

                let full_file_path =
                    resolve_project_file(root_path, &all_findings[finding_idx].file);
                let original_content =
                    std::fs::read_to_string(&full_file_path).with_context(|| {
                        format!(
                            "No se pudo leer '{}' para previsualizar el parche",
                            full_file_path.display()
                        )
                    })?;

                let diff_preview = preview_patch(
                    &original_content,
                    &all_findings[finding_idx],
                    &replacement,
                )
                .context("No se pudo generar la vista previa del parche")?;
                println!("\n{}", style("Vista previa del parche:").bold());
                print_colored_diff(&diff_preview);

                let confirm = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("¿Confirmas aplicar esta sugerencia determinista?")
                    .default(true)
                    .interact()
                    .context("Error al confirmar parche determinista")?;

                if confirm {
                    let instruction = PatchInstruction {
                        finding_id: all_findings[finding_idx].id.clone(),
                        replacement,
                        status: ResolutionStatus::AppliedDeterministic,
                    };
                    let diffs = apply_findings(root_path, all_findings, &[instruction])
                        .context("Falló la aplicación del parche determinista")?;
                    print_patch_diffs(&diffs);
                    applied_diffs.extend(diffs);
                    println!("{} Parche aplicado.", style("✔").green().bold());
                    break;
                }
            }
            1 => {
                let current_finding = all_findings[finding_idx].clone();
                let full_file_path = resolve_project_file(root_path, &current_finding.file);
                let file_content = std::fs::read_to_string(&full_file_path).with_context(|| {
                    format!(
                        "No se pudo leer el archivo '{}' para construir el contexto IA",
                        full_file_path.display()
                    )
                })?;

                let resolution_opt = if let Some(cached_res) = ai_cache.get(&current_finding) {
                    println!(
                        "\n{} Patrón resuelto desde caché local (0 tokens gastados).",
                        style("⚡").cyan().bold()
                    );
                    Some(cached_res)
                } else {
                    let ai_cfg = ensure_ai_config_interactive(cached_ai_config)?;
                    let related_sigs =
                        crate::graph::find_related_signatures(logic_graph, &current_finding.file);
                    let raw_snippet =
                        build_context_snippet(&file_content, &current_finding, &related_sigs);
                    let condensed_snippet =
                        condense_context_for_finding(&file_content, &current_finding, &related_sigs);
                    let raw_toks = estimate_tokens(&raw_snippet);
                    let cond_toks = estimate_tokens(&condensed_snippet);

                    println!();
                    println!(
                        "{} (~{} tokens vs ~{} sin condensar)",
                        style("── Contexto condensado y sanitizado para IA ────────────")
                            .magenta()
                            .bold(),
                        cond_toks,
                        raw_toks
                    );
                    println!("{condensed_snippet}");
                    println!(
                        "{}",
                        style("────────────────────────────────────────────────────────────")
                            .magenta()
                    );

                    let authorize_send = Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt(format!(
                            "¿Autorizas enviar este fragmento condensado (~{cond_toks} tokens) a '{}/{}'?",
                            ai_cfg.provider_id, ai_cfg.model
                        ))
                        .default(true)
                        .interact()
                        .context("Error al confirmar envío a IA")?;

                    if !authorize_send {
                        continue;
                    }

                    println!(
                        "{} Consultando proveedor IA...",
                        style("==>").magenta().bold()
                    );

                    match ask_ai_for_finding(&ai_cfg, &current_finding, &condensed_snippet).await {
                        Ok(res) => {
                            ai_cache.insert(&current_finding, res.clone());
                            let _ = ai_cache.save();
                            Some(res)
                        }
                        Err(err) => {
                            println!(
                                "{} Error al consultar la IA: {err:#}",
                                style("✖").red().bold()
                            );
                            None
                        }
                    }
                };

                if let Some(resolution) = resolution_opt {
                    println!();
                    println!("{}", style("Respuesta de la IA:").green().bold());
                    println!("  Explicación: {}", resolution.explanation);
                    if !resolution.logic_safety_notes.trim().is_empty() {
                        println!(
                            "  Notas de seguridad lógica: {}",
                            style(&resolution.logic_safety_notes).cyan()
                        );
                    }
                    println!("  Código propuesto:");
                    println!("{}", style(&resolution.replacement_code).green());

                    if let Ok(diff_preview) = preview_patch(
                        &file_content,
                        &all_findings[finding_idx],
                        &resolution.replacement_code,
                    ) {
                        println!("\n{}", style("Vista previa del parche IA:").bold());
                        print_colored_diff(&diff_preview);
                    }

                    let accept = Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("¿Aceptas y aplicas el parche propuesto por la IA?")
                        .default(false)
                        .interact()
                        .context("Error al confirmar parche IA")?;

                    if accept {
                        let instruction = PatchInstruction {
                            finding_id: all_findings[finding_idx].id.clone(),
                            replacement: resolution.replacement_code.clone(),
                            status: ResolutionStatus::AppliedAi,
                        };
                        let diffs = apply_findings(root_path, all_findings, &[instruction])
                            .context("Error al aplicar el parche propuesto por IA")?;
                        print_patch_diffs(&diffs);
                        applied_diffs.extend(diffs);
                        all_findings[finding_idx].suggested_replacement =
                            Some(resolution.replacement_code);
                        println!(
                            "{} Parche asistido por IA aplicado.",
                            style("✔").green().bold()
                        );
                        break;
                    }
                }
            }
            2 => {
                all_findings[finding_idx].status = ResolutionStatus::MarkedTodo;
                println!(
                    "{} Hallazgo marcado como TODO en el reporte.",
                    style("⚑").yellow().bold()
                );
                break;
            }
            3 | _ => {
                all_findings[finding_idx].status = ResolutionStatus::Skipped;
                println!("{} Hallazgo omitido.", style("↷").dim());
                break;
            }
        }
    }

    Ok(applied_diffs)
}

fn ensure_ai_config_interactive(cached: &mut Option<AiConfig>) -> Result<AiConfig> {
    if let Some(cfg) = cached {
        let needs_key = find_provider(&cfg.provider_id)
            .map(|p| p.requires_token)
            .unwrap_or(true);
        if !needs_key || cfg.api_key.is_some() {
            return Ok(cfg.clone());
        }
    }

    if let Ok(Some(mut saved)) = load_saved_config() {
        let use_saved = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "Se encontró configuración IA previa ({} / {}). ¿Deseas utilizarla?",
                saved.provider_id, saved.model
            ))
            .default(true)
            .interact()
            .context("Error al confirmar uso de configuración IA guardada")?;

        if use_saved {
            if let Some(provider) = find_provider(&saved.provider_id) {
                if provider.requires_token && saved.api_key.is_none() {
                    saved.api_key = prompt_api_key_for_provider(&provider)?;
                }
                *cached = Some(saved.clone());
                return Ok(saved);
            }
        }
    }

    println!();
    println!(
        "{}\n",
        style("Catálogo de proveedores IA compatibles (BYOK):")
            .cyan()
            .bold()
    );
    println!("{}", super::render_ai_catalog_table());

    let cfg = configure_ai_interactive()?;
    let _ = save_config_metadata(&cfg)
        .context("No se pudieron guardar los metadatos de configuración IA")?;
    *cached = Some(cfg.clone());
    Ok(cfg)
}

fn prompt_model_for_provider(provider: &AiProviderInfo) -> Result<String> {
    let theme = ColorfulTheme::default();
    if provider.suggested_models.is_empty() {
        return Input::with_theme(&theme)
            .with_prompt("Ingresa el nombre del modelo a utilizar")
            .interact_text()
            .context("Error al leer el modelo IA");
    }

    let mut choices: Vec<String> = provider
        .suggested_models
        .iter()
        .map(|m| m.to_string())
        .collect();
    choices.push("Ingresar modelo manualmente...".to_string());

    let idx = Select::with_theme(&theme)
        .with_prompt(format!("Selecciona un modelo para {}", provider.display_name))
        .items(&choices)
        .default(0)
        .interact()
        .context("Error al seleccionar modelo")?;

    if idx < provider.suggested_models.len() {
        Ok(provider.suggested_models[idx].to_string())
    } else {
        Input::with_theme(&theme)
            .with_prompt("Nombre del modelo personalizado")
            .interact_text()
            .context("Error al leer modelo personalizado")
    }
}

fn prompt_api_key_for_provider(provider: &AiProviderInfo) -> Result<Option<String>> {
    if !provider.requires_token {
        println!(
            "{} El proveedor '{}' es local y no requiere token.",
            style("ℹ").cyan(),
            provider.display_name
        );
        return Ok(None);
    }

    if let Some(env_token) = resolve_api_key_from_env(provider) {
        let env_name = provider.env_var.unwrap_or("variable de entorno");
        let use_env = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "Se detectó una API Key en `{env_name}`. ¿Deseas usarla?"
            ))
            .default(true)
            .interact()
            .context("Error al confirmar token de variable de entorno")?;
        if use_env {
            return Ok(Some(env_token));
        }
    }

    let help_md = crate::ai::render_token_help_for_provider(Some(provider.id));
    println!();
    println!(
        "{}",
        style("── Cómo obtener tu Token de IA ─────────────────────────────")
            .yellow()
            .bold()
    );
    println!("{help_md}");
    println!(
        "{}",
        style("────────────────────────────────────────────────────────────")
            .yellow()
    );

    let env_hint = provider
        .env_var
        .map(|e| format!(" (o configura `{e}` en tu entorno)"))
        .unwrap_or_default();
    let token = Password::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Ingresa el token/API Key para {}{}",
            provider.display_name, env_hint
        ))
        .allow_empty_password(false)
        .interact()
        .context("Error al leer API Key oculta")?;

    Ok(Some(token))
}

/// Informa al usuario y prepara una rama Git dedicada para aislar cambios y pruebas.
fn prepare_git_migration_branch(
    project_root: &Path,
    target_php: PhpVersion,
    requested_branch: Option<&str>,
    auto_create: bool,
    non_interactive: bool,
) -> Result<Option<GitBranchContext>> {
    let head_out = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(project_root)
        .output();

    let Ok(out) = head_out else {
        return Ok(None);
    };
    if !out.status.success() {
        return Ok(None);
    }

    let original_branch = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if original_branch.is_empty() {
        return Ok(None);
    }

    let default_branch = requested_branch
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("migration/php-{}", target_php.as_str()));

    if original_branch == default_branch {
        println!(
            "{} Ya estás trabajando en la rama de migración '{}'.",
            style("ℹ").cyan().bold(),
            style(&default_branch).green().bold()
        );
        return Ok(Some(GitBranchContext {
            original_branch,
            migration_branch: default_branch,
            branch_active: true,
        }));
    }

    println!();
    println!(
        "{} Se creará una rama Git dedicada ('{}') a partir de '{}' para realizar todas las modificaciones y pruebas sin afectar tu rama principal.",
        style("==>").cyan().bold(),
        style(&default_branch).green().bold(),
        style(&original_branch).yellow().bold()
    );
    println!(
        "    Cuando termines de probar y estés conforme con el resultado, podrás integrar los cambios con `git merge`."
    );

    if non_interactive && !auto_create {
        println!(
            "{} Modo no interactivo sin `--create-branch`: manteniendo la rama actual '{}'.",
            style("ℹ").dim(),
            original_branch
        );
        return Ok(None);
    }

    let migration_branch = if auto_create {
        default_branch
    } else {
        let confirm = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "¿Crear y cambiar ahora a la rama '{}' para hacer las pruebas?",
                default_branch
            ))
            .default(true)
            .interact()
            .context("Error al confirmar creación de rama Git")?;

        if !confirm {
            return Ok(None);
        }

        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Nombre de la rama de pruebas")
            .default(default_branch)
            .interact_text()
            .context("Error al leer nombre de rama Git")?
    };

    let checkout_new = std::process::Command::new("git")
        .args(["checkout", "-b", &migration_branch])
        .current_dir(project_root)
        .output()
        .context("Error al ejecutar `git checkout -b`")?;

    if checkout_new.status.success() {
        println!(
            "{} Rama '{}' creada y activada (origen: '{}').",
            style("✔").green().bold(),
            style(&migration_branch).green().bold(),
            original_branch
        );
        return Ok(Some(GitBranchContext {
            original_branch,
            migration_branch,
            branch_active: true,
        }));
    }

    // Si la rama ya existía, intentar cambiar a ella directamente
    let checkout_existing = std::process::Command::new("git")
        .args(["checkout", &migration_branch])
        .current_dir(project_root)
        .output()
        .context("Error al ejecutar `git checkout`")?;

    if checkout_existing.status.success() {
        println!(
            "{} Cambiado a rama existente '{}' (origen: '{}').",
            style("✔").green().bold(),
            style(&migration_branch).green().bold(),
            original_branch
        );
        Ok(Some(GitBranchContext {
            original_branch,
            migration_branch,
            branch_active: true,
        }))
    } else {
        let stderr = String::from_utf8_lossy(&checkout_existing.stderr);
        println!(
            "{} No se pudo activar la rama '{}' ({}). Se continuará en '{}'.",
            style("!").yellow().bold(),
            migration_branch,
            stderr.trim(),
            original_branch
        );
        Ok(None)
    }
}

/// Localiza un binario `php` local (PHP 8.x en PATH o Laragon) para validación offline `php -l`.
fn find_local_php_binary() -> Option<PathBuf> {
    if let Ok(out) = std::process::Command::new("php").arg("-v").output() {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("PHP 8.") {
                return Some(PathBuf::from("php"));
            }
        }
    }

    #[cfg(windows)]
    {
        let laragon_php_dir = Path::new(r"D:\laragon\bin\php");
        if let Ok(entries) = std::fs::read_dir(laragon_php_dir) {
            let mut candidates: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.is_dir()
                        && p.file_name()
                            .map(|n| n.to_string_lossy().to_ascii_lowercase().starts_with("php-8."))
                            .unwrap_or(false)
                })
                .map(|p| p.join("php.exe"))
                .filter(|exe| exe.is_file())
                .collect();
            candidates.sort();
            candidates.reverse();
            if let Some(best) = candidates.into_iter().next() {
                return Some(best);
            }
        }
    }

    if let Ok(out) = std::process::Command::new("php").arg("-v").output() {
        if out.status.success() {
            return Some(PathBuf::from("php"));
        }
    }

    None
}

fn verify_php_file_syntax_offline(php_bin: &Path, file_path: &Path) -> std::result::Result<(), String> {
    let out = std::process::Command::new(php_bin)
        .arg("-l")
        .arg(file_path)
        .output()
        .map_err(|e| format!("No se pudo ejecutar `{}`: {e}", php_bin.display()))?;

    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        Err(if stderr.is_empty() { stdout } else { stderr })
    }
}

/// Aplica una resolución IA individual validando sintaxis `php -l` y haciendo rollback si falla.
fn try_apply_single_ai_resolution(
    root_path: &Path,
    all_findings: &mut Vec<MigrationFinding>,
    finding_idx: usize,
    resolution: &crate::models::AiResolution,
    php_bin: Option<&Path>,
    collected_diffs: &mut Vec<FilePatchDiff>,
) -> bool {
    let original_code = all_findings[finding_idx].original_code.clone();
    if resolution.replacement_code.trim().is_empty()
        || resolution.replacement_code.trim() == original_code.trim()
    {
        println!("    {} IA mantuvo el código original sin cambios.", style("ℹ").dim());
        return false;
    }

    let full_file_path = resolve_project_file(root_path, &all_findings[finding_idx].file);
    let Ok(previous_bytes) = std::fs::read(&full_file_path) else {
        return false;
    };
    let findings_snapshot = all_findings.clone();
    let instruction = PatchInstruction {
        finding_id: all_findings[finding_idx].id.clone(),
        replacement: resolution.replacement_code.clone(),
        status: ResolutionStatus::AppliedAi,
    };

    match apply_findings(root_path, all_findings, &[instruction]) {
        Ok(diffs) => {
            let lint_ok = match php_bin {
                Some(bin) => verify_php_file_syntax_offline(bin, &full_file_path),
                None => Ok(()),
            };
            match lint_ok {
                Ok(()) => {
                    println!(
                        "    {} Parche IA aplicado y validado ({}).",
                        style("✔").green().bold(),
                        resolution.explanation
                    );
                    all_findings[finding_idx].suggested_replacement =
                        Some(resolution.replacement_code.clone());
                    collected_diffs.extend(diffs);
                    true
                }
                Err(lint_err) => {
                    let _ = std::fs::write(&full_file_path, &previous_bytes);
                    *all_findings = findings_snapshot;
                    println!(
                        "    {} Rollback automático: el parche IA falló `php -l` ({}).",
                        style("↺").red().bold(),
                        lint_err
                    );
                    false
                }
            }
        }
        Err(patch_err) => {
            println!(
                "    {} No se pudo aplicar parche IA: {patch_err:#}",
                style("!").yellow()
            );
            false
        }
    }
}

/// Modo piloto automático con IA: usa caché de patrones, agrupación por archivo y contexto condensado
/// para gastar el mínimo de tokens, validando cada cambio con `php -l` y auto-rollback.
async fn run_auto_ai_for_module(
    analysis: &mut ProjectAnalysis,
    logic_graph: &crate::graph::LogicGraphReport,
    module: &ModuleSlice,
    cached_ai_config: &mut Option<AiConfig>,
    ai_cache: &mut AiPatternCache,
) -> Result<Vec<FilePatchDiff>> {
    let ai_cfg = ensure_ai_config_interactive(cached_ai_config)?;
    let php_bin = find_local_php_binary();

    if let Some(ref bin) = php_bin {
        println!(
            "{} Validador offline detectado: `{}` (`php -l`, sin conectar a BD).",
            style("✔").green(),
            bin.display()
        );
    } else {
        println!(
            "{} No se detectó binario `php` local; se omitirá la validación `php -l` por archivo.",
            style("!").yellow()
        );
    }

    let mut collected_diffs: Vec<FilePatchDiff> = Vec::new();
    let root_path = analysis.root_path.clone();

    // 1. Aplicar primero todos los fixes Verdes deterministas del módulo
    let green_diffs = apply_green_fixes_for_module(
        &root_path,
        &mut analysis.migration_findings,
        &module.files,
    )?;
    if !green_diffs.is_empty() {
        println!(
            "{} [Auto-IA] Correcciones Verdes aplicadas ({} archivos):",
            style("✔").green().bold(),
            green_diffs.len()
        );
        print_patch_diffs(&green_diffs);
        collected_diffs.extend(green_diffs);
    }

    // 2. Resolver hallazgos Amarillos y Rojos con optimización máxima de tokens
    let decision_indices: Vec<usize> = analysis
        .migration_findings
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            f.status == ResolutionStatus::Pending
                && f.rule_id != "PHP84-PECL-EXTENSION"
                && matches!(
                    f.bucket,
                    DecisionBucket::YellowNeedsDecision | DecisionBucket::RedBlocker
                )
                && finding_belongs_to_module(f, &root_path, module)
        })
        .map(|(idx, _)| idx)
        .collect();

    if decision_indices.is_empty() {
        println!(
            "{} [Auto-IA] No hay hallazgos de código pendientes para IA en '{}'.",
            style("✔").green(),
            module.name
        );
        return Ok(collected_diffs);
    }

    println!(
        "{} [Auto-IA] Procesando {} hallazgos en '{}' con `{}/{}` (caché + lotes por archivo + contexto condensado)...",
        style("==>").magenta().bold(),
        decision_indices.len(),
        module.name,
        ai_cfg.provider_id,
        ai_cfg.model
    );

    let mut stats = TokenOptimizationStats::default();
    let mut remaining_by_file: std::collections::BTreeMap<PathBuf, Vec<usize>> =
        std::collections::BTreeMap::new();

    // Fase A: Resolver desde caché local (0 tokens) los patrones ya vistos
    for finding_idx in decision_indices {
        let current_finding = analysis.migration_findings[finding_idx].clone();
        let full_file_path = resolve_project_file(&root_path, &current_finding.file);
        let Ok(file_content) = std::fs::read_to_string(&full_file_path) else {
            continue;
        };
        let related_sigs =
            crate::graph::find_related_signatures(logic_graph, &current_finding.file);
        let raw_snippet = build_context_snippet(&file_content, &current_finding, &related_sigs);

        if let Some(cached_res) = ai_cache.get(&current_finding) {
            stats.raw_chars_without_optimization += raw_snippet.len();
            stats.cache_hits += 1;
            println!(
                "  [Caché 0 tokens] {} ({}:{})",
                current_finding.rule_id,
                current_finding.file.display(),
                current_finding.span.start_line
            );
            let _ = try_apply_single_ai_resolution(
                &root_path,
                &mut analysis.migration_findings,
                finding_idx,
                &cached_res,
                php_bin.as_deref(),
                &mut collected_diffs,
            );
        } else {
            remaining_by_file
                .entry(current_finding.file.clone())
                .or_default()
                .push(finding_idx);
        }
    }

    // Fase B: Agrupar por archivo en lotes de hasta 8 hallazgos con ventana fusionada
    for (rel_file, file_indices) in remaining_by_file {
        let full_file_path = resolve_project_file(&root_path, &rel_file);
        let related_sigs = crate::graph::find_related_signatures(logic_graph, &rel_file);

        for chunk in file_indices.chunks(8) {
            let Ok(previous_bytes) = std::fs::read(&full_file_path) else {
                continue;
            };
            let file_content = String::from_utf8_lossy(&previous_bytes).to_string();

            // Re-verificar caché dentro de la misma corrida (por si un lote previo ya resolvió un patrón)
            let mut uncached_indices = Vec::new();
            for &idx in chunk {
                let f = analysis.migration_findings[idx].clone();
                if f.status != ResolutionStatus::Pending {
                    continue;
                }
                let raw_snip = build_context_snippet(&file_content, &f, &related_sigs);
                if let Some(cached_res) = ai_cache.get(&f) {
                    stats.raw_chars_without_optimization += raw_snip.len();
                    stats.cache_hits += 1;
                    let _ = try_apply_single_ai_resolution(
                        &root_path,
                        &mut analysis.migration_findings,
                        idx,
                        &cached_res,
                        php_bin.as_deref(),
                        &mut collected_diffs,
                    );
                } else {
                    stats.raw_chars_without_optimization += raw_snip.len();
                    uncached_indices.push(idx);
                }
            }

            if uncached_indices.is_empty() {
                continue;
            }

            if uncached_indices.len() == 1 {
                let idx = uncached_indices[0];
                let current_finding = analysis.migration_findings[idx].clone();
                let condensed =
                    condense_context_for_finding(&file_content, &current_finding, &related_sigs);
                stats.condensed_chars_sent += condensed.len();
                stats.api_calls_made += 1;

                println!(
                    "  [1 item ~{} tok] {} ({}:{}) -> consultando IA...",
                    estimate_tokens(&condensed),
                    current_finding.rule_id,
                    rel_file.display(),
                    current_finding.span.start_line
                );

                match ask_ai_for_finding(&ai_cfg, &current_finding, &condensed).await {
                    Ok(res) => {
                        ai_cache.insert(&current_finding, res.clone());
                        let _ = try_apply_single_ai_resolution(
                            &root_path,
                            &mut analysis.migration_findings,
                            idx,
                            &res,
                            php_bin.as_deref(),
                            &mut collected_diffs,
                        );
                    }
                    Err(err) => {
                        println!("    {} Error consultando IA: {err:#}", style("✖").red());
                    }
                }
                continue;
            }

            // Lote >= 2 hallazgos en el mismo archivo
            let batch_findings: Vec<MigrationFinding> = uncached_indices
                .iter()
                .map(|&idx| analysis.migration_findings[idx].clone())
                .collect();
            let batch_refs: Vec<&MigrationFinding> = batch_findings.iter().collect();
            let merged_ctx =
                build_merged_file_batch_context(&file_content, &batch_refs, &related_sigs);
            stats.condensed_chars_sent += merged_ctx.len();
            stats.api_calls_made += 1;

            println!(
                "  [Lote {} items en 1 llamada ~{} tok] {} -> consultando IA...",
                batch_refs.len(),
                estimate_tokens(&merged_ctx),
                rel_file.display()
            );

            match ask_ai_batch_for_file(&ai_cfg, &batch_refs, &merged_ctx).await {
                Ok(resolutions) => {
                    let res_map: std::collections::HashMap<String, crate::models::AiResolution> =
                        resolutions.into_iter().collect();

                    let mut batch_instructions = Vec::new();
                    let mut applied_pairs = Vec::new();
                    for &idx in &uncached_indices {
                        let f = &analysis.migration_findings[idx];
                        if let Some(res) = res_map.get(&f.id) {
                            ai_cache.insert(f, res.clone());
                            if !res.replacement_code.trim().is_empty()
                                && res.replacement_code.trim() != f.original_code.trim()
                            {
                                batch_instructions.push(PatchInstruction {
                                    finding_id: f.id.clone(),
                                    replacement: res.replacement_code.clone(),
                                    status: ResolutionStatus::AppliedAi,
                                });
                                applied_pairs.push((idx, res.clone()));
                            }
                        }
                    }

                    if !batch_instructions.is_empty() {
                        let findings_snapshot = analysis.migration_findings.clone();
                        match apply_findings(
                            &root_path,
                            &mut analysis.migration_findings,
                            &batch_instructions,
                        ) {
                            Ok(diffs) => {
                                let lint_ok = match php_bin.as_deref() {
                                    Some(bin) => {
                                        verify_php_file_syntax_offline(bin, &full_file_path)
                                    }
                                    None => Ok(()),
                                };
                                match lint_ok {
                                    Ok(()) => {
                                        for (idx, res) in &applied_pairs {
                                            analysis.migration_findings[*idx]
                                                .suggested_replacement =
                                                Some(res.replacement_code.clone());
                                        }
                                        stats.batched_findings_resolved += applied_pairs.len();
                                        println!(
                                            "    {} Lote aplicado y validado ({} parches en {}).",
                                            style("✔").green().bold(),
                                            applied_pairs.len(),
                                            rel_file.display()
                                        );
                                        collected_diffs.extend(diffs);
                                    }
                                    Err(lint_err) => {
                                        let _ = std::fs::write(&full_file_path, &previous_bytes);
                                        analysis.migration_findings = findings_snapshot;
                                        println!(
                                            "    {} Lote falló `php -l` ({}); reintentando uno a uno con caché...",
                                            style("↺").yellow().bold(),
                                            lint_err
                                        );
                                        for (idx, res) in &applied_pairs {
                                            let _ = try_apply_single_ai_resolution(
                                                &root_path,
                                                &mut analysis.migration_findings,
                                                *idx,
                                                res,
                                                php_bin.as_deref(),
                                                &mut collected_diffs,
                                            );
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                println!(
                                    "    {} Error aplicando lote ({err:#}); intentando individual...",
                                    style("!").yellow()
                                );
                                for (idx, res) in &applied_pairs {
                                    let _ = try_apply_single_ai_resolution(
                                        &root_path,
                                        &mut analysis.migration_findings,
                                        *idx,
                                        res,
                                        php_bin.as_deref(),
                                        &mut collected_diffs,
                                    );
                                }
                            }
                        }
                    }
                }
                Err(batch_err) => {
                    println!(
                        "    {} Falló lote ({batch_err:#}); fallback individual...",
                        style("!").yellow()
                    );
                    for &idx in &uncached_indices {
                        let f = analysis.migration_findings[idx].clone();
                        let Ok(cur_content) = std::fs::read_to_string(&full_file_path) else {
                            continue;
                        };
                        let condensed =
                            condense_context_for_finding(&cur_content, &f, &related_sigs);
                        stats.condensed_chars_sent += condensed.len();
                        stats.api_calls_made += 1;
                        if let Ok(res) = ask_ai_for_finding(&ai_cfg, &f, &condensed).await {
                            ai_cache.insert(&f, res.clone());
                            let _ = try_apply_single_ai_resolution(
                                &root_path,
                                &mut analysis.migration_findings,
                                idx,
                                &res,
                                php_bin.as_deref(),
                                &mut collected_diffs,
                            );
                        }
                    }
                }
            }
        }
    }

    let _ = ai_cache.save();

    println!();
    println!(
        "{}",
        style("── Resumen de Optimización de Tokens IA ────────────────────")
            .cyan()
            .bold()
    );
    println!("  Llamadas API realizadas:       {}", stats.api_calls_made);
    println!("  Resueltos vía caché (0 tok):   {}", stats.cache_hits);
    println!("  Resueltos agrupados en lote:   {}", stats.batched_findings_resolved);
    println!("  Tokens de contexto enviados:   ~{}", stats.estimated_tokens_sent());
    println!(
        "  Tokens ahorrados estimados:    ~{} ({:.1}% de ahorro)",
        stats.estimated_tokens_saved(),
        stats.savings_percentage()
    );

    Ok(collected_diffs)
}

async fn run_docker_verification_flow(
    project_root: &Path,
    source: PhpVersion,
    target: PhpVersion,
    db_dump: Option<PathBuf>,
    db_engine: &str,
    routes: Vec<String>,
    auto_confirm: bool,
) -> Result<()> {
    let db_mode = if let Some(dump_path) = db_dump {
        let engine = parse_db_engine(db_engine)?;
        DbIsolationMode::SqlDumpClone { dump_path, engine }
    } else if auto_confirm {
        DbIsolationMode::NoDatabase
    } else {
        prompt_db_isolation_mode()?
    };

    let effective_routes = if !routes.is_empty() {
        routes
    } else if auto_confirm {
        vec!["/".to_string()]
    } else {
        let input: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Rutas HTTP a comparar separadas por coma")
            .default("/".to_string())
            .interact_text()
            .context("Error al leer rutas del sandbox")?;
        let parsed: Vec<String> = input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if parsed.is_empty() {
            vec!["/".to_string()]
        } else {
            parsed
        }
    };

    let config = SandboxConfig {
        project_root: project_root.to_path_buf(),
        source_php: source,
        target_php: target,
        db_mode,
        routes_to_test: effective_routes,
        source_port: 18074,
        target_port: 18085,
    };

    let compose_path = write_sandbox_files(&config)
        .context("No se pudieron generar los archivos de configuración del sandbox Docker")?;
    println!(
        "{} Archivo Docker Compose del sandbox generado en '{}'.",
        style("✔").green().bold(),
        style(compose_path.display()).cyan()
    );

    if !check_docker_available().await {
        println!(
            "{} Docker no está disponible o el daemon no responde en este equipo. El archivo '{}' quedó listo para ejecución manual.",
            style("!").yellow().bold(),
            compose_path.display()
        );
        return Ok(());
    }

    let authorized = if auto_confirm {
        true
    } else {
        Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "¿Autorizas descargar imágenes oficiales (PHP {} y PHP {}) si faltan y levantar contenedores Docker aislados?",
                source, target
            ))
            .default(false)
            .interact()
            .context("Error al solicitar autorización de Docker")?
    };

    if !authorized {
        println!(
            "{} Ejecución Docker cancelada por el usuario. El archivo del sandbox permanece en '{}'.",
            style("ℹ").cyan(),
            compose_path.display()
        );
        return Ok(());
    }

    println!(
        "{} Ejecutando verificación dual Docker (PHP {} vs PHP {})...",
        style("==>").cyan().bold(),
        source,
        target
    );
    let report = run_dual_verification(&config, authorized)
        .await
        .context("Error al ejecutar la verificación dual en Docker")?;
    print_sandbox_report(&report, source, target);

    Ok(())
}

fn prompt_db_isolation_mode() -> Result<DbIsolationMode> {
    let theme = ColorfulTheme::default();
    let options = [
        "[1] Clonar Dump SQL en dos contenedores aislados (Recomendado)",
        "[2] Base de datos existente en modo Solo Lectura",
        "[3] Sin base de datos (Solo php -l y rutas sin BD)",
    ];

    let choice = Select::with_theme(&theme)
        .with_prompt("¿Cómo deseas manejar la Base de Datos durante la verificación dual?")
        .items(&options)
        .default(0)
        .interact()
        .context("Error al seleccionar estrategia de base de datos")?;

    match choice {
        0 => {
            let dump_str: String = Input::with_theme(&theme)
                .with_prompt("Ruta al archivo dump .sql")
                .interact_text()
                .context("Error al leer ruta del dump SQL")?;
            let dump_path = PathBuf::from(dump_str.trim());
            if !dump_path.exists() {
                println!(
                    "{} Advertencia: el archivo '{}' no existe actualmente en disco.",
                    style("!").yellow().bold(),
                    dump_path.display()
                );
            }

            let engines = [DbEngine::MySql, DbEngine::MariaDb, DbEngine::Postgres];
            let engine_labels: Vec<String> = engines.iter().map(|e| e.to_string()).collect();
            let engine_idx = Select::with_theme(&theme)
                .with_prompt("Selecciona el motor de base de datos")
                .items(&engine_labels)
                .default(0)
                .interact()
                .context("Error al seleccionar motor de BD")?;

            Ok(DbIsolationMode::SqlDumpClone {
                dump_path,
                engine: engines[engine_idx],
            })
        }
        1 => {
            println!(
                "{} Usa únicamente un usuario con permisos de SOLO LECTURA (SELECT).",
                style("ℹ").yellow()
            );
            let host: String = Input::with_theme(&theme)
                .with_prompt("Host de la base de datos")
                .default("host.docker.internal".to_string())
                .interact_text()
                .context("Error al leer host de BD")?;
            let port: u16 = Input::with_theme(&theme)
                .with_prompt("Puerto")
                .default(3306)
                .interact_text()
                .context("Error al leer puerto de BD")?;
            let database: String = Input::with_theme(&theme)
                .with_prompt("Nombre de la base de datos")
                .interact_text()
                .context("Error al leer nombre de BD")?;
            let user: String = Input::with_theme(&theme)
                .with_prompt("Usuario de solo lectura")
                .interact_text()
                .context("Error al leer usuario de BD")?;

            Ok(DbIsolationMode::ExistingReadOnly {
                host,
                port,
                database,
                user,
            })
        }
        _ => Ok(DbIsolationMode::NoDatabase),
    }
}

fn parse_db_engine(raw: &str) -> Result<DbEngine> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "mysql" => Ok(DbEngine::MySql),
        "mariadb" => Ok(DbEngine::MariaDb),
        "postgres" | "postgresql" | "pg" => Ok(DbEngine::Postgres),
        other => Err(anyhow!(
            "Motor de BD no soportado: '{other}'. Usa: mysql, mariadb o postgres"
        )),
    }
}

fn print_sandbox_report(report: &SandboxReport, source_php: PhpVersion, target_php: PhpVersion) {
    println!();
    println!(
        "{}",
        style("══════════════════════════════════════════════════════════════")
            .cyan()
    );
    println!(
        "{} (PHP {} vs PHP {})",
        style("COMPARACIÓN DUAL EN SANDBOX DOCKER").cyan().bold(),
        source_php,
        target_php
    );
    println!(
        "{}",
        style("══════════════════════════════════════════════════════════════")
            .cyan()
    );
    println!("  Compose: {}", report.compose_path.display());

    let lint_label = if report.lint_passed {
        style("OK").green().bold()
    } else {
        style("ERRORES").red().bold()
    };

    println!(
        "  Sintaxis (`php -l`) en PHP {}: {}",
        target_php, lint_label
    );
    for err in &report.lint_errors {
        println!("    - {}", style(err).red());
    }

    if !report.comparisons.is_empty() {
        println!();
        println!("{}", style("Comparación de rutas HTTP:").bold());
        for rc in &report.comparisons {
            let status_badge = if rc.source_status == rc.target_status && rc.body_matches_normalized
            {
                style("EQUIVALENTE").green().bold()
            } else {
                style("DIFERENCIA").red().bold()
            };
            println!(
                "  • {} -> {} | origen HTTP {} | destino HTTP {} | {}",
                style(&rc.route).white().bold(),
                status_badge,
                rc.source_status,
                rc.target_status,
                rc.diff_summary
            );
            for err in &rc.source_errors {
                println!("      [origen]  {}", style(err).yellow());
            }
            for err in &rc.target_errors {
                println!("      [destino] {}", style(err).red());
            }
        }
    }
    println!();
}

fn print_patch_diffs(diffs: &[FilePatchDiff]) {
    for diff in diffs {
        println!(
            "  {} {} ({} cambio(s))",
            style("•").cyan(),
            style(diff.file.display()).bold(),
            diff.applied_count
        );
        if !diff.unified_diff.trim().is_empty() {
            print_colored_diff(&diff.unified_diff);
        }
    }
}

fn print_colored_diff(diff_text: &str) {
    for line in diff_text.lines() {
        if line.starts_with("+++") || line.starts_with("---") || line.starts_with("@@") {
            println!("    {}", style(line).cyan());
        } else if line.starts_with('+') {
            println!("    {}", style(line).green());
        } else if line.starts_with('-') {
            println!("    {}", style(line).red());
        } else {
            println!("    {}", style(line).dim());
        }
    }
}

fn count_module_findings(
    findings: &[MigrationFinding],
    root_path: &Path,
    module: &ModuleSlice,
    bucket: DecisionBucket,
    only_pending: bool,
) -> usize {
    findings
        .iter()
        .filter(|f| {
            f.bucket == bucket
                && (!only_pending || f.status == ResolutionStatus::Pending)
                && finding_belongs_to_module(f, root_path, module)
        })
        .count()
}

fn finding_belongs_to_module(
    finding: &MigrationFinding,
    root_path: &Path,
    module: &ModuleSlice,
) -> bool {
    let finding_abs = resolve_project_file(root_path, &finding.file);
    module.files.iter().any(|mf| {
        mf == &finding.file || resolve_project_file(root_path, mf) == finding_abs
    })
}

fn resolve_project_file(root_path: &Path, file: &Path) -> PathBuf {
    if file.is_absolute() {
        file.to_path_buf()
    } else {
        root_path.join(file)
    }
}

fn infer_routes_from_module(root_path: &Path, module: &ModuleSlice) -> Vec<String> {
    let mut routes: Vec<String> = module
        .entrypoints
        .iter()
        .filter_map(|ep| {
            let rel = ep.strip_prefix(root_path).unwrap_or(ep);
            let s = rel.to_string_lossy().replace('\\', "/");
            if s.is_empty() {
                None
            } else if s.starts_with('/') {
                Some(s)
            } else {
                Some(format!("/{s}"))
            }
        })
        .take(5)
        .collect();

    if routes.is_empty() {
        routes.push("/".to_string());
    }
    routes
}
