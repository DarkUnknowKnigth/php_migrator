pub mod wizard;

use crate::models::{DecisionBucket, PhpVersion, ProjectAnalysis, RiskLevel, Severity};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

/// CLI principal de `php-migrator`.
#[derive(Debug, Parser)]
#[command(
    name = "php-migrator",
    version,
    about = "Analiza, mapea lógica y migra proyectos PHP (7.4–8.x a 8.5) por módulos con verificación Docker y soporte IA BYOK."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Subcomandos disponibles en `php-migrator`.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Escanea el proyecto PHP y genera el reporte técnico, mapa Mermaid y JSON.
    Analyze {
        /// Ruta raíz del proyecto PHP a analizar.
        path: PathBuf,
        /// Versión objetivo de PHP (ej. 8.2, 8.3, 8.4, 8.5).
        #[arg(long, default_value = "8.5")]
        target: String,
        /// Directorio de salida para artefactos (por defecto: <path>/.php-migrator).
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Ejecuta el asistente interactivo de migración por módulos lógicos.
    Migrate {
        /// Ruta raíz del proyecto PHP a migrar.
        path: PathBuf,
        /// Versión destino de PHP (si se omite, el asistente la preguntará tras el escaneo).
        #[arg(long)]
        target: Option<String>,
        /// ID o nombre del módulo específico a migrar.
        #[arg(long)]
        module: Option<String>,
        /// Aplica automáticamente las correcciones seguras (Verde) sin pedir confirmación.
        #[arg(long)]
        auto_green: bool,
        /// Ejecuta sin prompts interactivos (aplica fixes verdes si --auto-green).
        #[arg(long)]
        non_interactive: bool,
        /// Finaliza sin conectar ni ejecutar consultas en BD y genera la guía post-migración para el usuario.
        #[arg(long)]
        no_db: bool,
        /// Directorio de salida para reportes y guía post-migración (por defecto: <path>/.php-migrator).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Modo piloto automático con IA: solicita proveedor/token al inicio, aplica Verdes, resuelve Amarillos/Rojos con IA y valida sintaxis `php -l` con auto-rollback.
        #[arg(long)]
        auto_ai: bool,
        /// Crea automáticamente una rama Git dedicada para las pruebas de migración sin pedir confirmación.
        #[arg(long)]
        create_branch: bool,
        /// Nombre personalizado para la rama Git de migración (por defecto: migration/php-<destino>).
        #[arg(long)]
        branch: Option<String>,
    },
    /// Muestra el catálogo de proveedores IA (BYOK) soportados y permite configurarlos.
    AiCatalog {
        /// Inicia el flujo interactivo para configurar y guardar metadatos del proveedor IA.
        #[arg(long)]
        configure: bool,
        /// Imprime en consola la guía Markdown paso a paso para obtener tokens de IA.
        #[arg(long)]
        help_tokens: bool,
        /// Filtra la guía de obtención de token por un proveedor específico (ej. gemini, openai, ollama).
        #[arg(long)]
        provider: Option<String>,
    },
    /// Levanta el entorno de verificación dual Docker (PHP origen vs PHP destino).
    Sandbox {
        /// Ruta raíz del proyecto PHP.
        path: PathBuf,
        /// Versión PHP de origen para comparación (ej. 7.4).
        #[arg(long, default_value = "7.4")]
        source: String,
        /// Versión PHP destino para comparación (ej. 8.5).
        #[arg(long, default_value = "8.5")]
        target: String,
        /// Ruta a un archivo dump .sql para clonar en contenedores aislados.
        #[arg(long)]
        db_dump: Option<PathBuf>,
        /// Motor de base de datos para el dump (mysql, mariadb, postgres).
        #[arg(long, default_value = "mysql")]
        db_engine: String,
        /// Rutas HTTP a verificar en ambos contenedores (ej. / /login.php).
        #[arg(long, value_delimiter = ',')]
        routes: Vec<String>,
        /// Autoriza automáticamente la ejecución de Docker sin confirmación interactiva.
        #[arg(long)]
        yes: bool,
    },
}

/// Formatea en una tabla legible los proveedores del catálogo integrado BYOK.
pub fn render_ai_catalog_table() -> String {
    let catalog = crate::ai::builtin_catalog();

    let headers = [
        "ID",
        "Proveedor",
        "Protocolo",
        "Token",
        "Variable de Entorno",
        "Modelos Sugeridos",
    ];

    let rows: Vec<[String; 6]> = catalog
        .iter()
        .map(|p| {
            [
                p.id.to_string(),
                p.display_name.to_string(),
                format!("{}", p.protocol),
                if p.requires_token {
                    "Requerido".to_string()
                } else {
                    "No (Local)".to_string()
                },
                p.env_var.unwrap_or("-").to_string(),
                if p.suggested_models.is_empty() {
                    "-".to_string()
                } else {
                    p.suggested_models.join(", ")
                },
            ]
        })
        .collect();

    let mut widths = headers.map(|h| h.chars().count());
    for row in &rows {
        for (idx, cell) in row.iter().enumerate() {
            widths[idx] = widths[idx].max(cell.chars().count());
        }
    }

    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}",
        format_table_row(
            &headers.map(|h| h.to_string()),
            &widths
        )
    );
    let sep: Vec<String> = widths.iter().map(|&w| "-".repeat(w)).collect();
    let _ = writeln!(out, "{}", sep.join(" | "));
    for row in &rows {
        let _ = writeln!(out, "{}", format_table_row(row, &widths));
    }

    out
}

/// Punto de entrada principal del CLI asíncrono.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            path,
            target,
            output,
        } => {
            ensure_project_dir_exists(&path)?;
            let target_php = PhpVersion::from_str(&target).map_err(|e| anyhow!(e))?;

            println!(
                "{} Escaneando proyecto en {} (destino: {})...",
                style("==>").cyan().bold(),
                style(path.display()).white().bold(),
                style(format!("PHP {target_php}")).green().bold()
            );

            let spinner = ProgressBar::new_spinner();
            if let Ok(pb_style) =
                ProgressStyle::with_template("{spinner:.cyan} {msg}")
            {
                spinner.set_style(pb_style);
            }
            spinner.set_message("Analizando AST, dependencias y grafo de lógica...");
            spinner.enable_steady_tick(Duration::from_millis(80));

            let scan = crate::scanner::scan_project(&path, target_php)
                .context("Falló el escaneo del proyecto PHP")?;
            spinner.finish_and_clear();

            let output_dir = output.unwrap_or_else(|| path.join(".php-migrator"));
            let (report_path, map_path, json_path) = crate::reporter::write_analysis_artifacts(
                &output_dir,
                &scan.analysis,
                &scan.logic_graph,
            )?;

            print_analyze_summary(&scan.analysis, &report_path, &map_path, &json_path);
        }
        Commands::Migrate {
            path,
            target,
            module,
            auto_green,
            non_interactive,
            no_db,
            output,
            auto_ai,
            create_branch,
            branch,
        } => {
            ensure_project_dir_exists(&path)?;
            let target_php = match target {
                Some(t) => Some(PhpVersion::from_str(&t).map_err(|e| anyhow!(e))?),
                None => None,
            };

            wizard::run_migrate_wizard(
                path,
                target_php,
                module,
                auto_green,
                non_interactive,
                no_db,
                output,
                auto_ai,
                create_branch,
                branch,
            )
            .await?;
        }
        Commands::AiCatalog {
            configure,
            help_tokens,
            provider,
        } => {
            println!(
                "{}\n",
                style("Catálogo de proveedores IA compatibles (BYOK)")
                    .cyan()
                    .bold()
            );
            println!("{}", render_ai_catalog_table());

            if help_tokens || provider.is_some() {
                println!(
                    "{}\n",
                    style("── Guía para obtener tu Token de IA ────────────────────────")
                        .yellow()
                        .bold()
                );
                println!("{}", crate::ai::render_token_help_for_provider(provider.as_deref()));
            }

            if configure {
                let config = wizard::configure_ai_interactive()?;
                let _ = crate::ai::save_config_metadata(&config)
                    .context("No se pudieron guardar los metadatos de configuración IA")?;
                println!(
                    "{} Configuración IA guardada (sin almacenar el token secreto en disco): proveedor '{}' / modelo '{}'.",
                    style("✔").green().bold(),
                    style(&config.provider_id).cyan(),
                    style(&config.model).cyan()
                );
            }
        }
        Commands::Sandbox {
            path,
            source,
            target,
            db_dump,
            db_engine,
            routes,
            yes,
        } => {
            ensure_project_dir_exists(&path)?;
            let source_php = PhpVersion::from_str(&source).map_err(|e| anyhow!(e))?;
            let target_php = PhpVersion::from_str(&target).map_err(|e| anyhow!(e))?;

            wizard::run_sandbox_cli(path, source_php, target_php, db_dump, db_engine, routes, yes)
                .await?;
        }
    }

    Ok(())
}

fn ensure_project_dir_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(anyhow!(
            "La ruta del proyecto no existe: '{}'",
            path.display()
        ));
    }
    if !path.is_dir() {
        return Err(anyhow!(
            "La ruta proporcionada no es un directorio: '{}'",
            path.display()
        ));
    }
    Ok(())
}

fn format_table_row(cells: &[String; 6], widths: &[usize; 6]) -> String {
    let padded: Vec<String> = cells
        .iter()
        .enumerate()
        .map(|(idx, cell)| {
            let len = cell.chars().count();
            let pad = widths[idx].saturating_sub(len);
            format!("{cell}{}", " ".repeat(pad))
        })
        .collect();
    padded.join(" | ")
}

fn print_analyze_summary(
    analysis: &ProjectAnalysis,
    report_path: &Path,
    map_path: &Path,
    json_path: &Path,
) {
    println!();
    println!(
        "{}",
        style("══════════════════════════════════════════════════════════════")
            .dim()
    );
    println!(
        "{}  {} → {}",
        style("RESUMEN DE ANÁLISIS PHP-MIGRATOR").cyan().bold(),
        style(format!("PHP {}", analysis.detected_php_version))
            .yellow()
            .bold(),
        style(format!("PHP {}", analysis.target_php_version))
            .green()
            .bold()
    );
    println!(
        "{}",
        style("══════════════════════════════════════════════════════════════")
            .dim()
    );

    println!(
        "  {:<22} {}",
        style("Proyecto:").bold(),
        analysis.root_path.display()
    );
    println!("  {:<22} {}", style("Framework:").bold(), analysis.framework);
    println!(
        "  {:<22} {} totales | {} PHP | {} mixtos HTML+PHP | {} líneas",
        style("Archivos:").bold(),
        analysis.total_files,
        analysis.php_files_count,
        analysis.mixed_html_files_count,
        analysis.total_lines
    );
    println!(
        "  {:<22} includes: {} | vendor: {}",
        style("Estructura:").bold(),
        analysis.include_dirs.len(),
        analysis.vendor_dirs.len()
    );

    if !analysis.version_evidence.is_empty() {
        let preview: Vec<&str> = analysis
            .version_evidence
            .iter()
            .take(3)
            .map(String::as_str)
            .collect();
        println!(
            "  {:<22} {}",
            style("Evidencia versión:").bold(),
            style(preview.join(" ; ")).dim()
        );
    }

    let incompatible_deps = analysis
        .dependencies
        .iter()
        .filter(|d| d.target_compatible == Some(false))
        .count();
    println!(
        "  {:<22} {} detectadas ({} incompatibles con PHP {})",
        style("Dependencias:").bold(),
        analysis.dependencies.len(),
        if incompatible_deps > 0 {
            style(incompatible_deps).red().bold()
        } else {
            style(incompatible_deps).green()
        },
        analysis.target_php_version
    );

    // Migración por bucket
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

    println!();
    println!("{}", style("Hallazgos de Migración:").bold());
    println!(
        "  {} {:<28} {}",
        style("●").green(),
        "Verde (Auto-fix seguro):",
        style(green).green().bold()
    );
    println!(
        "  {} {:<28} {}",
        style("●").yellow(),
        "Amarillo (Decisión / IA):",
        style(yellow).yellow().bold()
    );
    println!(
        "  {} {:<28} {}",
        style("●").red(),
        "Rojo (Bloqueante):",
        style(red).red().bold()
    );

    // Radar de Seguridad PHP2Shell / RCE
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
    let med = analysis
        .security_findings
        .iter()
        .filter(|s| s.severity == Severity::Medium)
        .count();
    let low = analysis
        .security_findings
        .iter()
        .filter(|s| s.severity == Severity::Low)
        .count();

    println!();
    println!("{}", style("Radar de Seguridad PHP2Shell / RCE:").bold());
    if analysis.security_findings.is_empty() {
        println!(
            "  {} Sin alertas críticas o sospechosas detectadas.",
            style("✔").green()
        );
    } else {
        println!(
            "  {} Crítica: {} | Alta: {} | Media: {} | Baja: {}",
            style("!").red().bold(),
            style(crit).red().bold(),
            style(high).red(),
            style(med).yellow(),
            style(low).dim()
        );
        for alert in analysis
            .security_findings
            .iter()
            .filter(|s| s.severity >= Severity::High)
            .take(5)
        {
            println!(
                "    - [{}] {}:{} — {}",
                style(alert.severity).red().bold(),
                alert.file.display(),
                alert.line,
                alert.description
            );
        }
    }

    // Módulos lógicos
    if !analysis.modules.is_empty() {
        println!();
        println!(
            "{}",
            style("Módulos Lógicos (orden recomendado de migración):").bold()
        );
        let ordered = crate::reporter::recommended_migration_order(&analysis.modules);
        for (idx, m) in ordered.iter().enumerate() {
            let risk_styled = match m.risk_level {
                RiskLevel::Low => style(m.risk_level.to_string()).green(),
                RiskLevel::Medium => style(m.risk_level.to_string()).yellow(),
                RiskLevel::High => style(m.risk_level.to_string()).red(),
                RiskLevel::Critical => style(m.risk_level.to_string()).red().bold(),
            };
            println!(
                "  {}. {} ({}) — {} archivos | Riesgo: {} | V/A/R: {}/{}/{}",
                idx + 1,
                style(&m.name).bold(),
                style(&m.id).dim(),
                m.files.len(),
                risk_styled,
                style(m.green_count).green(),
                style(m.yellow_count).yellow(),
                style(m.red_count).red(),
            );
        }
    }

    println!();
    println!("{}", style("Artefactos generados:").bold());
    println!("  - Reporte técnico: {}", style(report_path.display()).cyan());
    println!("  - Mapa lógico:     {}", style(map_path.display()).cyan());
    println!("  - Datos JSON:      {}", style(json_path.display()).cyan());
    println!();
}
