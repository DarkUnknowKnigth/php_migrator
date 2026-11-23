pub mod laravel;

use crate::models::{
    DecisionBucket, DependencyInfo, FileSummary, FrameworkKind, MigrationFinding, PhpVersion,
    ResolutionStatus, RuleCategory,
};
use crate::parser::lexer::span_from_bytes;
use std::fs;
use std::path::{Path, PathBuf};

/// Interfaz común para adaptadores de migración por framework PHP.
pub trait FrameworkAdapter {
    fn name(&self) -> &'static str;

    fn check_upgrade(
        &self,
        root: &Path,
        current_php: PhpVersion,
        target_php: PhpVersion,
        deps: &[DependencyInfo],
        summaries: &[FileSummary],
    ) -> Vec<MigrationFinding>;
}

/// Evalúa reglas específicas del framework detectado en el proyecto.
pub fn detect_and_evaluate_framework(
    framework: &FrameworkKind,
    root: &Path,
    current_php: PhpVersion,
    target_php: PhpVersion,
    deps: &[DependencyInfo],
    summaries: &[FileSummary],
) -> Vec<MigrationFinding> {
    match framework {
        FrameworkKind::Laravel { .. } => {
            let adapter = laravel::LaravelAdapter;
            adapter.check_upgrade(root, current_php, target_php, deps, summaries)
        }
        FrameworkKind::WordPress => {
            evaluate_wordpress(root, current_php, target_php)
        }
        FrameworkKind::CodeIgniter { version } => {
            evaluate_codeigniter(root, version.as_deref(), current_php, target_php)
        }
        FrameworkKind::Symfony { version } => {
            evaluate_symfony(root, version.as_deref(), current_php, target_php)
        }
        FrameworkKind::VanillaPhp => Vec::new(),
    }
}

fn evaluate_wordpress(
    root: &Path,
    current_php: PhpVersion,
    target_php: PhpVersion,
) -> Vec<MigrationFinding> {
    if target_php <= current_php || target_php < PhpVersion::Php81 {
        return Vec::new();
    }

    let wp_config = root.join("wp-config.php");
    let Ok(raw) = fs::read_to_string(&wp_config) else {
        return Vec::new();
    };
    let first_line_end = raw.find('\n').unwrap_or(raw.len());
    let end = raw[..first_line_end].trim_end_matches('\r').len();
    if end == 0 {
        return Vec::new();
    }

    let span = span_from_bytes(&raw, 0, end);
    vec![build_framework_finding(
        &PathBuf::from("wp-config.php"),
        &raw,
        "WP-COMPAT-CHECK",
        target_php,
        DecisionBucket::YellowNeedsDecision,
        RuleCategory::FrameworkUpgrade,
        span,
        format!(
            "Proyecto WordPress migrando de PHP {current_php} a {target_php}: valida la versión del núcleo WordPress (>= 6.4+ para PHP 8.2/8.3, >= 6.7+ para PHP 8.4) y los plugins/temas en `wp-content/`."
        ),
        "Las incompatibilidades de WordPress con PHP 8.2+ suelen originarse en plugins legados de terceros (propiedades dinámicas y parámetros null).".to_string(),
    )]
}

fn evaluate_codeigniter(
    root: &Path,
    version: Option<&str>,
    current_php: PhpVersion,
    target_php: PhpVersion,
) -> Vec<MigrationFinding> {
    if target_php <= current_php || target_php < PhpVersion::Php81 {
        return Vec::new();
    }
    let is_ci3 = version.is_some_and(|v| v.trim_start_matches('v').starts_with('3'))
        || root.join("system/core/CodeIgniter.php").is_file();
    if !is_ci3 {
        return Vec::new();
    }

    let core_rel = PathBuf::from("system/core/CodeIgniter.php");
    let core_disk = root.join(&core_rel);
    let Ok(raw) = fs::read_to_string(&core_disk) else {
        return Vec::new();
    };
    let end = raw
        .find('\n')
        .unwrap_or(raw.len())
        .min(raw.len());
    let clean_end = raw[..end].trim_end_matches('\r').len();
    if clean_end == 0 {
        return Vec::new();
    }

    let span = span_from_bytes(&raw, 0, clean_end);
    vec![build_framework_finding(
        &core_rel,
        &raw,
        "CI3-PHP8-COMPAT",
        target_php,
        DecisionBucket::RedBlocker,
        RuleCategory::FrameworkUpgrade,
        span,
        format!(
            "CodeIgniter 3{} presenta múltiples incompatibilidades estructurales en PHP {target_php} (propiedades dinámicas en CI_Controller/CI_Loader, firmas y funciones internas deprecadas).",
            version.map(|v| format!(" ({v})")).unwrap_or_default()
        ),
        "Se recomienda actualizar a CodeIgniter 4 o aplicar los parches del núcleo necesarios antes de ejecutar en PHP 8.2+.".to_string(),
    )]
}

fn evaluate_symfony(
    root: &Path,
    version: Option<&str>,
    current_php: PhpVersion,
    target_php: PhpVersion,
) -> Vec<MigrationFinding> {
    if target_php <= current_php || target_php < PhpVersion::Php82 {
        return Vec::new();
    }
    let composer_path = root.join("composer.json");
    let Ok(raw) = fs::read_to_string(&composer_path) else {
        return Vec::new();
    };

    let major = version
        .and_then(|v| {
            v.trim_start_matches(|c: char| !c.is_ascii_digit())
                .split('.')
                .next()
                .and_then(|s| s.parse::<u32>().ok())
        })
        .unwrap_or(0);

    if major == 0 || major >= 6 {
        return Vec::new();
    }

    let needle = "\"symfony/framework-bundle\"";
    let Some(pos) = raw.find(needle) else {
        return Vec::new();
    };
    let line_start = raw[..pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let line_end = raw[pos..]
        .find('\n')
        .map(|p| pos + p)
        .unwrap_or(raw.len());
    let clean_end = line_start + raw[line_start..line_end].trim_end_matches('\r').len();
    if clean_end <= line_start {
        return Vec::new();
    }

    let span = span_from_bytes(&raw, line_start, clean_end);
    vec![build_framework_finding(
        &PathBuf::from("composer.json"),
        &raw,
        "SYMFONY-VERSION-UPGRADE",
        target_php,
        DecisionBucket::YellowNeedsDecision,
        RuleCategory::FrameworkUpgrade,
        span,
        format!(
            "Symfony ({}) requiere actualización a Symfony 6.4 LTS o 7.x para compatibilidad completa con PHP {target_php}.",
            version.unwrap_or("legacy")
        ),
        "Consulta las guías oficiales `UPGRADE-*.md` de Symfony y actualiza paquetes `symfony/*` de forma coordinada.".to_string(),
    )]
}

fn build_framework_finding(
    file: &Path,
    source: &str,
    rule_id: &str,
    target_step: PhpVersion,
    bucket: DecisionBucket,
    category: RuleCategory,
    span: crate::models::Span,
    explanation: String,
    logic_impact: String,
) -> MigrationFinding {
    let original_code = source[span.start_byte..span.end_byte].to_string();
    let hash_input = format!(
        "{}:{}:{}:{}",
        file.to_string_lossy(),
        rule_id,
        span.start_byte,
        span.end_byte
    );
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in hash_input.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }

    MigrationFinding {
        id: format!("{rule_id}-{hash:08x}"),
        rule_id: rule_id.to_string(),
        target_step,
        bucket,
        category,
        file: file.to_path_buf(),
        span,
        original_code,
        suggested_replacement: None,
        explanation,
        logic_impact,
        status: ResolutionStatus::Pending,
    }
}
