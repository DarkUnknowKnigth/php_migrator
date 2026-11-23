use php_migrator::ai::{
    build_context_snippet, builtin_catalog, condense_context_for_finding, estimate_tokens,
    find_provider, redact_secrets, render_token_help_for_provider, AiPatternCache,
};
use php_migrator::graph::export_mermaid_markdown;
use php_migrator::models::{
    AiResolution, DbEngine, DbIsolationMode, DecisionBucket, DependencySource, FrameworkKind,
    MigrationFinding, PhpVersion, ResolutionStatus, RuleCategory, SecurityCategory, Severity, Span,
};
use php_migrator::patcher::apply_green_fixes_for_module;
use php_migrator::reporter::{write_analysis_artifacts, write_post_migration_test_guide};
use php_migrator::sandbox::{generate_docker_compose, write_sandbox_files, SandboxConfig};
use php_migrator::scanner::scan_project;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
fn test_full_vanilla_php74_to_85_pipeline_and_surgical_patching() {
    let temp = tempdir().expect("crear directorio temporal");
    let root = temp.path();

    fs::create_dir_all(root.join("includes")).expect("crear carpeta includes");

    let db_php = r#"<?php
$db_host = 'localhost';
$db_pass = 'SuperSecretDB!2024';
function legacy_fetch($sql) {
    return mysql_query($sql);
}
"#;
    fs::write(root.join("includes/db.php"), db_php).expect("escribir includes/db.php");

    let phpmailer_php = r#"<?php
class PHPMailer {
    const VERSION = '6.1.7';
}
"#;
    fs::write(root.join("includes/PHPMailer.php"), phpmailer_php)
        .expect("escribir includes/PHPMailer.php");

    let helpers_php = r#"<?php
require_once __DIR__ . '/db.php';

class User {}

function findUser(User $u = null, $rawId = '10', $text = 'hola', $str = 'abc') {
    $id = (integer)$rawId;
    $first = $str{0};
    $utf = utf8_encode($text);
    return [$u, $id, $first, $utf];
}
"#;
    fs::write(root.join("includes/helpers.php"), helpers_php)
        .expect("escribir includes/helpers.php");

    let html_head = "<!DOCTYPE html>\n<html lang=\"es\">\n<head>\n<meta charset=\"utf-8\">\n<style>\n  body { font-family: sans-serif; color: #222; }\n  .card { border: 1px solid #ccc; /* 0 == \"texto\" en comentario CSS no debe tocarse */ }\n</style>\n<script>\n  const castTest = \"(integer) ${noTocar} utf8_encode('x')\";\n  if (0 == \"texto\") { console.log(\"JS intacto\"); }\n</script>\n</head>\n<body>\n";
    let php_body = r#"<?php
require_once 'includes/helpers.php';
$role = $_GET['role'] ?? 'guest';
$uid = (integer)$_GET['id'];
if ($role == 0) {
    echo "Invitado";
}
if (isset($_POST['cmd'])) {
    eval($_POST['cmd']);
}
?>"#;
    let html_tail = "\n<div class=\"card\">Panel Legacy</div>\n</body>\n</html>\n";
    let index_php = format!("{html_head}{php_body}{html_tail}");
    fs::write(root.join("index.php"), &index_php).expect("escribir index.php");

    // 1. Ejecutar escaneo completo 7.4 -> 8.5 (0% IA)
    let mut scan = scan_project(root, PhpVersion::Php85).expect("scan_project exitoso");

    assert_eq!(scan.analysis.detected_php_version, PhpVersion::Php74);
    assert_eq!(scan.analysis.target_php_version, PhpVersion::Php85);
    assert_eq!(scan.analysis.framework, FrameworkKind::VanillaPhp);
    assert!(
        scan.analysis
            .include_dirs
            .iter()
            .any(|d| d.to_string_lossy().replace('\\', "/").ends_with("includes")),
        "Debe detectar carpeta includes/"
    );

    let phpmailer_dep = scan
        .analysis
        .dependencies
        .iter()
        .find(|d| d.name == "PHPMailer")
        .expect("Debe detectar librería embebida PHPMailer");
    assert_eq!(phpmailer_dep.detected_version.as_deref(), Some("6.1.7"));
    assert_eq!(phpmailer_dep.source, DependencySource::BundledFolder);

    // 2. Verificar Radar PHP2Shell
    assert!(
        scan.analysis.security_findings.iter().any(|s| {
            s.category == SecurityCategory::RemoteCodeExecution
                && s.severity == Severity::Critical
                && s.file.to_string_lossy().ends_with("index.php")
        }),
        "Debe detectar eval($_POST['cmd']) como RCE Crítico"
    );

    // 3. Verificar Grafo de Lógica y Mermaid
    let has_index_to_helpers = scan.logic_graph.edges.iter().any(|e| {
        e.from.to_string_lossy().replace('\\', "/").ends_with("index.php")
            && e.to
                .as_ref()
                .map(|p| p.to_string_lossy().replace('\\', "/").ends_with("includes/helpers.php"))
                .unwrap_or(false)
    });
    let has_helpers_to_db = scan.logic_graph.edges.iter().any(|e| {
        e.from.to_string_lossy().replace('\\', "/").ends_with("includes/helpers.php")
            && e.to
                .as_ref()
                .map(|p| p.to_string_lossy().replace('\\', "/").ends_with("includes/db.php"))
                .unwrap_or(false)
    });
    assert!(has_index_to_helpers, "Arista index.php -> includes/helpers.php");
    assert!(has_helpers_to_db, "Arista includes/helpers.php -> includes/db.php");

    let mermaid_md = export_mermaid_markdown(&scan.logic_graph);
    assert!(mermaid_md.contains("flowchart LR"));

    // 4. Verificar clasificación Verde / Amarillo / Rojo en 7.4 -> 8.5
    let rule_ids: Vec<&str> = scan
        .analysis
        .migration_findings
        .iter()
        .map(|f| f.rule_id.as_str())
        .collect();
    assert!(
        scan.analysis
            .migration_findings
            .iter()
            .any(|f| f.bucket == DecisionBucket::GreenAutoFix && f.original_code.contains("{0}")),
        "Debe detectar $str{{0}} como GreenAutoFix; reglas encontradas: {:?}",
        rule_ids
    );
    assert!(
        scan.analysis
            .migration_findings
            .iter()
            .any(|f| f.bucket == DecisionBucket::GreenAutoFix && f.original_code.contains("utf8_encode")),
        "Debe detectar utf8_encode como GreenAutoFix; reglas: {:?}",
        rule_ids
    );
    assert!(
        scan.analysis
            .migration_findings
            .iter()
            .any(|f| f.bucket == DecisionBucket::GreenAutoFix && f.target_step == PhpVersion::Php84),
        "Debe detectar parámetro implícitamente nulo en PHP 8.4; reglas: {:?}",
        rule_ids
    );
    assert!(
        scan.analysis
            .migration_findings
            .iter()
            .any(|f| f.bucket == DecisionBucket::GreenAutoFix && f.original_code == "(integer)"),
        "Debe detectar cast (integer) de PHP 8.5; reglas: {:?}",
        rule_ids
    );
    assert!(
        scan.analysis
            .migration_findings
            .iter()
            .any(|f| f.bucket == DecisionBucket::YellowNeedsDecision && f.original_code.contains("== 0")),
        "Debe detectar comparación débil == 0 como YellowNeedsDecision; reglas: {:?}",
        rule_ids
    );
    assert!(
        scan.analysis
            .migration_findings
            .iter()
            .any(|f| f.bucket == DecisionBucket::RedBlocker && f.original_code.contains("mysql_query")),
        "Debe detectar mysql_query como RedBlocker; reglas: {:?}",
        rule_ids
    );

    // 5. Aplicar parcheo quirúrgico GreenAutoFix y validar preservación de HTML/CSS/JS
    let all_files: Vec<PathBuf> = scan
        .analysis
        .modules
        .iter()
        .flat_map(|m| m.files.iter().cloned())
        .collect();
    let diffs = apply_green_fixes_for_module(root, &mut scan.analysis.migration_findings, &all_files)
        .expect("apply_green_fixes_for_module exitoso");
    assert!(!diffs.is_empty(), "Debe haber archivos parcheados");
    assert!(
        diffs.iter().all(|d| d.backup_path.as_ref().map(|p| p.is_file()).unwrap_or(false)),
        "Cada archivo parcheado debe generar respaldo en .php-migrator/backups"
    );

    let patched_helpers =
        fs::read_to_string(root.join("includes/helpers.php")).expect("leer helpers parcheado");
    assert!(patched_helpers.contains("?User $u = null"), "helpers.php: {patched_helpers}");
    assert!(patched_helpers.contains("(int)$rawId"), "helpers.php: {patched_helpers}");
    assert!(patched_helpers.contains("$str[0]"), "helpers.php: {patched_helpers}");
    assert!(
        patched_helpers.contains("mb_convert_encoding($text, 'UTF-8', 'ISO-8859-1')"),
        "helpers.php: {patched_helpers}"
    );

    let patched_index = fs::read_to_string(root.join("index.php")).expect("leer index parcheado");
    assert!(
        patched_index.starts_with(html_head),
        "El bloque HTML, <style> y <script> inicial debe quedar 100% intacto byte por byte"
    );
    assert!(
        patched_index.ends_with(html_tail),
        "El bloque HTML final debe quedar 100% intacto byte por byte"
    );
    assert!(patched_index.contains("(int)$_GET['id']"), "index.php: {patched_index}");

    // Verificar que los hallazgos Green aplicados actualizaron su estado
    assert!(
        scan.analysis
            .migration_findings
            .iter()
            .filter(|f| f.bucket == DecisionBucket::GreenAutoFix)
            .all(|f| f.status == ResolutionStatus::AppliedDeterministic)
    );

    // 6. Verificar generación de artefactos de reporte
    let (rep_p, map_p, json_p) =
        write_analysis_artifacts(&root.join(".php-migrator"), &scan.analysis, &scan.logic_graph)
            .expect("escribir artefactos");
    assert!(rep_p.is_file() && map_p.is_file() && json_p.is_file());
}

#[test]
fn test_byok_ai_catalog_and_secret_redaction() {
    let catalog = builtin_catalog();
    assert_eq!(catalog.len(), 9, "El catálogo BYOK debe exponer 9 proveedores");
    for expected in [
        "gemini",
        "anthropic",
        "openai",
        "deepseek",
        "openrouter",
        "groq",
        "xai",
        "ollama",
        "custom",
    ] {
        assert!(find_provider(expected).is_some(), "Falta proveedor {expected}");
    }

    let sensitive = r#"
$db_pass = "SuperSecret123!";
$token = 'sk-abc1234567890SECRETKEY999';
DB_PASSWORD=my_prod_pwd
$g = "AIzaSyD1234567890abcdef123456";
"#;
    let sanitized = redact_secrets(sensitive);
    assert!(!sanitized.contains("SuperSecret123!"));
    assert!(!sanitized.contains("sk-abc1234567890SECRETKEY999"));
    assert!(!sanitized.contains("my_prod_pwd"));
    assert!(!sanitized.contains("AIzaSyD1234567890abcdef123456"));
    assert!(sanitized.contains("[REDACTED]"));
}

#[test]
fn test_sandbox_dual_database_compose_generation() {
    let temp = tempdir().expect("crear dir temporal");
    let root = temp.path();
    let dump = root.join("schema.sql");
    fs::write(&dump, "CREATE TABLE users (id INT PRIMARY KEY);\n").expect("escribir dump sql");

    let cfg = SandboxConfig {
        project_root: root.to_path_buf(),
        source_php: PhpVersion::Php74,
        target_php: PhpVersion::Php85,
        db_mode: DbIsolationMode::SqlDumpClone {
            dump_path: dump,
            engine: DbEngine::MySql,
        },
        routes_to_test: vec!["/index.php".to_string()],
        source_port: 18074,
        target_port: 18085,
    };

    let yml = generate_docker_compose(&cfg);
    assert!(yml.contains("php:7.4-apache"));
    assert!(yml.contains("php:8.5-apache"));
    assert!(yml.contains("db_source"));
    assert!(yml.contains("db_target"));
    assert!(yml.contains("/docker-entrypoint-initdb.d/init.sql"));

    let compose_path = write_sandbox_files(&cfg).expect("escribir compose");
    assert!(compose_path.is_file());
}

#[test]
fn test_oracle_oci8_db_interactions_and_extension_detection() {
    let temp = tempdir().expect("crear dir temporal");
    let root = temp.path();
    fs::create_dir_all(root.join("includes")).expect("crear includes");

    let oracle_php = r#"<?php
$conn = oci_connect('TEST_USER', 'dummy', 'localhost/orcl', 'AL32UTF8');
$st = oci_parse($conn, 'SELECT 1 FROM DUAL');
oci_execute($st);
"#;
    fs::write(root.join("includes/oracle.php"), oracle_php).expect("escribir oracle.php");

    let scan = scan_project(root, PhpVersion::Php85).expect("scan_project exitoso");
    assert!(
        scan.analysis
            .dependencies
            .iter()
            .any(|d| d.name == "ext-oci8" && d.target_compatible == Some(false)),
        "Debe detectar ext-oci8 como extensión PECL en 8.4+"
    );
    let includes_mod = scan
        .analysis
        .modules
        .iter()
        .find(|m| m.id == "includes")
        .expect("módulo includes presente");
    assert_eq!(
        includes_mod.db_ops_count, 3,
        "Debe contabilizar oci_connect, oci_parse y oci_execute en db_ops_count"
    );

    let pecl_findings: Vec<_> = scan
        .analysis
        .migration_findings
        .iter()
        .filter(|f| f.rule_id == "PHP84-PECL-EXTENSION")
        .collect();
    assert_eq!(
        pecl_findings.len(),
        1,
        "Solo la apertura oci_connect debe generar aviso PECL, no cada consulta oci_parse/oci_execute"
    );

    let guide_path = write_post_migration_test_guide(
        &root.join(".php-migrator"),
        &scan.analysis,
        &[],
        Some(("main", "migration/php-8.5")),
    )
    .expect("escribir guía post-migración");
    let guide_text = fs::read_to_string(&guide_path).expect("leer guía");
    assert!(guide_text.contains("No se ejecutaron consultas SQL"));
    assert!(guide_text.contains("ext-oci8"));
    assert!(guide_text.contains("includes/oracle.php"));
    assert!(guide_text.contains("migration/php-8.5"));
    assert!(guide_text.contains("git merge migration/php-8.5"));
}

#[test]
fn test_markdown_token_help_guide_for_providers() {
    let full = render_token_help_for_provider(None);
    assert!(full.contains("https://aistudio.google.com/app/apikey"));
    assert!(full.contains("https://platform.openai.com/api-keys"));
    assert!(full.contains("https://console.anthropic.com/settings/keys"));
    assert!(full.contains("https://ollama.com/download"));

    let gemini_only = render_token_help_for_provider(Some("gemini"));
    assert!(gemini_only.contains("Google Gemini"));
    assert!(gemini_only.contains("GEMINI_API_KEY"));
    assert!(!gemini_only.contains("OPENAI_API_KEY"));
}

#[test]
fn test_token_optimizer_condenser_cache_and_compact_toon() {
    let temp = tempdir().expect("crear dir temporal");
    let root = temp.path();

    let mut php_lines = vec![
        "<?php".to_string(),
        "/*".to_string(),
        " * Bloque de documentación muy largo que no debe gastarse en tokens de IA".to_string(),
        " * Copyright legacy system 2015-2024 - comentarios extensos".to_string(),
        " */".to_string(),
    ];
    for i in 1..=12 {
        php_lines.push(format!("// Comentario innecesario línea {i}"));
        php_lines.push(format!("    $padding_{i} = {i};"));
        php_lines.push(String::new());
    }
    php_lines.push("    $db_pass = 'SecretaProd99'; // clave que debe redactarse".to_string());
    php_lines.push("    $ok = helper_used($input);".to_string());
    php_lines.push("    if ($role == 0) { return true; }".to_string());
    for i in 13..=25 {
        php_lines.push(format!("// Otro comentario extenso {i}"));
        php_lines.push(format!("    $tail_{i} = {i};"));
    }
    let php_source = php_lines.join("\n");
    fs::write(root.join("sample.php"), &php_source).expect("escribir sample.php");

    let target_line_no = php_lines
        .iter()
        .position(|l| l.contains("$role == 0"))
        .expect("línea target")
        + 1;

    let finding = MigrationFinding {
        id: "M-OPT-1".to_string(),
        rule_id: "PHP80-LOOSE-COMPARISON".to_string(),
        target_step: PhpVersion::Php80,
        bucket: DecisionBucket::YellowNeedsDecision,
        category: RuleCategory::LooseComparisonRisk,
        file: PathBuf::from("sample.php"),
        span: Span {
            start_byte: 0,
            end_byte: 10,
            start_line: target_line_no,
            start_col: 1,
            end_line: target_line_no,
            end_col: 10,
        },
        original_code: "$role == 0".to_string(),
        suggested_replacement: Some("(string)$role === '0'".to_string()),
        explanation: "Comparación débil".to_string(),
        logic_impact: "0 == '' cambió en PHP 8.0".to_string(),
        status: ResolutionStatus::Pending,
    };

    let sigs = vec![
        "function helper_used($x)".to_string(),
        "function unused_other_function_1($a, $b, $c)".to_string(),
        "function unused_other_function_2($d, $e, $f)".to_string(),
    ];

    let raw_ctx = build_context_snippet(&php_source, &finding, &sigs);
    let condensed_ctx = condense_context_for_finding(&php_source, &finding, &sigs);

    assert!(!condensed_ctx.contains("SecretaProd99"));
    assert!(!condensed_ctx.contains("Comentario innecesario"));
    assert!(!condensed_ctx.contains("unused_other_function_1"));
    assert!(condensed_ctx.contains("helper_used"));
    assert!(
        estimate_tokens(&condensed_ctx) < estimate_tokens(&raw_ctx),
        "El contexto condensado ({}) debe usar menos tokens que el crudo ({})",
        estimate_tokens(&condensed_ctx),
        estimate_tokens(&raw_ctx)
    );

    // Verificar caché persistente por huella
    let cache_path = root.join(".php-migrator/ai-cache.json");
    let mut cache = AiPatternCache::load_or_new(&cache_path);
    assert!(cache.get(&finding).is_none());
    cache.insert(
        &finding,
        AiResolution {
            replacement_code: "$role === 0".to_string(),
            explanation: "Comparación estricta".to_string(),
            logic_safety_notes: "Tipo entero esperado".to_string(),
        },
    );
    cache.save().expect("guardar caché");

    let reloaded = AiPatternCache::load_or_new(&cache_path);
    let hit = reloaded.get(&finding).expect("debe recuperar caché");
    assert_eq!(hit.replacement_code, "$role === 0");

    // Verificar generación de analysis-compact.toon drásticamente más pequeña que analysis.json
    let scan = scan_project(root, PhpVersion::Php85).expect("scan_project exitoso");
    let out_dir = root.join(".php-migrator");
    let (_rep, _map, json_path) =
        write_analysis_artifacts(&out_dir, &scan.analysis, &scan.logic_graph)
            .expect("escribir artefactos");
    let toon_path = out_dir.join("analysis-compact.toon");
    assert!(toon_path.is_file(), "Debe generar analysis-compact.toon");
    let json_text = fs::read_to_string(&json_path).expect("leer analysis.json");
    let toon_text = fs::read_to_string(&toon_path).expect("leer analysis-compact.toon");
    assert!(toon_text.contains("META|"));
    assert!(
        estimate_tokens(&toon_text) < estimate_tokens(&json_text),
        "analysis-compact.toon ({} tok) debe ser más compacto que analysis.json ({} tok)",
        estimate_tokens(&toon_text),
        estimate_tokens(&json_text)
    );
}


