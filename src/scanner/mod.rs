pub mod fingerprint;
pub mod security;

use crate::models::{FileSummary, MigrationFinding, PhpVersion, ProjectAnalysis, SecurityFinding};
use anyhow::{bail, Result};
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Resultado completo del escaneo del proyecto incluyendo AST por archivo y grafo lógico.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub analysis: ProjectAnalysis,
    pub file_summaries: Vec<FileSummary>,
    pub logic_graph: crate::graph::LogicGraphReport,
}

/// Recorre el proyecto, detecta stack/dependencias y ejecuta auditoría de seguridad, reglas PHP y grafo lógico.
pub fn scan_project(root: &Path, target: PhpVersion) -> Result<ScanResult> {
    if !root.exists() {
        bail!("La ruta del proyecto '{}' no existe.", root.display());
    }
    if !root.is_dir() {
        bail!(
            "La ruta '{}' no es un directorio válido.",
            root.display()
        );
    }

    let has_composer_vendor = root.join("composer.json").is_file()
        || root.join("composer.lock").is_file()
        || root.join("vendor/composer/installed.json").is_file();

    let mut total_files = 0usize;
    let mut all_rel_files: Vec<PathBuf> = Vec::new();
    let mut php_targets: Vec<PathBuf> = Vec::new();

    let walker = WalkBuilder::new(root)
        .hidden(false)
        .filter_entry(|entry| {
            let Some(name) = entry.file_name().to_str() else {
                return true;
            };
            if entry.file_type().is_some_and(|ft| ft.is_dir()) {
                return !matches!(name, ".git" | ".php-migrator" | "node_modules");
            }
            true
        })
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        total_files += 1;
        let abs_path = entry.path();
        let rel_path = abs_path.strip_prefix(root).unwrap_or(abs_path).to_path_buf();
        all_rel_files.push(rel_path.clone());

        if !is_php_source_file(abs_path) {
            continue;
        }
        if has_composer_vendor && is_inside_vendor(&rel_path) {
            continue;
        }
        php_targets.push(abs_path.to_path_buf());
    }

    all_rel_files.sort();
    php_targets.sort();

    // Parseo paralelo de archivos PHP + HTML mixto
    let mut parsed_pairs: Vec<(FileSummary, String)> = php_targets
        .par_iter()
        .filter_map(|abs_path| {
            let source = read_source_lossy(abs_path)?;
            let summary = crate::parser::parse_file(abs_path, root, &source);
            Some((summary, source))
        })
        .collect();

    parsed_pairs.sort_by(|a, b| a.0.path.cmp(&b.0.path));

    let summaries: Vec<FileSummary> = parsed_pairs.iter().map(|(s, _)| s.clone()).collect();
    let fp = fingerprint::inspect_project_fingerprint(root, &all_rel_files, &summaries);
    let hops = PhpVersion::all_hops_between(fp.detected_php, target);

    // Evaluación paralela de seguridad y reglas de migración
    let per_file_results: Vec<(Vec<SecurityFinding>, Vec<MigrationFinding>)> = parsed_pairs
        .par_iter()
        .map(|(summary, source)| {
            let sec = security::scan_security_file(&summary.path, source, summary);
            let mig = crate::rules::evaluate_file(&summary.path, source, summary, &hops);
            (sec, mig)
        })
        .collect();

    let mut security_findings = Vec::new();
    let mut migration_findings = Vec::new();
    for (mut sec, mut mig) in per_file_results {
        security_findings.append(&mut sec);
        migration_findings.append(&mut mig);
    }

    // Reglas específicas de framework (Laravel, WordPress, CodeIgniter, Symfony)
    let mut framework_findings = crate::frameworks::detect_and_evaluate_framework(
        &fp.framework,
        root,
        fp.detected_php,
        target,
        &fp.dependencies,
        &summaries,
    );
    migration_findings.append(&mut framework_findings);

    security_findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.id.cmp(&b.id))
    });

    migration_findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.span.start_byte.cmp(&b.span.start_byte))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    let logic_graph = crate::graph::build_logic_graph(
        root,
        &summaries,
        &migration_findings,
        &security_findings,
    );

    let php_files_count = summaries.len();
    let mixed_html_files_count = summaries.iter().filter(|s| s.is_mixed_html).count();
    let total_lines = summaries.iter().map(|s| s.total_lines).sum();

    let analysis = ProjectAnalysis {
        root_path: root.to_path_buf(),
        detected_php_version: fp.detected_php,
        version_evidence: fp.version_evidence,
        target_php_version: target,
        framework: fp.framework,
        dependencies: fp.dependencies,
        total_files,
        php_files_count,
        mixed_html_files_count,
        total_lines,
        include_dirs: fp.include_dirs,
        vendor_dirs: fp.vendor_dirs,
        security_findings,
        migration_findings,
        modules: logic_graph.modules.clone(),
    };

    Ok(ScanResult {
        analysis,
        file_summaries: summaries,
        logic_graph,
    })
}

fn is_php_source_file(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "php" | "phtml" | "php5" | "php7" | "inc"
    )
}

fn is_inside_vendor(rel_path: &Path) -> bool {
    rel_path.components().any(|comp| {
        matches!(comp, Component::Normal(part) if part.to_string_lossy().eq_ignore_ascii_case("vendor"))
    })
}

fn read_source_lossy(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
}
