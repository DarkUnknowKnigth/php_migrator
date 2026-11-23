use super::docker::{check_docker_available, write_sandbox_files, SandboxConfig};
use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::process::Command;

/// Resultado comparativo entre el contenedor origen y el contenedor destino para una ruta HTTP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteComparison {
    pub route: String,
    pub source_status: u16,
    pub target_status: u16,
    pub body_matches_normalized: bool,
    pub diff_summary: String,
    pub source_errors: Vec<String>,
    pub target_errors: Vec<String>,
}

/// Reporte consolidado de la verificación dual en el sandbox Docker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    pub compose_path: PathBuf,
    pub lint_passed: bool,
    pub lint_errors: Vec<String>,
    pub comparisons: Vec<RouteComparison>,
}

struct BodyNormalizers {
    iso_datetime: Regex,
    iso_date: Regex,
    phpsessid_kv: Regex,
    phpsessid_input: Regex,
    csrf_input_nv: Regex,
    csrf_input_vn: Regex,
    csrf_meta: Regex,
    csrf_json: Regex,
    inter_tag_ws: Regex,
    whitespace: Regex,
    php_error_line: Regex,
}

fn normalizers() -> &'static BodyNormalizers {
    static NORM: OnceLock<BodyNormalizers> = OnceLock::new();
    NORM.get_or_init(|| BodyNormalizers {
        iso_datetime: Regex::new(
            r"\b\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
        )
        .expect("regex iso_datetime válida"),
        iso_date: Regex::new(r"\b\d{4}-\d{2}-\d{2}\b").expect("regex iso_date válida"),
        phpsessid_kv: Regex::new(r"(?i)\bPHPSESSID=[A-Za-z0-9,-]+")
            .expect("regex phpsessid_kv válida"),
        phpsessid_input: Regex::new(
            r#"(?i)(<input\b[^>]*\bname\s*=\s*["']PHPSESSID["'][^>]*\bvalue\s*=\s*["'])[^"']*(["'])"#,
        )
        .expect("regex phpsessid_input válida"),
        csrf_input_nv: Regex::new(
            r#"(?i)(<input\b[^>]*\bname\s*=\s*["'](?:_?csrf(?:_?token)?|_token|csrfmiddlewaretoken|__RequestVerificationToken)["'][^>]*\bvalue\s*=\s*["'])[^"']*(["'])"#,
        )
        .expect("regex csrf_input_nv válida"),
        csrf_input_vn: Regex::new(
            r#"(?i)(<input\b[^>]*\bvalue\s*=\s*["'])[^"']*(["'][^>]*\bname\s*=\s*["'](?:_?csrf(?:_?token)?|_token|csrfmiddlewaretoken|__RequestVerificationToken)["'])"#,
        )
        .expect("regex csrf_input_vn válida"),
        csrf_meta: Regex::new(
            r#"(?i)(<meta\b[^>]*\bname\s*=\s*["']csrf-token["'][^>]*\bcontent\s*=\s*["'])[^"']*(["'])"#,
        )
        .expect("regex csrf_meta válida"),
        csrf_json: Regex::new(
            r#"(?i)(["'](?:_?csrf_?token|_token)["']\s*:\s*["'])[^"']*(["'])"#,
        )
        .expect("regex csrf_json válida"),
        inter_tag_ws: Regex::new(r">\s+<").expect("regex inter_tag_ws válida"),
        whitespace: Regex::new(r"\s+").expect("regex whitespace válida"),
        php_error_line: Regex::new(
            r"(?i)\b(?:Fatal error|Parse error|TypeError|Uncaught\s+\w*Error|PHP\s+Warning|Warning:|PHP\s+Deprecated|Deprecated:)\b",
        )
        .expect("regex php_error_line válida"),
    })
}

/// Normaliza fechas/timestamps ISO, identificadores `PHPSESSID`, tokens CSRF comunes
/// y espacios repetidos para realizar una comparación justa entre origen y destino.
pub fn normalize_http_body(body: &str) -> String {
    let n = normalizers();

    let out = n.iso_datetime.replace_all(body, "[TIMESTAMP]");
    let out = n.iso_date.replace_all(&out, "[DATE]");
    let out = n.phpsessid_kv.replace_all(&out, "PHPSESSID=[SESSION_ID]");
    let out = n
        .phpsessid_input
        .replace_all(&out, "${1}[SESSION_ID]${2}");
    let out = n.csrf_input_nv.replace_all(&out, "${1}[CSRF_TOKEN]${2}");
    let out = n.csrf_input_vn.replace_all(&out, "${1}[CSRF_TOKEN]${2}");
    let out = n.csrf_meta.replace_all(&out, "${1}[CSRF_TOKEN]${2}");
    let out = n.csrf_json.replace_all(&out, "${1}[CSRF_TOKEN]${2}");
    let out = n.inter_tag_ws.replace_all(&out, "><");
    let out = n.whitespace.replace_all(&out, " ");

    out.trim().to_string()
}

fn extract_php_error_lines(text: &str) -> Vec<String> {
    let re = &normalizers().php_error_line;
    let mut seen = HashSet::new();
    let mut errors = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && re.is_match(trimmed) && seen.insert(trimmed.to_string()) {
            errors.push(trimmed.to_string());
        }
    }
    errors
}

fn normalize_route(route: &str) -> String {
    let trimmed = route.trim();
    if trimmed.is_empty() {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn safe_preview(s: &str, start_char: usize, max_chars: usize) -> String {
    s.chars().skip(start_char).take(max_chars).collect()
}

fn summarize_diff(
    source_status: u16,
    target_status: u16,
    norm_src: &str,
    norm_tgt: &str,
) -> String {
    if source_status == target_status && norm_src == norm_tgt {
        return "Coincidencia exacta tras normalización.".to_string();
    }

    let mut parts = Vec::new();
    if source_status != target_status {
        parts.push(format!(
            "HTTP status distinto (origen={source_status}, destino={target_status})"
        ));
    }

    if norm_src != norm_tgt {
        let mismatch_idx = norm_src
            .chars()
            .zip(norm_tgt.chars())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| norm_src.chars().count().min(norm_tgt.chars().count()));

        let ctx_start = mismatch_idx.saturating_sub(20);
        let src_excerpt = safe_preview(norm_src, ctx_start, 80);
        let tgt_excerpt = safe_preview(norm_tgt, ctx_start, 80);
        parts.push(format!(
            "Cuerpo difiere en carácter {mismatch_idx}: origen='{src_excerpt}' vs destino='{tgt_excerpt}'"
        ));
    }

    parts.join("; ")
}

async fn run_compose(compose_path: &Path, args: &[&str]) -> Result<std::process::Output> {
    Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_path)
        .args(args)
        .output()
        .await
        .with_context(|| format!("Error ejecutando `docker compose {}`", args.join(" ")))
}

async fn teardown_compose(compose_path: &Path) -> Result<()> {
    let out = run_compose(compose_path, &["down", "-v"]).await?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("`docker compose down -v` falló: {}", stderr.trim());
    }
    Ok(())
}

async fn wait_for_http_ready(client: &reqwest::Client, port: u16) -> Result<()> {
    let url = format!("http://127.0.0.1:{port}/");
    for _ in 0..20 {
        if client.get(&url).send().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::bail!("Tiempo de espera agotado esperando respuesta HTTP en {url}")
}

async fn run_target_php_lint(compose_path: &Path) -> Result<(bool, Vec<String>)> {
    let lint_cmd = concat!(
        "find /var/www/html -type f -name '*.php' ",
        "! -path '*/.git/*' ! -path '*/.php-migrator/*' ",
        "-exec sh -c '",
        "status=0; ",
        "for f do ",
        "out=$(php -l \"$f\" 2>&1) || { printf \"%s\\n\" \"$out\"; status=1; }; ",
        "done; ",
        "exit $status' sh {} +"
    );

    let output = run_compose(compose_path, &["exec", "-T", "php_target", "sh", "-c", lint_cmd])
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let mut errors = Vec::new();
    for line in stdout.lines().chain(stderr.lines()) {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with("No syntax errors detected") {
            errors.push(trimmed.to_string());
        }
    }

    let passed = output.status.success() && errors.is_empty();
    Ok((passed, errors))
}

async fn collect_new_service_errors(
    compose_path: &Path,
    service: &str,
    seen_logs: &mut HashSet<String>,
) -> Vec<String> {
    let Ok(output) = run_compose(compose_path, &["logs", "--no-color", "--tail=200", service]).await
    else {
        return Vec::new();
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut new_errors = Vec::new();

    for line in stdout.lines().chain(stderr.lines()) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen_logs.insert(trimmed.to_string())
            && normalizers().php_error_line.is_match(trimmed)
        {
            new_errors.push(trimmed.to_string());
        }
    }

    new_errors
}

async fn seed_existing_logs(compose_path: &Path, service: &str) -> HashSet<String> {
    let mut seen = HashSet::new();
    if let Ok(output) =
        run_compose(compose_path, &["logs", "--no-color", "--tail=200", service]).await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for line in stdout.lines().chain(stderr.lines()) {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                seen.insert(trimmed.to_string());
            }
        }
    }
    seen
}

async fn fetch_route(client: &reqwest::Client, port: u16, route: &str) -> (u16, String, Vec<String>) {
    let url = format!("http://127.0.0.1:{port}{route}");
    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            match resp.text().await {
                Ok(body) => {
                    let errors = extract_php_error_lines(&body);
                    (status, body, errors)
                }
                Err(err) => (
                    status,
                    String::new(),
                    vec![format!("Error leyendo respuesta HTTP de {url}: {err}")],
                ),
            }
        }
        Err(err) => (
            0,
            String::new(),
            vec![format!("Error de conexión consultando {url}: {err}")],
        ),
    }
}

async fn execute_verification_steps(
    config: &SandboxConfig,
    compose_path: &Path,
) -> Result<(bool, Vec<String>, Vec<RouteComparison>)> {
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .context("No se pudo construir el cliente HTTP para el sandbox")?;

    wait_for_http_ready(&http_client, config.source_port).await?;
    wait_for_http_ready(&http_client, config.target_port).await?;

    let (lint_passed, lint_errors) = run_target_php_lint(compose_path).await?;

    let mut seen_src_logs = seed_existing_logs(compose_path, "php_source").await;
    let mut seen_tgt_logs = seed_existing_logs(compose_path, "php_target").await;
    let mut comparisons = Vec::with_capacity(config.routes_to_test.len());

    for raw_route in &config.routes_to_test {
        let route = normalize_route(raw_route);

        let ((src_status, src_body, mut src_errors), (tgt_status, tgt_body, mut tgt_errors)) =
            tokio::join!(
                fetch_route(&http_client, config.source_port, &route),
                fetch_route(&http_client, config.target_port, &route),
            );

        let src_log_errs =
            collect_new_service_errors(compose_path, "php_source", &mut seen_src_logs).await;
        let tgt_log_errs =
            collect_new_service_errors(compose_path, "php_target", &mut seen_tgt_logs).await;

        for err in src_log_errs {
            if !src_errors.contains(&err) {
                src_errors.push(err);
            }
        }
        for err in tgt_log_errs {
            if !tgt_errors.contains(&err) {
                tgt_errors.push(err);
            }
        }

        let norm_src = normalize_http_body(&src_body);
        let norm_tgt = normalize_http_body(&tgt_body);
        let body_matches_normalized = norm_src == norm_tgt;
        let diff_summary = summarize_diff(src_status, tgt_status, &norm_src, &norm_tgt);

        comparisons.push(RouteComparison {
            route,
            source_status: src_status,
            target_status: tgt_status,
            body_matches_normalized,
            diff_summary,
            source_errors: src_errors,
            target_errors: tgt_errors,
        });
    }

    Ok((lint_passed, lint_errors, comparisons))
}

/// Ejecuta la verificación dual en contenedores Docker (`php_source` vs `php_target`),
/// validando autorización explícita previa, sintaxis `php -l`, rutas HTTP y limpieza final.
pub async fn run_dual_verification(
    config: &SandboxConfig,
    user_authorized: bool,
) -> Result<SandboxReport> {
    if !user_authorized {
        return Err(anyhow::anyhow!(
            "Ejecución cancelada: el sandbox Docker requiere autorización explícita del usuario."
        ));
    }

    if !check_docker_available().await {
        return Err(anyhow::anyhow!(
            "Docker no está disponible o el daemon no está en ejecución."
        ));
    }

    let compose_path = write_sandbox_files(config)?;

    let up_output = run_compose(&compose_path, &["up", "-d"]).await?;
    if !up_output.status.success() {
        let stderr = String::from_utf8_lossy(&up_output.stderr);
        let _ = teardown_compose(&compose_path).await;
        anyhow::bail!(
            "No se pudieron iniciar los contenedores del sandbox: {}",
            stderr.trim()
        );
    }

    let verify_result = execute_verification_steps(config, &compose_path).await;
    let teardown_result = teardown_compose(&compose_path).await;

    let (lint_passed, lint_errors, comparisons) = verify_result?;
    teardown_result?;

    Ok(SandboxReport {
        compose_path,
        lint_passed,
        lint_errors,
        comparisons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DbIsolationMode, PhpVersion};

    #[test]
    fn normalizes_timestamps_sessions_csrf_and_whitespace() {
        let a = r#"
            <html>
              <body>
                <p>Fecha: 2026-11-23T04:34:44Z   y  2026-11-23</p>
                <a href="/home?PHPSESSID=abc123def456">Ir</a>
                <input type="hidden" name="_token" value="tok_aaa111">
              </body>
            </html>
        "#;
        let b = r#"
            <html><body>
              <p>Fecha: 2026-12-01T18:10:00+00:00 y 2026-12-01</p>
              <a href="/home?PHPSESSID=zzz999yyy888">Ir</a>
              <input type="hidden" name="_token" value="tok_bbb222">
            </body></html>
        "#;

        assert_eq!(normalize_http_body(a), normalize_http_body(b));
    }

    #[tokio::test]
    async fn rejects_execution_without_user_authorization() {
        let cfg = SandboxConfig {
            project_root: PathBuf::from("."),
            source_php: PhpVersion::Php74,
            target_php: PhpVersion::Php85,
            db_mode: DbIsolationMode::NoDatabase,
            routes_to_test: vec!["/".to_string()],
            source_port: 18074,
            target_port: 18085,
        };

        let err = run_dual_verification(&cfg, false)
            .await
            .expect_err("debe fallar si no hay autorización");
        assert!(err.to_string().contains("autorización"));
    }
}
