use super::client::redact_secrets;
use crate::models::{AiResolution, MigrationFinding};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Métricas acumuladas del optimizador de tokens durante la sesión de migración.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenOptimizationStats {
    pub raw_chars_without_optimization: usize,
    pub condensed_chars_sent: usize,
    pub api_calls_made: usize,
    pub cache_hits: usize,
    pub batched_findings_resolved: usize,
}

impl TokenOptimizationStats {
    /// Tokens aproximados enviados tras condensación y deduplicación (~4 bytes/token).
    pub fn estimated_tokens_sent(&self) -> usize {
        self.condensed_chars_sent / 4
    }

    /// Tokens aproximados ahorrados frente a consultas sin condensador ni caché.
    pub fn estimated_tokens_saved(&self) -> usize {
        self.raw_chars_without_optimization
            .saturating_sub(self.condensed_chars_sent)
            / 4
    }

    /// Porcentaje de ahorro respecto al escenario sin optimización.
    pub fn savings_percentage(&self) -> f64 {
        if self.raw_chars_without_optimization == 0 {
            return 0.0;
        }
        let saved = self
            .raw_chars_without_optimization
            .saturating_sub(self.condensed_chars_sent) as f64;
        (saved / self.raw_chars_without_optimization as f64) * 100.0
    }
}

/// Estima tokens aproximados a partir de la longitud en bytes (~4 bytes por token).
pub fn estimate_tokens(text: &str) -> usize {
    if text.is_empty() {
        0
    } else {
        (text.len() + 3) / 4
    }
}

/// Elimina comentarios PHP (`/* ... */`, `//`, `#` salvo atributos `#[...]`),
/// colapsa indentación repetida y descarta líneas vacías sin tocar literales de cadena.
pub fn strip_php_comments_and_blank_lines(snippet: &str) -> String {
    let without_blocks = strip_block_comments_preserving_strings(snippet);
    let mut out = Vec::new();

    for raw_line in without_blocks.lines() {
        let cleaned_line = strip_inline_comment_preserving_strings(raw_line);
        let trimmed = cleaned_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let had_indent = cleaned_line.starts_with(' ') || cleaned_line.starts_with('\t');
        if had_indent {
            out.push(format!(" {trimmed}"));
        } else {
            out.push(trimmed.to_string());
        }
    }

    out.join("\n")
}

fn strip_block_comments_preserving_strings(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0usize;
    let mut in_sq = false;
    let mut in_dq = false;

    while i < len {
        let b = bytes[i];
        if in_sq {
            let ch = input[i..].chars().next().unwrap();
            out.push(ch);
            if b == b'\\' && i + 1 < len {
                i += ch.len_utf8();
                let next_ch = input[i..].chars().next().unwrap();
                out.push(next_ch);
                i += next_ch.len_utf8();
                continue;
            }
            if b == b'\'' {
                in_sq = false;
            }
            i += ch.len_utf8();
            continue;
        }
        if in_dq {
            let ch = input[i..].chars().next().unwrap();
            out.push(ch);
            if b == b'\\' && i + 1 < len {
                i += ch.len_utf8();
                let next_ch = input[i..].chars().next().unwrap();
                out.push(next_ch);
                i += next_ch.len_utf8();
                continue;
            }
            if b == b'"' {
                in_dq = false;
            }
            i += ch.len_utf8();
            continue;
        }

        if b == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            if i + 1 < len {
                i += 2;
            } else {
                i = len;
            }
            continue;
        }

        if b == b'\'' {
            in_sq = true;
        } else if b == b'"' {
            in_dq = true;
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn strip_inline_comment_preserving_strings(line: &str) -> String {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut in_sq = false;
    let mut in_dq = false;

    while i < len {
        let b = bytes[i];
        if in_sq {
            if b == b'\\' && i + 1 < len {
                i += 2;
                continue;
            }
            if b == b'\'' {
                in_sq = false;
            }
            i += 1;
            continue;
        }
        if in_dq {
            if b == b'\\' && i + 1 < len {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_dq = false;
            }
            i += 1;
            continue;
        }

        if b == b'\'' {
            in_sq = true;
            i += 1;
            continue;
        }
        if b == b'"' {
            in_dq = true;
            i += 1;
            continue;
        }

        if b == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            return line[..i].to_string();
        }
        // Mantener atributos PHP 8 `#[...]` y solo recortar comentarios `#`
        if b == b'#' && !(i + 1 < len && bytes[i + 1] == b'[') {
            return line[..i].to_string();
        }

        i += 1;
    }

    line.to_string()
}

fn extract_sig_ident(sig: &str) -> Option<&str> {
    let trimmed = sig.trim();
    for prefix in ["function ", "fn ", "class ", "interface ", "trait "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let ident = rest
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '\\')
                .next()
                .unwrap_or("")
                .rsplit('\\')
                .next()
                .unwrap_or("");
            if ident.len() >= 2 {
                return Some(ident);
            }
        }
    }
    trimmed
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .find(|tok| tok.len() >= 3)
}

fn filter_relevant_signatures<'a>(
    related_signatures: &'a [String],
    window_text: &str,
) -> Vec<&'a str> {
    let mut kept = Vec::new();
    for sig in related_signatures {
        if let Some(ident) = extract_sig_ident(sig) {
            if window_text.contains(ident) {
                kept.push(sig.as_str());
                if kept.len() >= 6 {
                    break;
                }
            }
        }
    }
    kept
}

/// Condensa el contexto de un hallazgo (±5 líneas), eliminando comentarios/líneas vacías,
/// filtrando firmas del grafo realmente invocadas y aplicando `redact_secrets`.
pub fn condense_context_for_finding(
    file_content: &str,
    finding: &MigrationFinding,
    related_signatures: &[String],
) -> String {
    let raw_lines: Vec<&str> = file_content.lines().collect();
    let mut out = String::new();

    if raw_lines.is_empty() {
        out.push_str("// vacío\n");
        return redact_secrets(&out);
    }

    let start_line = finding.span.start_line.max(1).min(raw_lines.len());
    let end_line = finding.span.end_line.max(start_line).min(raw_lines.len());
    let win_start = start_line.saturating_sub(6); // base 0 => ±5 líneas
    let win_end = (end_line + 4).min(raw_lines.len() - 1);

    let raw_window = raw_lines[win_start..=win_end].join("\n");
    let stripped_window = strip_block_comments_preserving_strings(&raw_window);
    let stripped_lines: Vec<&str> = stripped_window.lines().collect();

    let _ = writeln!(out, "// {}:{}-{}", finding.file.display(), start_line, end_line);

    let mut focus_corpus = finding.original_code.clone();
    for (offset, raw_line) in raw_lines[win_start..=win_end].iter().enumerate() {
        let line_no = win_start + offset + 1;
        let line_src = stripped_lines.get(offset).copied().unwrap_or(raw_line);
        let cleaned = strip_inline_comment_preserving_strings(line_src);
        let trimmed = cleaned.trim();
        let is_focus = line_no >= start_line && line_no <= end_line;
        if trimmed.is_empty() && !is_focus {
            continue;
        }
        focus_corpus.push(' ');
        focus_corpus.push_str(trimmed);
        let prefix = if is_focus { ">" } else { "" };
        let _ = writeln!(out, "{prefix}{line_no}:{trimmed}");
    }

    let sigs = filter_relevant_signatures(related_signatures, &focus_corpus);
    if !sigs.is_empty() {
        out.push_str("// sigs:\n");
        for sig in sigs {
            let _ = writeln!(out, "// {sig}");
        }
    }

    redact_secrets(&out)
}

/// Fusiona ventanas de ±3 líneas para múltiples hallazgos de un mismo archivo sin duplicar líneas,
/// limpiando comentarios y adjuntando solo firmas usadas en el bloque combinado.
pub fn build_merged_file_batch_context(
    file_content: &str,
    findings: &[&MigrationFinding],
    related_signatures: &[String],
) -> String {
    if findings.is_empty() {
        return String::new();
    }

    let raw_lines: Vec<&str> = file_content.lines().collect();
    if raw_lines.is_empty() {
        return String::new();
    }

    let mut ranges: Vec<(usize, usize)> = findings
        .iter()
        .map(|f| {
            let s = f.span.start_line.max(1).min(raw_lines.len());
            let e = f.span.end_line.max(s).min(raw_lines.len());
            (s.saturating_sub(4), (e + 2).min(raw_lines.len() - 1))
        })
        .collect();
    ranges.sort_by_key(|r| r.0);

    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut() {
            if s <= last.1 + 2 {
                last.1 = last.1.max(e);
                continue;
            }
        }
        merged.push((s, e));
    }

    let stripped_file = strip_block_comments_preserving_strings(file_content);
    let stripped_lines: Vec<&str> = stripped_file.lines().collect();

    let mut out = String::new();
    let _ = writeln!(out, "// {}", findings[0].file.display());

    let mut corpus = String::new();
    for (r_idx, (s, e)) in merged.iter().enumerate() {
        if r_idx > 0 {
            out.push_str("...\n");
        }
        for line_idx in *s..=*e {
            let line_no = line_idx + 1;
            let line_src = stripped_lines
                .get(line_idx)
                .copied()
                .unwrap_or(raw_lines[line_idx]);
            let cleaned = strip_inline_comment_preserving_strings(line_src);
            let trimmed = cleaned.trim();
            let is_focus = findings
                .iter()
                .any(|f| line_no >= f.span.start_line && line_no <= f.span.end_line.max(f.span.start_line));
            if trimmed.is_empty() && !is_focus {
                continue;
            }
            corpus.push(' ');
            corpus.push_str(trimmed);
            let marker = if is_focus { ">" } else { "" };
            let _ = writeln!(out, "{marker}{line_no}:{trimmed}");
        }
    }

    let sigs = filter_relevant_signatures(related_signatures, &corpus);
    if !sigs.is_empty() {
        out.push_str("// sigs:\n");
        for sig in sigs {
            let _ = writeln!(out, "// {sig}");
        }
    }

    redact_secrets(&out)
}

/// Caché persistente por huella `(rule_id, target_step, original_code)` para evitar consultas repetidas a la IA.
#[derive(Debug, Clone, Default)]
pub struct AiPatternCache {
    path: Option<PathBuf>,
    entries: BTreeMap<String, AiResolution>,
}

impl AiPatternCache {
    /// Carga la caché desde `cache_path` si existe, o crea una vacía vinculada a esa ruta.
    pub fn load_or_new(cache_path: &Path) -> Self {
        let entries = if cache_path.is_file() {
            std::fs::read_to_string(cache_path)
                .ok()
                .and_then(|raw| serde_json::from_str::<BTreeMap<String, AiResolution>>(&raw).ok())
                .unwrap_or_default()
        } else {
            BTreeMap::new()
        };

        Self {
            path: Some(cache_path.to_path_buf()),
            entries,
        }
    }

    /// Clave determinista de patrón para deduplicar hallazgos equivalentes.
    pub fn pattern_key(finding: &MigrationFinding) -> String {
        format!(
            "{}|{}|{}",
            finding.rule_id,
            finding.target_step,
            finding.original_code.trim()
        )
    }

    /// Busca una resolución previa en caché para la huella del hallazgo.
    pub fn get(&self, finding: &MigrationFinding) -> Option<AiResolution> {
        self.entries.get(&Self::pattern_key(finding)).cloned()
    }

    /// Inserta o actualiza la resolución en caché para la huella del hallazgo.
    pub fn insert(&mut self, finding: &MigrationFinding, resolution: AiResolution) {
        self.entries.insert(Self::pattern_key(finding), resolution);
    }

    /// Cantidad de patrones almacenados en caché.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Indica si la caché está vacía.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Persiste la caché en formato JSON compacto.
    pub fn save(&self) -> Result<()> {
        let Some(ref path) = self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "No se pudo crear directorio de caché IA '{}'",
                    parent.display()
                )
            })?;
        }
        let json = serde_json::to_string(&self.entries)
            .context("Error al serializar caché de patrones IA")?;
        std::fs::write(path, json).with_context(|| {
            format!("No se pudo guardar caché IA en '{}'", path.display())
        })?;
        Ok(())
    }
}
