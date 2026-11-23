use crate::models::{DecisionBucket, MigrationFinding, ResolutionStatus};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static BACKUP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Instrucción de parcheo asociada a un hallazgo específico.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchInstruction {
    pub finding_id: String,
    pub replacement: String,
    pub status: ResolutionStatus,
}

/// Resumen de los parches aplicados sobre un archivo individual.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePatchDiff {
    pub file: PathBuf,
    pub applied_count: usize,
    pub backup_path: Option<PathBuf>,
    pub unified_diff: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffOp<'a> {
    Equal(&'a str),
    Delete(&'a str),
    Insert(&'a str),
}

/// Genera un unified diff estándar línea por línea entre `original` y `modified`.
pub fn generate_unified_diff(path: &Path, original: &str, modified: &str) -> String {
    if original == modified {
        return String::new();
    }

    let old_lines: Vec<&str> = split_lines_preserving_empty(original);
    let new_lines: Vec<&str> = split_lines_preserving_empty(modified);

    let prefix = old_lines
        .iter()
        .zip(new_lines.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let mut suffix = 0usize;
    while suffix + prefix < old_lines.len()
        && suffix + prefix < new_lines.len()
        && old_lines[old_lines.len() - 1 - suffix] == new_lines[new_lines.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let old_mid = &old_lines[prefix..old_lines.len() - suffix];
    let new_mid = &new_lines[prefix..new_lines.len() - suffix];

    let mut ops: Vec<DiffOp<'_>> = Vec::with_capacity(old_lines.len() + new_lines.len());
    for &line in &old_lines[..prefix] {
        ops.push(DiffOp::Equal(line));
    }
    compute_middle_diff(old_mid, new_mid, &mut ops);
    for &line in &old_lines[old_lines.len() - suffix..] {
        ops.push(DiffOp::Equal(line));
    }

    format_unified_hunks(path, &ops, 3)
}

/// Valida el rango de bytes del hallazgo y retorna una vista previa en formato unified diff.
pub fn preview_patch(
    original: &str,
    finding: &MigrationFinding,
    replacement: &str,
) -> Result<String> {
    validate_finding_span(original, finding)?;
    let mut modified = String::with_capacity(
        original.len() - finding.span.len() + replacement.len(),
    );
    modified.push_str(&original[..finding.span.start_byte]);
    modified.push_str(replacement);
    modified.push_str(&original[finding.span.end_byte..]);
    Ok(generate_unified_diff(&finding.file, original, &modified))
}

/// Aplica instrucciones de parcheo sobre disco de manera quirúrgica por rango de bytes, creando backups previos.
pub fn apply_findings(
    project_root: &Path,
    findings: &mut [MigrationFinding],
    instructions: &[PatchInstruction],
) -> Result<Vec<FilePatchDiff>> {
    if instructions.is_empty() {
        return Ok(Vec::new());
    }

    let mut id_to_index: HashMap<String, usize> = HashMap::with_capacity(findings.len());
    for (idx, f) in findings.iter().enumerate() {
        id_to_index.insert(f.id.clone(), idx);
    }

    let mut seen_instruction_ids: HashSet<String> = HashSet::new();
    let mut status_only_updates: Vec<(usize, ResolutionStatus)> = Vec::new();
    let mut grouped_by_disk_path: BTreeMap<PathBuf, Vec<(usize, String, ResolutionStatus)>> =
        BTreeMap::new();

    for instr in instructions {
        if !seen_instruction_ids.insert(instr.finding_id.clone()) {
            bail!(
                "Instrucción duplicada para el hallazgo '{}'",
                instr.finding_id
            );
        }

        let Some(&f_idx) = id_to_index.get(&instr.finding_id) else {
            bail!(
                "No se encontró el hallazgo '{}' para aplicar parche",
                instr.finding_id
            );
        };

        if matches!(
            instr.status,
            ResolutionStatus::Skipped | ResolutionStatus::MarkedTodo
        ) {
            status_only_updates.push((f_idx, instr.status));
            continue;
        }

        let final_status = if instr.status == ResolutionStatus::Pending {
            ResolutionStatus::AppliedDeterministic
        } else {
            instr.status
        };

        let disk_path = resolve_disk_path(project_root, &findings[f_idx].file);
        grouped_by_disk_path
            .entry(disk_path)
            .or_default()
            .push((f_idx, instr.replacement.clone(), final_status));
    }

    // Aplicar actualizaciones que no modifican código
    for (f_idx, new_status) in status_only_updates {
        findings[f_idx].status = new_status;
    }

    if grouped_by_disk_path.is_empty() {
        return Ok(Vec::new());
    }

    let backup_batch_dir = build_backup_batch_dir(project_root);
    let mut diffs = Vec::new();

    for (disk_path, mut edits) in grouped_by_disk_path {
        let original = fs::read_to_string(&disk_path).with_context(|| {
            format!(
                "No se pudo leer '{}' en UTF-8 para parchear",
                disk_path.display()
            )
        })?;

        // Orden descendente por start_byte para no invalidar desplazamientos anteriores
        edits.sort_by(|a, b| {
            let fa = &findings[a.0];
            let fb = &findings[b.0];
            fb.span
                .start_byte
                .cmp(&fa.span.start_byte)
                .then_with(|| fb.span.end_byte.cmp(&fa.span.end_byte))
        });

        // Validar coincidencia exacta de bytes y ausencia de solapamiento antes de tocar disco
        for (idx, _, _) in &edits {
            validate_finding_span(&original, &findings[*idx])?;
        }
        for pair in edits.windows(2) {
            let higher = &findings[pair[0].0];
            let lower = &findings[pair[1].0];
            if higher.span.start_byte < lower.span.end_byte {
                bail!(
                    "Spans solapados en '{}': {} [{}..{}) y {} [{}..{})",
                    higher.file.display(),
                    lower.id,
                    lower.span.start_byte,
                    lower.span.end_byte,
                    higher.id,
                    higher.span.start_byte,
                    higher.span.end_byte
                );
            }
        }

        // Crear backup del archivo original
        let rel_for_backup = disk_path
            .strip_prefix(project_root)
            .unwrap_or_else(|_| findings[edits[0].0].file.as_path());
        let backup_path = backup_batch_dir.join(rel_for_backup);
        if let Some(parent) = backup_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("No se pudo crear directorio de backup '{}'", parent.display())
            })?;
        }
        fs::write(&backup_path, original.as_bytes()).with_context(|| {
            format!("No se pudo escribir backup en '{}'", backup_path.display())
        })?;

        // Aplicar reemplazos en memoria (en orden descendente de start_byte)
        let edited_set: HashSet<usize> = edits.iter().map(|(idx, _, _)| *idx).collect();
        let mut modified = original.clone();
        let mut applied_deltas: Vec<(usize, usize, isize)> = Vec::with_capacity(edits.len());
        for (f_idx, replacement, _) in &edits {
            let span = findings[*f_idx].span;
            let old_len = span.end_byte.saturating_sub(span.start_byte);
            let delta = replacement.len() as isize - old_len as isize;
            modified.replace_range(span.start_byte..span.end_byte, replacement);
            applied_deltas.push((span.start_byte, span.end_byte, delta));
        }

        // Persistir archivo parcheado
        fs::write(&disk_path, modified.as_bytes()).with_context(|| {
            format!(
                "No se pudo escribir el archivo parcheado '{}'",
                disk_path.display()
            )
        })?;

        let display_path = findings[edits[0].0].file.clone();
        let unified_diff = generate_unified_diff(&display_path, &original, &modified);
        let applied_count = edits.len();

        // Actualizar estado y spans de hallazgos editados y desplazar spans posteriores en el mismo archivo
        for (f_idx, replacement, new_status) in edits {
            findings[f_idx].status = new_status;
            let mut new_start = findings[f_idx].span.start_byte;
            // Ajustar por ediciones aplicadas con start_byte menor? No: ninguna edición en este lote tiene start_byte menor que ya haya corrido después,
            // todas las ediciones con start_byte < actual se aplicaron DESPUÉS en el orden descendente, pero el offset de actual se desplaza por las de menor byte!
            for &(ed_start, ed_end, delta) in &applied_deltas {
                if ed_end <= findings[f_idx].span.start_byte {
                    new_start = (new_start as isize + delta) as usize;
                } else if ed_start == findings[f_idx].span.start_byte {
                    // misma edición
                }
            }
            let new_end = new_start + replacement.len();
            if new_end <= modified.len() {
                findings[f_idx].span =
                    crate::parser::lexer::span_from_bytes(&modified, new_start, new_end);
            }
        }

        for (idx, f) in findings.iter_mut().enumerate() {
            if edited_set.contains(&idx) {
                continue;
            }
            if resolve_disk_path(project_root, &f.file) != disk_path {
                continue;
            }
            let mut shift: isize = 0;
            let mut overlapped = false;
            for &(ed_start, ed_end, delta) in &applied_deltas {
                if f.span.start_byte >= ed_end {
                    shift += delta;
                } else if f.span.end_byte > ed_start {
                    overlapped = true;
                    break;
                }
            }
            if !overlapped && shift != 0 {
                let new_start = (f.span.start_byte as isize + shift).max(0) as usize;
                let new_end = (f.span.end_byte as isize + shift).max(new_start as isize) as usize;
                if new_end <= modified.len() {
                    f.span = crate::parser::lexer::span_from_bytes(&modified, new_start, new_end);
                }
            }
        }

        diffs.push(FilePatchDiff {
            file: display_path,
            applied_count,
            backup_path: Some(backup_path),
            unified_diff,
        });
    }

    Ok(diffs)
}

/// Aplica automáticamente todos los hallazgos VERDE pendientes pertenecientes a los archivos de un módulo.
pub fn apply_green_fixes_for_module(
    project_root: &Path,
    findings: &mut [MigrationFinding],
    module_files: &[PathBuf],
) -> Result<Vec<FilePatchDiff>> {
    let module_set: HashSet<String> = module_files
        .iter()
        .map(|p| normalize_rel_key(project_root, p))
        .collect();

    let instructions: Vec<PatchInstruction> = findings
        .iter()
        .filter(|f| {
            f.bucket == DecisionBucket::GreenAutoFix
                && f.status == ResolutionStatus::Pending
                && f.suggested_replacement.is_some()
                && module_set.contains(&normalize_rel_key(project_root, &f.file))
        })
        .map(|f| PatchInstruction {
            finding_id: f.id.clone(),
            replacement: f
                .suggested_replacement
                .clone()
                .expect("verificado is_some"),
            status: ResolutionStatus::AppliedDeterministic,
        })
        .collect();

    if instructions.is_empty() {
        return Ok(Vec::new());
    }

    apply_findings(project_root, findings, &instructions)
}

fn validate_finding_span(original: &str, finding: &MigrationFinding) -> Result<()> {
    let start = finding.span.start_byte;
    let end = finding.span.end_byte;
    if start > end || end > original.len() {
        bail!(
            "Span fuera de rango en '{}' para hallazgo '{}': [{}..{}) sobre longitud {}",
            finding.file.display(),
            finding.id,
            start,
            end,
            original.len()
        );
    }
    if !original.is_char_boundary(start) || !original.is_char_boundary(end) {
        bail!(
            "Span no alineado a límites UTF-8 en '{}' para hallazgo '{}'",
            finding.file.display(),
            finding.id
        );
    }
    let actual = &original[start..end];
    if actual != finding.original_code {
        bail!(
            "El código en '{}' [{}..{}) no coincide con el hallazgo '{}'. Esperado {:?}, encontrado {:?}",
            finding.file.display(),
            start,
            end,
            finding.id,
            finding.original_code,
            actual
        );
    }
    Ok(())
}

fn resolve_disk_path(project_root: &Path, file: &Path) -> PathBuf {
    if file.is_absolute() {
        file.to_path_buf()
    } else {
        project_root.join(file)
    }
}

fn normalize_rel_key(project_root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(project_root).unwrap_or(path);
    rel.to_string_lossy().replace('\\', "/")
}

fn build_backup_batch_dir(project_root: &Path) -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let seq = BACKUP_COUNTER.fetch_add(1, Ordering::Relaxed);
    project_root
        .join(".php-migrator")
        .join("backups")
        .join(format!("{millis}-{seq}"))
}

fn split_lines_preserving_empty(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&str> = text.split('\n').collect();
    if text.ends_with('\n') {
        lines.pop();
    }
    lines
}

fn compute_middle_diff<'a>(old_mid: &[&'a str], new_mid: &[&'a str], ops: &mut Vec<DiffOp<'a>>) {
    let n = old_mid.len();
    let m = new_mid.len();

    if n == 0 {
        for &line in new_mid {
            ops.push(DiffOp::Insert(line));
        }
        return;
    }
    if m == 0 {
        for &line in old_mid {
            ops.push(DiffOp::Delete(line));
        }
        return;
    }

    // Límite de seguridad para evitar tablas LCS gigantes en archivos masivos
    if n.saturating_mul(m) > 1_000_000 {
        for &line in old_mid {
            ops.push(DiffOp::Delete(line));
        }
        for &line in new_mid {
            ops.push(DiffOp::Insert(line));
        }
        return;
    }

    let cols = m + 1;
    let mut dp = vec![0u32; (n + 1) * cols];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i * cols + j] = if old_mid[i] == new_mid[j] {
                dp[(i + 1) * cols + (j + 1)] + 1
            } else {
                dp[(i + 1) * cols + j].max(dp[i * cols + (j + 1)])
            };
        }
    }

    let mut i = 0usize;
    let mut j = 0usize;
    while i < n && j < m {
        if old_mid[i] == new_mid[j] {
            ops.push(DiffOp::Equal(old_mid[i]));
            i += 1;
            j += 1;
        } else if dp[(i + 1) * cols + j] >= dp[i * cols + (j + 1)] {
            ops.push(DiffOp::Delete(old_mid[i]));
            i += 1;
        } else {
            ops.push(DiffOp::Insert(new_mid[j]));
            j += 1;
        }
    }
    while i < n {
        ops.push(DiffOp::Delete(old_mid[i]));
        i += 1;
    }
    while j < m {
        ops.push(DiffOp::Insert(new_mid[j]));
        j += 1;
    }
}

fn format_unified_hunks(path: &Path, ops: &[DiffOp<'_>], context: usize) -> String {
    let change_indices: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter_map(|(idx, op)| match op {
            DiffOp::Equal(_) => None,
            _ => Some(idx),
        })
        .collect();

    if change_indices.is_empty() {
        return String::new();
    }

    // Construir rangos de índices en `ops` agrupando contextos solapados
    let mut hunks: Vec<(usize, usize)> = Vec::new();
    for &c_idx in &change_indices {
        let start = c_idx.saturating_sub(context);
        let end = (c_idx + context + 1).min(ops.len());
        if let Some(last) = hunks.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        hunks.push((start, end));
    }

    // Calcular coordenadas de línea 1-based antes de cada op
    let mut old_line_at = Vec::with_capacity(ops.len() + 1);
    let mut new_line_at = Vec::with_capacity(ops.len() + 1);
    let mut cur_old = 1usize;
    let mut cur_new = 1usize;
    for op in ops {
        old_line_at.push(cur_old);
        new_line_at.push(cur_new);
        match op {
            DiffOp::Equal(_) => {
                cur_old += 1;
                cur_new += 1;
            }
            DiffOp::Delete(_) => cur_old += 1,
            DiffOp::Insert(_) => cur_new += 1,
        }
    }

    let display_path = path.to_string_lossy().replace('\\', "/");
    let mut out = format!("--- a/{display_path}\n+++ b/{display_path}\n");

    for (h_start, h_end) in hunks {
        let mut old_count = 0usize;
        let mut new_count = 0usize;
        for op in &ops[h_start..h_end] {
            match op {
                DiffOp::Equal(_) => {
                    old_count += 1;
                    new_count += 1;
                }
                DiffOp::Delete(_) => old_count += 1,
                DiffOp::Insert(_) => new_count += 1,
            }
        }
        let old_start = if old_count == 0 {
            old_line_at[h_start].saturating_sub(1)
        } else {
            old_line_at[h_start]
        };
        let new_start = if new_count == 0 {
            new_line_at[h_start].saturating_sub(1)
        } else {
            new_line_at[h_start]
        };

        out.push_str(&format!(
            "@@ -{old_start},{old_count} +{new_start},{new_count} @@\n"
        ));
        for op in &ops[h_start..h_end] {
            match op {
                DiffOp::Equal(line) => {
                    out.push(' ');
                    out.push_str(line);
                    out.push('\n');
                }
                DiffOp::Delete(line) => {
                    out.push('-');
                    out.push_str(line);
                    out.push('\n');
                }
                DiffOp::Insert(line) => {
                    out.push('+');
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
    }

    out
}
