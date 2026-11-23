use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write;
use std::path::Path;

use crate::models::{FileSummary, FunctionSummary};

use super::LogicGraphReport;

/// Exporta el reporte del grafo lógico en un documento Markdown completo con:
/// 1. Resumen de módulos y orden recomendado de migración.
/// 2. Diagrama Mermaid (`flowchart LR`) con entrypoints y aristas estáticas/dinámicas.
/// 3. Inventario de funciones, clases, superglobales y operaciones de BD por archivo.
pub fn export_mermaid_markdown(report: &LogicGraphReport) -> String {
    let mut out = String::with_capacity(4096);

    let entrypoint_set: HashSet<String> = report
        .entrypoints
        .iter()
        .map(|p| norm_key(p))
        .collect();

    let static_edges_count = report.edges.iter().filter(|e| !e.is_dynamic).count();
    let dynamic_edges_count = report.edges.iter().filter(|e| e.is_dynamic).count();

    let _ = writeln!(out, "# Mapa Lógico y Plan de Migración PHP\n");
    let _ = writeln!(out, "## 1. Resumen de Módulos y Orden Recomendado\n");
    let _ = writeln!(
        out,
        "- **Archivos analizados:** {}",
        report.files.len()
    );
    let _ = writeln!(
        out,
        "- **Entrypoints detectados:** {}",
        report.entrypoints.len()
    );
    let _ = writeln!(out, "- **Módulos lógicos:** {}", report.modules.len());
    let _ = writeln!(
        out,
        "- **Aristas `include`/`require`:** {} estáticas, {} dinámicas\n",
        static_edges_count, dynamic_edges_count
    );

    if report.recommended_migration_order.is_empty() {
        let _ = writeln!(out, "_No se detectaron módulos para ordenar._\n");
    } else {
        let mod_lookup: HashMap<&str, _> = report
            .modules
            .iter()
            .map(|m| (m.id.as_str(), m))
            .collect();

        let _ = writeln!(out, "### Orden Recomendado de Migración (Base -> Dependientes)\n");
        for (idx, mod_id) in report.recommended_migration_order.iter().enumerate() {
            if let Some(m) = mod_lookup.get(mod_id.as_str()) {
                let deps = if m.depends_on_modules.is_empty() {
                    "ninguna".to_string()
                } else {
                    m.depends_on_modules.join(", ")
                };
                let _ = writeln!(
                    out,
                    "{}. **{}** — Riesgo: **{}** (score: {}, archivos: {}, dependencias: `{}`)",
                    idx + 1,
                    m.name,
                    m.risk_level,
                    m.risk_score,
                    m.files.len(),
                    deps
                );
            } else {
                let _ = writeln!(out, "{}. **{}**", idx + 1, mod_id);
            }
        }
        let _ = writeln!(out);
    }

    if !report.modules.is_empty() {
        let _ = writeln!(out, "### Métricas por Módulo\n");
        let _ = writeln!(
            out,
            "| Módulo | Archivos | Entrypoints | Dependencias | Ops BD | Includes Dinámicos | Verde / Amarillo / Rojo | Riesgo (Score) |"
        );
        let _ = writeln!(
            out,
            "|---|---:|---:|---|---:|---:|---:|---|"
        );
        for m in &report.modules {
            let deps = if m.depends_on_modules.is_empty() {
                "-".to_string()
            } else {
                m.depends_on_modules.join(", ")
            };
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} | {} | {} | {} / {} / {} | {} ({}) |",
                m.name,
                m.files.len(),
                m.entrypoints.len(),
                deps,
                m.db_ops_count,
                m.dynamic_includes_count,
                m.green_count,
                m.yellow_count,
                m.red_count,
                m.risk_level,
                m.risk_score
            );
        }
        let _ = writeln!(out);
    }

    // Sección 2: Diagrama Mermaid
    let _ = writeln!(out, "## 2. Diagrama de Dependencias (Mermaid)\n");
    let _ = writeln!(out, "```mermaid");
    let _ = writeln!(out, "flowchart LR");

    let mut file_node_ids: HashMap<String, String> = HashMap::new();
    for f in &report.files {
        let key = norm_key(&f.path);
        let id = mermaid_id("file", &key);
        file_node_ids.insert(key, id);
    }

    for m in &report.modules {
        let mod_node = mermaid_id("mod", &m.id);
        let mod_label = sanitize_mermaid_label(&format!(
            "Módulo: {} ({} - score {})",
            m.name, m.risk_level, m.risk_score
        ));
        let _ = writeln!(out, "    subgraph {mod_node}[\"{mod_label}\"]");
        for f_path in &m.files {
            let key = norm_key(f_path);
            let node_id = file_node_ids
                .get(&key)
                .cloned()
                .unwrap_or_else(|| mermaid_id("file", &key));
            let display = f_path.to_string_lossy().replace('\\', "/");
            if entrypoint_set.contains(&key) {
                let lbl = sanitize_mermaid_label(&format!("ENTRYPOINT: {display}"));
                let _ = writeln!(out, "        {node_id}([\"{lbl}\"]):::entrypoint");
            } else {
                let lbl = sanitize_mermaid_label(&display);
                let _ = writeln!(out, "        {node_id}[\"{lbl}\"]");
            }
        }
        let _ = writeln!(out, "    end");
    }

    let mut seen_static_edges: HashSet<(String, String)> = HashSet::new();
    let mut external_nodes: HashMap<String, String> = HashMap::new();

    for (edge_idx, edge) in report.edges.iter().enumerate() {
        let from_key = norm_key(&edge.from);
        let from_id = file_node_ids
            .get(&from_key)
            .cloned()
            .unwrap_or_else(|| mermaid_id("file", &from_key));

        if let Some(ref to_path) = edge.to {
            let to_key = norm_key(to_path);
            let to_id = if let Some(existing) = file_node_ids.get(&to_key) {
                existing.clone()
            } else if let Some(ext_existing) = external_nodes.get(&to_key) {
                ext_existing.clone()
            } else {
                let ext_id = mermaid_id("ext", &to_key);
                let lbl = sanitize_mermaid_label(&format!(
                    "(externo) {}",
                    to_path.to_string_lossy().replace('\\', "/")
                ));
                let _ = writeln!(out, "    {ext_id}[\"{lbl}\"]");
                external_nodes.insert(to_key, ext_id.clone());
                ext_id
            };

            if edge.is_dynamic {
                let _ = writeln!(out, "    {from_id} -. dinámicas .-> {to_id}");
            } else if seen_static_edges.insert((from_id.clone(), to_id.clone())) {
                let _ = writeln!(out, "    {from_id} --> {to_id}");
            }
        } else {
            let dyn_id = format!("dyn_{edge_idx}");
            let expr_lbl = sanitize_mermaid_label(&edge.target_expr);
            if edge.is_dynamic {
                let _ = writeln!(
                    out,
                    "    {from_id} -. dinámicas .-> {dyn_id}[\"Dinámico: {expr_lbl}\"]:::dynamicNode"
                );
            } else {
                let _ = writeln!(
                    out,
                    "    {from_id} -. no resuelto .-> {dyn_id}[\"No resuelto: {expr_lbl}\"]"
                );
            }
        }
    }

    let _ = writeln!(
        out,
        "    classDef entrypoint fill:#fef3c7,stroke:#d97706,stroke-width:2px,color:#111827;"
    );
    let _ = writeln!(
        out,
        "    classDef dynamicNode fill:#fee2e2,stroke:#dc2626,stroke-dasharray: 5 5,color:#111827;"
    );
    let _ = writeln!(out, "```\n");

    // Sección 3: Inventario por archivo
    let _ = writeln!(
        out,
        "## 3. Inventario de Funciones, Clases, Superglobales y BD\n"
    );

    if report.files.is_empty() {
        let _ = writeln!(out, "_No hay archivos PHP en el reporte._\n");
        return out;
    }

    for f in &report.files {
        write_file_inventory(&mut out, f, &entrypoint_set);
    }

    out
}

fn write_file_inventory(
    out: &mut String,
    f: &FileSummary,
    entrypoint_set: &HashSet<String>,
) {
    let display_path = f.path.to_string_lossy().replace('\\', "/");
    let key = norm_key(&f.path);
    let mut badges = Vec::new();
    if entrypoint_set.contains(&key) {
        badges.push("ENTRYPOINT");
    }
    if f.is_mixed_html {
        badges.push("PHP+HTML Mixto");
    }
    let badge_str = if badges.is_empty() {
        String::new()
    } else {
        format!(" [{}]", badges.join(" | "))
    };

    let _ = writeln!(out, "### `{display_path}`{badge_str}\n");
    let _ = writeln!(
        out,
        "- **Líneas:** {} | **Bloques PHP:** {} | **Namespace:** {}",
        f.total_lines,
        f.blocks.iter().filter(|b| b.is_php).count(),
        f.namespace.as_deref().unwrap_or("(global)")
    );

    if !f.use_imports.is_empty() {
        let _ = writeln!(out, "- **Imports (`use`):** `{}`", f.use_imports.join("`, `"));
    }

    if !f.includes.is_empty() {
        let _ = writeln!(out, "- **Includes/Requires:**");
        for inc in &f.includes {
            let status = if inc.is_dynamic {
                "dinámico".to_string()
            } else if let Some(ref rp) = inc.resolved_path {
                format!("-> `{}`", rp.to_string_lossy().replace('\\', "/"))
            } else {
                "no resuelto".to_string()
            };
            let _ = writeln!(
                out,
                "  - L{}: `{} {}` ({status})",
                inc.span.start_line, inc.kind, inc.target_expr
            );
        }
    }

    if !f.classes.is_empty() {
        let _ = writeln!(out, "- **Clases:**");
        for cls in &f.classes {
            let mut meta = Vec::new();
            if let Some(ref ext) = cls.extends {
                meta.push(format!("extends {ext}"));
            }
            if !cls.implements.is_empty() {
                meta.push(format!("implements {}", cls.implements.join(", ")));
            }
            if cls.has_allow_dynamic_properties {
                meta.push("#[AllowDynamicProperties]".to_string());
            }
            let meta_str = if meta.is_empty() {
                String::new()
            } else {
                format!(" ({})", meta.join("; "))
            };
            let _ = writeln!(out, "  - `class {}`{meta_str}", cls.name);
            if !cls.declared_properties.is_empty() {
                let _ = writeln!(
                    out,
                    "    - Propiedades declaradas: `${}`",
                    cls.declared_properties.join("`, `$")
                );
            }
            if !cls.dynamic_properties.is_empty() {
                let dyn_list: Vec<String> = cls
                    .dynamic_properties
                    .iter()
                    .map(|dp| format!("`{}` (L{})", dp.property_name, dp.span.start_line))
                    .collect();
                let _ = writeln!(
                    out,
                    "    - Propiedades dinámicas detectadas: {}",
                    dyn_list.join(", ")
                );
            }
            if !cls.methods.is_empty() {
                let _ = writeln!(out, "    - Métodos:");
                for m in &cls.methods {
                    let vis = m.visibility.as_deref().unwrap_or("public");
                    let static_kw = if m.is_static { " static" } else { "" };
                    let attr = if m.has_return_type_will_change {
                        " #[ReturnTypeWillChange]"
                    } else {
                        ""
                    };
                    let _ = writeln!(
                        out,
                        "      - `{vis}{static_kw} {}`{attr} (L{})",
                        format_fn_summary(m),
                        m.span.start_line
                    );
                }
            }
        }
    }

    if !f.functions.is_empty() {
        let _ = writeln!(out, "- **Funciones standalone:**");
        for func in &f.functions {
            let _ = writeln!(
                out,
                "  - `{}` (L{})",
                format_fn_summary(func),
                func.span.start_line
            );
        }
    }

    if !f.superglobals.is_empty() {
        let mut grouped: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (sg, line) in &f.superglobals {
            grouped.entry(sg.as_str()).or_default().push(*line);
        }
        let items: Vec<String> = grouped
            .into_iter()
            .map(|(sg, lines)| {
                let l_str: Vec<String> = lines.iter().map(|l| format!("L{l}")).collect();
                format!("`{sg}` ({})", l_str.join(", "))
            })
            .collect();
        let _ = writeln!(out, "- **Superglobales:** {}", items.join("; "));
    }

    if !f.globals_declared.is_empty() {
        let _ = writeln!(
            out,
            "- **Variables `global`:** `{}`",
            f.globals_declared.join("`, `")
        );
    }

    if !f.db_interactions.is_empty() {
        let _ = writeln!(out, "- **Operaciones de Base de Datos:**");
        for db in &f.db_interactions {
            let _ = writeln!(
                out,
                "  - L{}: `{}` / `{}` -> `{}`",
                db.line,
                db.driver,
                db.kind,
                db.snippet.replace('`', "'")
            );
        }
    }

    if !f.syntax_version_markers.is_empty() {
        let markers: Vec<String> = f
            .syntax_version_markers
            .iter()
            .map(|(v, msg)| format!("PHP {v}: {msg}"))
            .collect();
        let _ = writeln!(out, "- **Marcadores de versión:** {}", markers.join("; "));
    }

    let _ = writeln!(out);
}

fn format_fn_summary(func: &FunctionSummary) -> String {
    let params: Vec<String> = func
        .params
        .iter()
        .map(|p| {
            let mut s = String::new();
            if let Some(ref th) = p.type_hint {
                s.push_str(th);
                s.push(' ');
            }
            s.push_str(&p.name);
            if p.has_default {
                s.push_str(if p.default_is_null { " = null" } else { " = ..." });
            }
            s
        })
        .collect();
    let ret = func
        .return_type
        .as_ref()
        .map(|r| format!(": {r}"))
        .unwrap_or_default();
    format!("function {}({}){ret}", func.name, params.join(", "))
}

fn norm_key(path: &Path) -> String {
    let raw = path
        .to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string();
    if cfg!(windows) {
        raw.to_ascii_lowercase()
    } else {
        raw
    }
}

fn mermaid_id(prefix: &str, raw: &str) -> String {
    let mut id = String::with_capacity(prefix.len() + raw.len() + 2);
    id.push_str(prefix);
    id.push('_');
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            id.push(ch);
        } else {
            id.push('_');
        }
    }
    id
}

fn sanitize_mermaid_label(raw: &str) -> String {
    raw.replace('"', "'")
        .replace('\r', " ")
        .replace('\n', " ")
}
