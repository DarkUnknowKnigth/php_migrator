pub mod exporter;

pub use exporter::export_mermaid_markdown;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};

use crate::models::{
    DecisionBucket, FileSummary, FunctionSummary, MigrationFinding, ModuleSlice, RiskLevel,
    SecurityFinding, Severity,
};

/// Arista de inclusión (`include`/`require`) entre archivos del proyecto.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncludeEdgeInfo {
    pub from: PathBuf,
    pub to: Option<PathBuf>,
    pub target_expr: String,
    pub is_dynamic: bool,
}

/// Reporte estructural del grafo lógico de dependencias, módulos y orden recomendado de migración.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicGraphReport {
    pub files: Vec<FileSummary>,
    pub entrypoints: Vec<PathBuf>,
    pub edges: Vec<IncludeEdgeInfo>,
    pub modules: Vec<ModuleSlice>,
    pub recommended_migration_order: Vec<String>,
}

/// Construye el grafo lógico del proyecto agrupando archivos por módulos de primer nivel,
/// detectando entrypoints, dependencias inter-archivo (`include` + llamadas/herencia),
/// riesgo por módulo y orden recomendado de migración desde módulos base.
pub fn build_logic_graph(
    root: &Path,
    summaries: &[FileSummary],
    findings: &[MigrationFinding],
    security: &[SecurityFinding],
) -> LogicGraphReport {
    let mut files: Vec<FileSummary> = summaries
        .iter()
        .map(|s| {
            let mut cloned = s.clone();
            cloned.path = normalize_rel_path(root, &s.path);
            for inc in &mut cloned.includes {
                if let Some(ref rp) = inc.resolved_path {
                    inc.resolved_path = Some(normalize_rel_path(root, rp));
                }
            }
            cloned
        })
        .collect();

    files.sort_by(|a, b| path_cmp_key(&a.path).cmp(&path_cmp_key(&b.path)));

    let mut file_graph: DiGraph<usize, ()> = DiGraph::with_capacity(files.len(), files.len() * 2);
    let mut nodes: Vec<NodeIndex> = Vec::with_capacity(files.len());
    let mut exact_index: HashMap<String, usize> = HashMap::new();
    let mut lower_index: HashMap<String, usize> = HashMap::new();

    for (idx, f) in files.iter().enumerate() {
        let node = file_graph.add_node(idx);
        nodes.push(node);
        let key = path_exact_key(&f.path);
        let low = key.to_ascii_lowercase();
        exact_index.insert(key, idx);
        lower_index.entry(low).or_insert(idx);
    }

    // Índices globales de funciones y clases definidas por archivo
    let mut fn_defs: HashMap<String, Vec<usize>> = HashMap::new();
    let mut class_defs: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, f) in files.iter().enumerate() {
        for func in &f.functions {
            let short = func
                .name
                .rsplit('\\')
                .next()
                .unwrap_or(&func.name)
                .to_ascii_lowercase();
            fn_defs.entry(short).or_default().push(idx);
        }
        for cls in &f.classes {
            let short = cls
                .name
                .rsplit('\\')
                .next()
                .unwrap_or(&cls.name)
                .to_ascii_lowercase();
            class_defs.entry(short).or_default().push(idx);
        }
    }

    let mut edges = Vec::new();
    let mut include_in_degree = vec![0usize; files.len()];

    for (src_idx, summary) in files.iter().enumerate() {
        // Aristas de include/require
        for inc in &summary.includes {
            let resolved = inc.resolved_path.clone();
            edges.push(IncludeEdgeInfo {
                from: summary.path.clone(),
                to: resolved.clone(),
                target_expr: inc.target_expr.clone(),
                is_dynamic: inc.is_dynamic,
            });

            if let Some(ref target) = resolved {
                if let Some(dst_idx) = lookup_file_idx(&exact_index, &lower_index, target) {
                    if dst_idx != src_idx {
                        include_in_degree[dst_idx] += 1;
                        if !file_graph.contains_edge(nodes[src_idx], nodes[dst_idx]) {
                            file_graph.add_edge(nodes[src_idx], nodes[dst_idx], ());
                        }
                    }
                }
            }
        }

        // Aristas por llamadas a funciones / métodos estáticos definidos en otros archivos
        for call in &summary.calls {
            if !call.is_method_call && !call.is_static_call {
                let fn_key = call
                    .name
                    .rsplit('\\')
                    .next()
                    .unwrap_or(&call.name)
                    .to_ascii_lowercase();
                if let Some(defs) = fn_defs.get(&fn_key) {
                    if defs.len() == 1 && defs[0] != src_idx {
                        let dst_idx = defs[0];
                        if !file_graph.contains_edge(nodes[src_idx], nodes[dst_idx]) {
                            file_graph.add_edge(nodes[src_idx], nodes[dst_idx], ());
                        }
                    }
                }
            } else if call.is_static_call {
                if let Some((cls, _)) = call.name.split_once("::") {
                    let cls_key = cls
                        .rsplit('\\')
                        .next()
                        .unwrap_or(cls)
                        .to_ascii_lowercase();
                    if let Some(defs) = class_defs.get(&cls_key) {
                        if defs.len() == 1 && defs[0] != src_idx {
                            let dst_idx = defs[0];
                            if !file_graph.contains_edge(nodes[src_idx], nodes[dst_idx]) {
                                file_graph.add_edge(nodes[src_idx], nodes[dst_idx], ());
                            }
                        }
                    }
                }
            }
        }

        // Aristas por herencia/implementación de clases definidas en otros archivos
        for cls in &summary.classes {
            let mut bases: Vec<&str> = Vec::new();
            if let Some(ref ext) = cls.extends {
                bases.extend(ext.split(',').map(str::trim));
            }
            for imp in &cls.implements {
                bases.push(imp.trim());
            }
            for base in bases {
                let base_key = base
                    .rsplit('\\')
                    .next()
                    .unwrap_or(base)
                    .to_ascii_lowercase();
                if let Some(defs) = class_defs.get(&base_key) {
                    if defs.len() == 1 && defs[0] != src_idx {
                        let dst_idx = defs[0];
                        if !file_graph.contains_edge(nodes[src_idx], nodes[dst_idx]) {
                            file_graph.add_edge(nodes[src_idx], nodes[dst_idx], ());
                        }
                    }
                }
            }
        }
    }

    // Identificar entrypoints
    let mut entrypoints = Vec::new();
    let mut is_entrypoint_flag = vec![false; files.len()];
    for (idx, f) in files.iter().enumerate() {
        if is_internal_library_dir(&f.path) {
            continue;
        }
        let has_http_sg = has_http_superglobals(f);
        let is_index = f
            .path
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("index.php"));
        let has_exec = !f.includes.is_empty()
            || !f.calls.is_empty()
            || !f.db_interactions.is_empty();
        if include_in_degree[idx] == 0
            && (has_http_sg || f.is_mixed_html || is_index || has_exec)
        {
            is_entrypoint_flag[idx] = true;
            entrypoints.push(f.path.clone());
        }
    }
    if entrypoints.is_empty() {
        for (idx, f) in files.iter().enumerate() {
            if !is_internal_library_dir(&f.path) && include_in_degree[idx] == 0 {
                is_entrypoint_flag[idx] = true;
                entrypoints.push(f.path.clone());
            }
        }
    }

    // Agrupar archivos en ModuleSlice por carpeta lógica de primer nivel
    struct ModuleAcc {
        id: String,
        name: String,
        root_path: PathBuf,
        files: Vec<PathBuf>,
        entrypoints: Vec<PathBuf>,
        depends_on_modules: BTreeSet<String>,
        db_ops_count: usize,
        dynamic_includes_count: usize,
        green_count: usize,
        yellow_count: usize,
        red_count: usize,
        sec_score: u32,
        has_critical_sec: bool,
        has_high_sec: bool,
    }

    let mut module_map: BTreeMap<String, ModuleAcc> = BTreeMap::new();
    let mut file_module_id: Vec<String> = Vec::with_capacity(files.len());

    for (idx, f) in files.iter().enumerate() {
        let (mod_id, mod_root) = module_id_for_path(&f.path);
        file_module_id.push(mod_id.clone());

        let acc = module_map.entry(mod_id.clone()).or_insert_with(|| ModuleAcc {
            id: mod_id.clone(),
            name: mod_id,
            root_path: mod_root,
            files: Vec::new(),
            entrypoints: Vec::new(),
            depends_on_modules: BTreeSet::new(),
            db_ops_count: 0,
            dynamic_includes_count: 0,
            green_count: 0,
            yellow_count: 0,
            red_count: 0,
            sec_score: 0,
            has_critical_sec: false,
            has_high_sec: false,
        });

        acc.files.push(f.path.clone());
        if is_entrypoint_flag[idx] {
            acc.entrypoints.push(f.path.clone());
        }
        acc.db_ops_count += f.db_interactions.len();
        acc.dynamic_includes_count += f.includes.iter().filter(|i| i.is_dynamic).count();
    }

    // Asignar hallazgos de migración a su módulo correspondiente
    for finding in findings {
        let rel = normalize_rel_path(root, &finding.file);
        let mod_id = if let Some(idx) = lookup_file_idx(&exact_index, &lower_index, &rel) {
            file_module_id[idx].clone()
        } else {
            module_id_for_path(&rel).0
        };
        if let Some(acc) = module_map.get_mut(&mod_id) {
            match finding.bucket {
                DecisionBucket::GreenAutoFix => acc.green_count += 1,
                DecisionBucket::YellowNeedsDecision => acc.yellow_count += 1,
                DecisionBucket::RedBlocker => acc.red_count += 1,
            }
        }
    }

    // Asignar hallazgos de seguridad a su módulo correspondiente
    for sec in security {
        let rel = normalize_rel_path(root, &sec.file);
        let mod_id = if let Some(idx) = lookup_file_idx(&exact_index, &lower_index, &rel) {
            file_module_id[idx].clone()
        } else {
            module_id_for_path(&rel).0
        };
        if let Some(acc) = module_map.get_mut(&mod_id) {
            match sec.severity {
                Severity::Critical => {
                    acc.sec_score += 25;
                    acc.has_critical_sec = true;
                }
                Severity::High => {
                    acc.sec_score += 15;
                    acc.has_high_sec = true;
                }
                Severity::Medium => acc.sec_score += 8,
                Severity::Low => acc.sec_score += 3,
            }
        }
    }

    // Calcular dependencias entre módulos a partir de las aristas del grafo de archivos
    for edge in file_graph.raw_edges() {
        let u = file_graph[edge.source()];
        let v = file_graph[edge.target()];
        let mod_u = &file_module_id[u];
        let mod_v = &file_module_id[v];
        if mod_u != mod_v {
            if let Some(acc) = module_map.get_mut(mod_u) {
                acc.depends_on_modules.insert(mod_v.clone());
            }
        }
    }

    let modules: Vec<ModuleSlice> = module_map
        .into_values()
        .map(|acc| {
            let risk_score = (acc.red_count as u32) * 20
                + (acc.yellow_count as u32) * 8
                + (acc.green_count as u32)
                + (acc.dynamic_includes_count as u32) * 10
                + (acc.db_ops_count as u32) * 2
                + acc.sec_score;

            let risk_level = if risk_score >= 100 || acc.red_count >= 5 || acc.has_critical_sec {
                RiskLevel::Critical
            } else if risk_score >= 50 || acc.red_count >= 2 || acc.has_high_sec {
                RiskLevel::High
            } else if risk_score >= 15 || acc.yellow_count >= 2 || acc.red_count >= 1 {
                RiskLevel::Medium
            } else {
                RiskLevel::Low
            };

            ModuleSlice {
                id: acc.id,
                name: acc.name,
                root_path: acc.root_path,
                files: acc.files,
                entrypoints: acc.entrypoints,
                depends_on_modules: acc.depends_on_modules.into_iter().collect(),
                db_ops_count: acc.db_ops_count,
                dynamic_includes_count: acc.dynamic_includes_count,
                risk_level,
                risk_score,
                green_count: acc.green_count,
                yellow_count: acc.yellow_count,
                red_count: acc.red_count,
            }
        })
        .collect();

    let recommended_migration_order = compute_recommended_order(&modules);

    LogicGraphReport {
        files,
        entrypoints,
        edges,
        modules,
        recommended_migration_order,
    }
}

/// Extrae hasta ~15 firmas concisas de funciones/clases desde los archivos incluidos por `target_file`
/// y los archivos que incluyen o llaman a `target_file`, útiles como contexto acotado para la IA.
pub fn find_related_signatures(report: &LogicGraphReport, target_file: &Path) -> Vec<String> {
    let target_norm = normalize_rel_path(Path::new(""), target_file);
    let mut exact_map: HashMap<String, usize> = HashMap::new();
    let mut lower_map: HashMap<String, usize> = HashMap::new();

    for (idx, f) in report.files.iter().enumerate() {
        let key = path_exact_key(&f.path);
        let low = key.to_ascii_lowercase();
        exact_map.insert(key, idx);
        lower_map.entry(low).or_insert(idx);
    }

    let target_idx = lookup_file_idx(&exact_map, &lower_map, &target_norm).or_else(|| {
        let t_key = path_cmp_key(&target_norm);
        report
            .files
            .iter()
            .enumerate()
            .filter_map(|(idx, f)| {
                let f_key = path_cmp_key(&f.path);
                if t_key == f_key || t_key.ends_with(&format!("/{f_key}")) {
                    Some((f_key.len(), idx))
                } else {
                    None
                }
            })
            .max_by_key(|(len, _)| *len)
            .map(|(_, idx)| idx)
    });

    let Some(target_idx) = target_idx else {
        return Vec::new();
    };
    let target_summary = &report.files[target_idx];

    let mut related_order: Vec<usize> = Vec::new();
    let mut seen_files: HashSet<usize> = HashSet::new();
    seen_files.insert(target_idx);

    // 1. Archivos incluidos directamente por `target_file`
    for edge in &report.edges {
        if lookup_file_idx(&exact_map, &lower_map, &edge.from) == Some(target_idx) {
            if let Some(ref to_path) = edge.to {
                if let Some(dst_idx) = lookup_file_idx(&exact_map, &lower_map, to_path) {
                    if seen_files.insert(dst_idx) {
                        related_order.push(dst_idx);
                    }
                }
            }
        }
    }

    // 2. Archivos que incluyen a `target_file`
    for edge in &report.edges {
        if let Some(ref to_path) = edge.to {
            if lookup_file_idx(&exact_map, &lower_map, to_path) == Some(target_idx) {
                if let Some(src_idx) = lookup_file_idx(&exact_map, &lower_map, &edge.from) {
                    if seen_files.insert(src_idx) {
                        related_order.push(src_idx);
                    }
                }
            }
        }
    }

    // 3. Archivos relacionados por llamadas a funciones o clases
    let target_defined_fns: HashSet<String> = target_summary
        .functions
        .iter()
        .map(|f| f.name.to_ascii_lowercase())
        .collect();
    let target_defined_classes: HashSet<String> = target_summary
        .classes
        .iter()
        .map(|c| c.name.to_ascii_lowercase())
        .collect();

    let target_called_fns: HashSet<String> = target_summary
        .calls
        .iter()
        .filter(|c| !c.is_method_call && !c.is_static_call)
        .map(|c| {
            c.name
                .rsplit('\\')
                .next()
                .unwrap_or(&c.name)
                .to_ascii_lowercase()
        })
        .collect();
    let target_called_classes: HashSet<String> = target_summary
        .calls
        .iter()
        .filter_map(|c| {
            if c.is_static_call {
                c.name.split_once("::").map(|(cls, _)| {
                    cls.rsplit('\\')
                        .next()
                        .unwrap_or(cls)
                        .to_ascii_lowercase()
                })
            } else {
                None
            }
        })
        .collect();

    for (idx, f) in report.files.iter().enumerate() {
        if seen_files.contains(&idx) {
            continue;
        }
        let defines_called = f
            .functions
            .iter()
            .any(|fn_s| target_called_fns.contains(&fn_s.name.to_ascii_lowercase()))
            || f.classes
                .iter()
                .any(|c| target_called_classes.contains(&c.name.to_ascii_lowercase()));

        let calls_target = f.calls.iter().any(|c| {
            if !c.is_method_call && !c.is_static_call {
                let short = c
                    .name
                    .rsplit('\\')
                    .next()
                    .unwrap_or(&c.name)
                    .to_ascii_lowercase();
                target_defined_fns.contains(&short)
            } else if c.is_static_call {
                c.name.split_once("::").is_some_and(|(cls, _)| {
                    let short = cls.rsplit('\\').next().unwrap_or(cls).to_ascii_lowercase();
                    target_defined_classes.contains(&short)
                })
            } else {
                false
            }
        });

        if defines_called || calls_target {
            if seen_files.insert(idx) {
                related_order.push(idx);
            }
        }
    }

    const MAX_SIGNATURES: usize = 15;
    let mut signatures = Vec::new();
    let mut sig_seen = HashSet::new();

    for idx in related_order {
        if signatures.len() >= MAX_SIGNATURES {
            break;
        }
        let f = &report.files[idx];
        let file_label = f.path.to_string_lossy().replace('\\', "/");

        for func in &f.functions {
            if signatures.len() >= MAX_SIGNATURES {
                break;
            }
            let sig = format!("[{file_label}] {}", format_function_sig(None, func));
            if sig_seen.insert(sig.clone()) {
                signatures.push(sig);
            }
        }

        for cls in &f.classes {
            if signatures.len() >= MAX_SIGNATURES {
                break;
            }
            let mut header = format!("[{file_label}] class {}", cls.name);
            if let Some(ref ext) = cls.extends {
                header.push_str(&format!(" extends {ext}"));
            }
            if !cls.implements.is_empty() {
                header.push_str(&format!(" implements {}", cls.implements.join(", ")));
            }
            if sig_seen.insert(header.clone()) {
                signatures.push(header);
            }

            for method in &cls.methods {
                if signatures.len() >= MAX_SIGNATURES {
                    break;
                }
                let sig = format!(
                    "[{file_label}] {}",
                    format_function_sig(Some(&cls.name), method)
                );
                if sig_seen.insert(sig.clone()) {
                    signatures.push(sig);
                }
            }
        }
    }

    signatures.truncate(MAX_SIGNATURES);
    signatures
}

fn format_function_sig(class_name: Option<&str>, func: &FunctionSummary) -> String {
    let params_str: Vec<String> = func
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

    let ret_str = func
        .return_type
        .as_ref()
        .map(|r| format!(": {r}"))
        .unwrap_or_default();

    if let Some(cls) = class_name {
        format!("{cls}::{}({}){ret_str}", func.name, params_str.join(", "))
    } else {
        format!("function {}({}){ret_str}", func.name, params_str.join(", "))
    }
}

fn compute_recommended_order(modules: &[ModuleSlice]) -> Vec<String> {
    let n = modules.len();
    if n == 0 {
        return Vec::new();
    }

    let mut mod_graph: DiGraph<usize, ()> = DiGraph::with_capacity(n, n * 2);
    let mut nodes: Vec<NodeIndex> = Vec::with_capacity(n);
    let mut id_to_idx: HashMap<&str, usize> = HashMap::with_capacity(n);

    for (idx, m) in modules.iter().enumerate() {
        nodes.push(mod_graph.add_node(idx));
        id_to_idx.insert(m.id.as_str(), idx);
    }

    let mut unmet_deps = vec![0usize; n];
    for (idx, m) in modules.iter().enumerate() {
        for dep in &m.depends_on_modules {
            if let Some(&dep_idx) = id_to_idx.get(dep.as_str()) {
                if dep_idx != idx && !mod_graph.contains_edge(nodes[dep_idx], nodes[idx]) {
                    mod_graph.add_edge(nodes[dep_idx], nodes[idx], ());
                    unmet_deps[idx] += 1;
                }
            }
        }
    }

    let mut visited = vec![false; n];
    let mut order = Vec::with_capacity(n);

    for _ in 0..n {
        let mut best_idx: Option<usize> = None;
        for idx in 0..n {
            if visited[idx] {
                continue;
            }
            let cand_key = (
                unmet_deps[idx],
                modules[idx].risk_score,
                modules[idx].depends_on_modules.len(),
                modules[idx].id.as_str(),
            );
            let replace = match best_idx {
                None => true,
                Some(cur) => {
                    let cur_key = (
                        unmet_deps[cur],
                        modules[cur].risk_score,
                        modules[cur].depends_on_modules.len(),
                        modules[cur].id.as_str(),
                    );
                    cand_key < cur_key
                }
            };
            if replace {
                best_idx = Some(idx);
            }
        }

        let Some(chosen) = best_idx else {
            break;
        };
        visited[chosen] = true;
        order.push(modules[chosen].id.clone());

        for neighbor in mod_graph.neighbors(nodes[chosen]) {
            let dst = neighbor.index();
            unmet_deps[dst] = unmet_deps[dst].saturating_sub(1);
        }
    }

    order
}

fn is_internal_library_dir(rel_path: &Path) -> bool {
    let raw = rel_path.to_string_lossy().replace('\\', "/");
    let parts: Vec<&str> = raw.split('/').collect();
    if parts.len() <= 1 {
        return false;
    }
    for dir in &parts[..parts.len() - 1] {
        let low = dir.to_ascii_lowercase();
        if matches!(
            low.as_str(),
            "includes" | "include" | "inc" | "lib" | "libs" | "vendor" | "node_modules"
        ) {
            return true;
        }
    }
    false
}

fn has_http_superglobals(summary: &FileSummary) -> bool {
    summary.superglobals.iter().any(|(name, _)| {
        matches!(
            name.as_str(),
            "$_GET" | "$_POST" | "$_REQUEST" | "$_SESSION" | "$_COOKIE" | "$_FILES"
        )
    })
}

fn module_id_for_path(rel_path: &Path) -> (String, PathBuf) {
    let raw = rel_path.to_string_lossy().replace('\\', "/");
    let trimmed = raw.trim_start_matches("./");
    let mut parts = trimmed.split('/').filter(|p| !p.is_empty() && *p != ".");
    let first = parts.next();
    let second = parts.next();

    match (first, second) {
        (Some(dir), Some(_)) => (dir.to_string(), PathBuf::from(dir)),
        _ => ("root".to_string(), PathBuf::from(".")),
    }
}

fn lookup_file_idx(
    exact_index: &HashMap<String, usize>,
    lower_index: &HashMap<String, usize>,
    path: &Path,
) -> Option<usize> {
    let key = path_exact_key(path);
    if let Some(&idx) = exact_index.get(&key) {
        return Some(idx);
    }
    if cfg!(windows) {
        let low = key.to_ascii_lowercase();
        return lower_index.get(&low).copied();
    }
    None
}

fn path_exact_key(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string()
}

fn path_cmp_key(path: &Path) -> String {
    path_exact_key(path).to_ascii_lowercase()
}

fn normalize_rel_path(root: &Path, path: &Path) -> PathBuf {
    let p_norm = path.to_string_lossy().replace('\\', "/");
    let r_norm = root
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_string();

    let stripped = if !r_norm.is_empty() && r_norm != "." {
        if let Some(rest) = strip_root_prefix(&p_norm, &r_norm) {
            rest.to_string()
        } else {
            p_norm
        }
    } else {
        p_norm
    };

    let mut stack: Vec<&str> = Vec::new();
    for seg in stripped.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }

    if stack.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(stack.join("/"))
    }
}

fn strip_root_prefix<'a>(path: &'a str, root: &str) -> Option<&'a str> {
    if cfg!(windows) {
        let p_low = path.to_ascii_lowercase();
        let r_low = root.to_ascii_lowercase();
        if p_low == r_low {
            return Some("");
        }
        if p_low.starts_with(&r_low) && path.as_bytes().get(root.len()) == Some(&b'/') {
            return Some(&path[root.len() + 1..]);
        }
        None
    } else {
        if path == root {
            return Some("");
        }
        path.strip_prefix(root)
            .filter(|rest| rest.starts_with('/'))
            .map(|rest| &rest[1..])
    }
}
