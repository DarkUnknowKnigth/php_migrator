use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use crate::models::{
    CallArg, ClassSummary, DbInteraction, DynamicPropertyWrite, FileSummary, FunctionCallSite,
    FunctionSummary, IncludeKind, IncludeStatement, ParamSummary, PhpVersion,
};
use crate::parser::lexer::{self, PhpToken, PhpTokenKind};

#[derive(Debug, Clone)]
struct Tok {
    tok: PhpToken,
    block_id: usize,
}

impl Tok {
    fn eq_ci(&self, word: &str) -> bool {
        self.tok.kind == PhpTokenKind::Word && self.tok.text.eq_ignore_ascii_case(word)
    }

    fn is_punct(&self, p: &str) -> bool {
        self.tok.kind == PhpTokenKind::Punctuation && self.tok.text == p
    }

    fn is_op(&self, op: &str) -> bool {
        self.tok.kind == PhpTokenKind::Operator && self.tok.text == op
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    TopLevel,
    ClassBody(usize),
    FunctionBody { owner_class: Option<usize> },
    AnonClassBody,
}

#[derive(Debug, Clone)]
struct ParsedAttr {
    name: String,
}

impl ParsedAttr {
    fn matches_short_name(&self, expected: &str) -> bool {
        let trimmed = self.name.trim_start_matches('\\');
        trimmed.eq_ignore_ascii_case(expected)
    }
}

/// Analiza un archivo PHP o PHP+HTML mixto y construye su `FileSummary` estructural completo.
pub fn analyze_file(path: &Path, project_root: &Path, source: &str) -> FileSummary {
    let rel_path = normalize_relative_path(path, project_root);
    let file_dir = rel_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();

    let blocks = lexer::split_blocks(source);
    let has_php = blocks.iter().any(|b| b.is_php);
    let has_non_empty_non_php = blocks.iter().any(|b| {
        !b.is_php
            && !source[b.span.start_byte..b.span.end_byte]
                .trim_matches(|c: char| c.is_whitespace() || c == '\u{FEFF}')
                .is_empty()
    });
    let is_mixed_html = has_php && has_non_empty_non_php;
    let total_lines = if source.is_empty() {
        0
    } else {
        source.lines().count()
    };

    let mut tokens = Vec::new();
    for (block_id, block) in blocks.iter().enumerate() {
        if !block.is_php {
            continue;
        }
        for tok in lexer::tokenize_block(source, block) {
            if matches!(
                tok.kind,
                PhpTokenKind::Comment | PhpTokenKind::Whitespace
            ) {
                continue;
            }
            tokens.push(Tok { tok, block_id });
        }
    }

    let lines_cache: Vec<&str> = source.lines().collect();

    let mut analyzer = AstAnalyzer {
        source,
        project_root,
        file_dir,
        tokens,
        lines_cache,
        namespace: None,
        use_imports: Vec::new(),
        includes: Vec::new(),
        functions: Vec::new(),
        classes: Vec::new(),
        calls: Vec::new(),
        superglobals: Vec::new(),
        globals_declared: Vec::new(),
        globals_seen: HashSet::new(),
        db_interactions: Vec::new(),
        syntax_version_markers: Vec::new(),
        markers_seen: HashSet::new(),
        saw_pdo: false,
        saw_mysqli: false,
    };

    let total_tokens = analyzer.tokens.len();
    analyzer.parse_range(0, total_tokens, ScopeKind::TopLevel);
    analyzer.refine_db_drivers();

    FileSummary {
        path: rel_path,
        is_mixed_html,
        total_lines,
        blocks,
        namespace: analyzer.namespace,
        use_imports: analyzer.use_imports,
        includes: analyzer.includes,
        functions: analyzer.functions,
        classes: analyzer.classes,
        calls: analyzer.calls,
        superglobals: analyzer.superglobals,
        globals_declared: analyzer.globals_declared,
        db_interactions: analyzer.db_interactions,
        syntax_version_markers: analyzer.syntax_version_markers,
    }
}

struct AstAnalyzer<'a> {
    source: &'a str,
    project_root: &'a Path,
    file_dir: PathBuf,
    tokens: Vec<Tok>,
    lines_cache: Vec<&'a str>,
    namespace: Option<String>,
    use_imports: Vec<String>,
    includes: Vec<IncludeStatement>,
    functions: Vec<FunctionSummary>,
    classes: Vec<ClassSummary>,
    calls: Vec<FunctionCallSite>,
    superglobals: Vec<(String, usize)>,
    globals_declared: Vec<String>,
    globals_seen: HashSet<String>,
    db_interactions: Vec<DbInteraction>,
    syntax_version_markers: Vec<(PhpVersion, String)>,
    markers_seen: HashSet<(PhpVersion, String)>,
    saw_pdo: bool,
    saw_mysqli: bool,
}

impl<'a> AstAnalyzer<'a> {
    fn add_marker(&mut self, version: PhpVersion, reason: &str) {
        let key = (version, reason.to_string());
        if self.markers_seen.insert(key.clone()) {
            self.syntax_version_markers.push(key);
        }
    }

    fn snippet_for_line(&self, line: usize) -> String {
        if line == 0 || line > self.lines_cache.len() {
            return String::new();
        }
        let raw = self.lines_cache[line - 1].trim();
        truncate_chars(raw, 180)
    }

    fn refine_db_drivers(&mut self) {
        let inferred = match (self.saw_pdo, self.saw_mysqli) {
            (true, false) => "pdo",
            (false, true) => "mysqli",
            _ => "pdo/mysqli",
        };
        for db in &mut self.db_interactions {
            if db.driver == "__method__" {
                db.driver = inferred.to_string();
            }
        }
    }

    fn is_member_access(&self, idx: usize) -> bool {
        if idx == 0 {
            return false;
        }
        let prev = &self.tokens[idx - 1];
        prev.is_op("->") || prev.is_op("?->") || prev.is_op("::")
    }

    fn is_prev_ns_or_member(&self, idx: usize) -> bool {
        if idx == 0 {
            return false;
        }
        let prev = &self.tokens[idx - 1];
        prev.is_op("->") || prev.is_op("?->") || prev.is_op("::") || prev.is_punct("\\")
    }

    fn parse_range(&mut self, start: usize, end: usize, scope: ScopeKind) {
        let mut i = start;
        let mut pending_attrs: Vec<ParsedAttr> = Vec::new();

        while i < end {
            // Superglobales en tokens Variable
            if self.tokens[i].tok.kind == PhpTokenKind::Variable {
                let name = &self.tokens[i].tok.text;
                if is_superglobal(name) {
                    self.superglobals
                        .push((name.clone(), self.tokens[i].tok.span.start_line));
                }
            } else if self.tokens[i].tok.kind == PhpTokenKind::StringLiteral
                && self.tokens[i].tok.text.starts_with('"')
            {
                self.scan_string_for_superglobals(i);
            }

            // Marcadores de versión por token
            if self.tokens[i].is_op("?->") {
                self.add_marker(PhpVersion::Php80, "Operador nullsafe ?-> (PHP >= 8.0)");
            } else if self.tokens[i].is_op("??=") {
                self.add_marker(PhpVersion::Php74, "Operador ??= (PHP >= 7.4)");
            } else if self.tokens[i].tok.kind == PhpTokenKind::Number
                && self.tokens[i].tok.text.contains('_')
            {
                self.add_marker(
                    PhpVersion::Php74,
                    "Separadores numéricos con _ (PHP >= 7.4)",
                );
            } else if self.tokens[i].eq_ci("match")
                && !self.is_member_access(i)
                && i + 1 < end
                && self.tokens[i + 1].is_punct("(")
            {
                self.add_marker(PhpVersion::Php80, "Expresión match() (PHP >= 8.0)");
            } else if self.tokens[i].eq_ci("fn")
                && !self.is_member_access(i)
                && i + 1 < end
                && self.tokens[i + 1].is_punct("(")
            {
                self.add_marker(PhpVersion::Php74, "Arrow functions fn() (PHP >= 7.4)");
            } else if self.tokens[i].is_punct("{")
                && i > start
                && (self.tokens[i - 1].tok.kind == PhpTokenKind::Variable
                    || self.tokens[i - 1].is_punct("]"))
            {
                self.add_marker(
                    PhpVersion::Php74,
                    "Acceso con llaves $var{...} (deprecado en 7.4, eliminado en PHP 8.0)",
                );
            }

            // Atributos PHP 8: #[...]
            if self.tokens[i].is_punct("#")
                && i + 1 < end
                && self.tokens[i + 1].is_punct("[")
            {
                self.add_marker(PhpVersion::Php80, "Atributos PHP 8 #[...] (PHP >= 8.0)");
                if let Some(close_bracket) = self.find_matching(i + 1, end, "[", "]") {
                    let attrs = self.extract_attributes(i + 2, close_bracket);
                    pending_attrs.extend(attrs);
                    i = close_bracket + 1;
                    continue;
                }
            }

            // Namespace y Use solo a nivel TopLevel
            if scope == ScopeKind::TopLevel && !self.is_member_access(i) {
                if self.tokens[i].eq_ci("namespace")
                    && !(i + 1 < end && self.tokens[i + 1].is_punct("\\"))
                {
                    pending_attrs.clear();
                    i = self.parse_namespace(i, end);
                    continue;
                }
                if self.tokens[i].eq_ci("use") && !self.prev_is_rparen(i) {
                    pending_attrs.clear();
                    i = self.parse_use_import(i, end);
                    continue;
                }
            }

            // Declaración de clase / interface / trait / enum en TopLevel
            if scope == ScopeKind::TopLevel && !self.is_member_access(i) && !self.prev_is_new(i) {
                if let Some(next_i) = self.try_parse_class(i, end, &pending_attrs) {
                    pending_attrs.clear();
                    i = next_i;
                    continue;
                }
            }

            // Declaración de función o método en TopLevel o ClassBody
            if matches!(scope, ScopeKind::TopLevel | ScopeKind::ClassBody(_))
                && !self.is_member_access(i)
            {
                if let Some(next_i) = self.try_parse_function(i, end, scope, &pending_attrs) {
                    pending_attrs.clear();
                    i = next_i;
                    continue;
                }
            }

            // Miembros dentro de ClassBody (constantes, trait use, propiedades declaradas)
            if let ScopeKind::ClassBody(class_idx) = scope {
                if !self.is_member_access(i) {
                    if let Some(next_i) = self.try_parse_class_member(i, end, class_idx) {
                        pending_attrs.clear();
                        i = next_i;
                        continue;
                    }
                }
            }

            // Clase anónima: new class(...) { ... }
            if self.tokens[i].eq_ci("new")
                && !self.is_member_access(i)
                && i + 1 < end
                && self.tokens[i + 1].eq_ci("class")
            {
                pending_attrs.clear();
                if let Some(next_i) = self.parse_anon_class(i, end) {
                    i = next_i;
                    continue;
                }
            }

            // new PDO(...) / new mysqli(...)
            if self.tokens[i].eq_ci("new") && !self.is_member_access(i) {
                self.check_new_db_driver(i, end);
            }

            // include / require
            if let Some(inc_kind) = self.match_include_kind(i) {
                pending_attrs.clear();
                self.parse_include_statement(i, end, inc_kind);
                i += 1;
                continue;
            }

            // global $a, $b;
            if self.tokens[i].eq_ci("global") && !self.is_member_access(i) {
                pending_attrs.clear();
                self.parse_global_decl(i, end);
                i += 1;
                continue;
            }

            // Propiedad dinámica $this->prop = ... dentro de métodos de una clase
            if let ScopeKind::FunctionBody {
                owner_class: Some(class_idx),
            } = scope
            {
                self.check_dynamic_property_write(i, end, class_idx);
            }

            // Sitios de llamada a función / método / estático
            if let Some(advance_to) = self.try_parse_call_site(i, end) {
                pending_attrs.clear();
                i = advance_to;
                continue;
            }

            // Limpiar atributos pendientes si avanzamos fuera de modificadores de declaración
            if !is_declaration_modifier(&self.tokens[i]) {
                pending_attrs.clear();
            }

            // Recursión en llaves `{ ... }` dentro de TopLevel / FunctionBody / AnonClassBody
            if self.tokens[i].is_punct("{") {
                if let Some(close_brace) = self.find_matching(i, end, "{", "}") {
                    self.parse_range(i + 1, close_brace, scope);
                    i = close_brace + 1;
                    continue;
                }
            }

            i += 1;
        }
    }

    fn prev_is_rparen(&self, idx: usize) -> bool {
        idx > 0 && self.tokens[idx - 1].is_punct(")")
    }

    fn prev_is_new(&self, idx: usize) -> bool {
        idx > 0 && self.tokens[idx - 1].eq_ci("new")
    }

    fn find_matching(&self, open_idx: usize, end: usize, open: &str, close: &str) -> Option<usize> {
        if open_idx >= end || self.tokens[open_idx].tok.text != open {
            return None;
        }
        let mut depth = 0usize;
        for j in open_idx..end {
            let txt = &self.tokens[j].tok.text;
            if txt == open {
                depth += 1;
            } else if txt == close {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
        }
        None
    }

    fn extract_attributes(&self, start: usize, end: usize) -> Vec<ParsedAttr> {
        let mut attrs = Vec::new();
        let mut depth = 0usize;
        let mut idx = start;

        while idx < end {
            let t = &self.tokens[idx];
            if depth == 0 {
                // Leer nombre cualificado al inicio de cada elemento separado por coma
                let mut qname = String::new();
                while idx < end {
                    let cur = &self.tokens[idx];
                    if cur.is_punct("\\") || cur.tok.kind == PhpTokenKind::Word {
                        qname.push_str(&cur.tok.text);
                        idx += 1;
                    } else {
                        break;
                    }
                }
                if !qname.is_empty() {
                    attrs.push(ParsedAttr { name: qname });
                }
                while idx < end {
                    let cur = &self.tokens[idx];
                    if cur.is_punct("(") || cur.is_punct("[") || cur.is_punct("{") {
                        depth += 1;
                    } else if cur.is_punct(")") || cur.is_punct("]") || cur.is_punct("}") {
                        depth = depth.saturating_sub(1);
                    } else if cur.is_punct(",") && depth == 0 {
                        idx += 1;
                        break;
                    }
                    idx += 1;
                }
            } else {
                if t.is_punct("(") || t.is_punct("[") || t.is_punct("{") {
                    depth += 1;
                } else if t.is_punct(")") || t.is_punct("]") || t.is_punct("}") {
                    depth = depth.saturating_sub(1);
                }
                idx += 1;
            }
        }

        attrs
    }

    fn parse_namespace(&mut self, idx: usize, end: usize) -> usize {
        let mut j = idx + 1;
        let mut ns = String::new();
        while j < end {
            let t = &self.tokens[j];
            if t.is_punct(";") {
                if !ns.is_empty() {
                    self.namespace = Some(ns);
                }
                return j + 1;
            }
            if t.is_punct("{") {
                if !ns.is_empty() {
                    self.namespace = Some(ns);
                }
                if let Some(close_brace) = self.find_matching(j, end, "{", "}") {
                    self.parse_range(j + 1, close_brace, ScopeKind::TopLevel);
                    return close_brace + 1;
                }
                return j + 1;
            }
            if t.tok.kind == PhpTokenKind::Word || t.is_punct("\\") {
                ns.push_str(&t.tok.text);
            }
            j += 1;
        }
        j
    }

    fn parse_use_import(&mut self, idx: usize, end: usize) -> usize {
        let mut j = idx + 1;
        let mut kind_prefix = String::new();
        if j < end && (self.tokens[j].eq_ci("function") || self.tokens[j].eq_ci("const")) {
            kind_prefix = format!("{} ", self.tokens[j].tok.text.to_ascii_lowercase());
            j += 1;
        }

        let stmt_start = j;
        while j < end {
            if self.tokens[j].is_punct(";") {
                break;
            }
            if j > idx + 1 && self.tokens[j].block_id != self.tokens[j - 1].block_id {
                break;
            }
            j += 1;
        }

        let stmt_end = j;
        self.collect_use_items(stmt_start, stmt_end, &kind_prefix);

        if j < end && self.tokens[j].is_punct(";") {
            j + 1
        } else {
            j
        }
    }

    fn collect_use_items(&mut self, start: usize, end: usize, kind_prefix: &str) {
        // Soporta: use A\B, C\D as E; y group use: use Foo\Bar\{Baz, Qux as Q};
        let mut cur = start;
        while cur < end {
            // Buscar hasta ',' al nivel 0 o '{'
            let mut prefix = String::new();
            let mut found_group = false;
            while cur < end {
                let t = &self.tokens[cur];
                if t.is_punct("{") {
                    found_group = true;
                    break;
                }
                if t.is_punct(",") {
                    cur += 1;
                    break;
                }
                if t.eq_ci("as") {
                    prefix.push_str(" as ");
                } else if t.tok.kind == PhpTokenKind::Word || t.is_punct("\\") {
                    prefix.push_str(&t.tok.text);
                }
                cur += 1;
            }

            if found_group {
                let mut inner_cur = cur + 1;
                let mut inner_item = String::new();
                while inner_cur < end {
                    let t = &self.tokens[inner_cur];
                    if t.is_punct("}") {
                        let trimmed = inner_item.trim();
                        if !trimmed.is_empty() {
                            self.use_imports
                                .push(format!("{kind_prefix}{prefix}{trimmed}"));
                        }
                        inner_cur += 1;
                        break;
                    }
                    if t.is_punct(",") {
                        let trimmed = inner_item.trim();
                        if !trimmed.is_empty() {
                            self.use_imports
                                .push(format!("{kind_prefix}{prefix}{trimmed}"));
                        }
                        inner_item.clear();
                    } else if t.eq_ci("as") {
                        inner_item.push_str(" as ");
                    } else if (t.eq_ci("function") || t.eq_ci("const")) && inner_item.is_empty() {
                        inner_item.push_str(&t.tok.text.to_ascii_lowercase());
                        inner_item.push(' ');
                    } else if t.tok.kind == PhpTokenKind::Word || t.is_punct("\\") {
                        inner_item.push_str(&t.tok.text);
                    }
                    inner_cur += 1;
                }
                cur = inner_cur;
                if cur < end && self.tokens[cur].is_punct(",") {
                    cur += 1;
                }
            } else {
                let trimmed = prefix.trim();
                if !trimmed.is_empty() {
                    self.use_imports.push(format!("{kind_prefix}{trimmed}"));
                }
            }
        }
    }

    fn try_parse_class(
        &mut self,
        idx: usize,
        end: usize,
        pending_attrs: &[ParsedAttr],
    ) -> Option<usize> {
        let mut j = idx;
        let mut saw_readonly = false;
        while j < end {
            if self.tokens[j].eq_ci("abstract") || self.tokens[j].eq_ci("final") {
                j += 1;
            } else if self.tokens[j].eq_ci("readonly") {
                saw_readonly = true;
                j += 1;
            } else {
                break;
            }
        }

        if j >= end {
            return None;
        }

        let is_class = self.tokens[j].eq_ci("class");
        let is_interface = self.tokens[j].eq_ci("interface");
        let is_trait = self.tokens[j].eq_ci("trait");
        let is_enum = self.tokens[j].eq_ci("enum");

        if !(is_class || is_interface || is_trait || is_enum) {
            return None;
        }
        if j + 1 >= end || self.tokens[j + 1].tok.kind != PhpTokenKind::Word {
            return None;
        }

        if saw_readonly && is_class {
            self.add_marker(PhpVersion::Php82, "Clases readonly (PHP >= 8.2)");
        }
        if is_enum {
            self.add_marker(PhpVersion::Php81, "Enums (PHP >= 8.1)");
        }

        let class_name = self.tokens[j + 1].tok.text.clone();
        let mut k = j + 2;

        // Enum backing type (: string | : int)
        if is_enum && k < end && self.tokens[k].is_punct(":") {
            k += 1;
            while k < end
                && !self.tokens[k].eq_ci("implements")
                && !self.tokens[k].is_punct("{")
            {
                k += 1;
            }
        }

        let mut extends = None;
        if k < end && self.tokens[k].eq_ci("extends") {
            k += 1;
            let mut ext_parts = Vec::new();
            let mut cur_name = String::new();
            while k < end
                && !self.tokens[k].eq_ci("implements")
                && !self.tokens[k].is_punct("{")
            {
                if self.tokens[k].is_punct(",") {
                    if !cur_name.is_empty() {
                        ext_parts.push(cur_name.clone());
                        cur_name.clear();
                    }
                } else if self.tokens[k].tok.kind == PhpTokenKind::Word
                    || self.tokens[k].is_punct("\\")
                {
                    cur_name.push_str(&self.tokens[k].tok.text);
                }
                k += 1;
            }
            if !cur_name.is_empty() {
                ext_parts.push(cur_name);
            }
            if !ext_parts.is_empty() {
                extends = Some(ext_parts.join(", "));
            }
        }

        let mut implements = Vec::new();
        if k < end && self.tokens[k].eq_ci("implements") {
            k += 1;
            let mut cur_name = String::new();
            while k < end && !self.tokens[k].is_punct("{") {
                if self.tokens[k].is_punct(",") {
                    if !cur_name.is_empty() {
                        implements.push(cur_name.clone());
                        cur_name.clear();
                    }
                } else if self.tokens[k].tok.kind == PhpTokenKind::Word
                    || self.tokens[k].is_punct("\\")
                {
                    cur_name.push_str(&self.tokens[k].tok.text);
                }
                k += 1;
            }
            if !cur_name.is_empty() {
                implements.push(cur_name);
            }
        }

        while k < end && !self.tokens[k].is_punct("{") {
            k += 1;
        }
        if k >= end {
            return None;
        }

        let close_brace = self.find_matching(k, end, "{", "}")?;
        let header_start = self.tokens[idx].tok.span.start_byte;
        let header_end = if k > idx {
            self.tokens[k - 1].tok.span.end_byte
        } else {
            self.tokens[k].tok.span.start_byte
        };
        let header_span = lexer::span_from_bytes(self.source, header_start, header_end);
        let full_span = lexer::span_from_bytes(
            self.source,
            header_start,
            self.tokens[close_brace].tok.span.end_byte,
        );

        let has_allow_dynamic_properties = pending_attrs
            .iter()
            .any(|a| a.matches_short_name("AllowDynamicProperties"));

        let class_idx = self.classes.len();
        self.classes.push(ClassSummary {
            name: class_name,
            extends,
            implements,
            declared_properties: Vec::new(),
            dynamic_properties: Vec::new(),
            methods: Vec::new(),
            has_allow_dynamic_properties,
            header_span,
            span: full_span,
        });

        self.parse_range(k + 1, close_brace, ScopeKind::ClassBody(class_idx));

        // Filtrar propiedades dinámicas contra TODAS las propiedades declaradas de la clase.
        let declared_set: HashSet<String> = self.classes[class_idx]
            .declared_properties
            .iter()
            .cloned()
            .collect();
        self.classes[class_idx]
            .dynamic_properties
            .retain(|dp| !declared_set.contains(&dp.property_name));

        Some(close_brace + 1)
    }

    fn parse_anon_class(&mut self, idx: usize, end: usize) -> Option<usize> {
        let mut k = idx + 2; // tras `new class`
        if k < end && self.tokens[k].is_punct("(") {
            let close_p = self.find_matching(k, end, "(", ")")?;
            self.parse_range(k + 1, close_p, ScopeKind::AnonClassBody);
            k = close_p + 1;
        }
        while k < end && !self.tokens[k].is_punct("{") && !self.tokens[k].is_punct(";") {
            k += 1;
        }
        if k < end && self.tokens[k].is_punct("{") {
            let close_brace = self.find_matching(k, end, "{", "}")?;
            self.parse_range(k + 1, close_brace, ScopeKind::AnonClassBody);
            return Some(close_brace + 1);
        }
        None
    }

    fn try_parse_function(
        &mut self,
        idx: usize,
        end: usize,
        scope: ScopeKind,
        pending_attrs: &[ParsedAttr],
    ) -> Option<usize> {
        let mut j = idx;
        let mut visibility: Option<String> = None;
        let mut is_static = false;

        if matches!(scope, ScopeKind::ClassBody(_)) {
            while j < end {
                if self.tokens[j].eq_ci("public")
                    || self.tokens[j].eq_ci("protected")
                    || self.tokens[j].eq_ci("private")
                {
                    visibility = Some(self.tokens[j].tok.text.to_ascii_lowercase());
                    j += 1;
                } else if self.tokens[j].eq_ci("static") {
                    is_static = true;
                    j += 1;
                } else if self.tokens[j].eq_ci("final") || self.tokens[j].eq_ci("abstract") {
                    j += 1;
                } else {
                    break;
                }
            }
        }

        if j >= end || !self.tokens[j].eq_ci("function") {
            return None;
        }
        j += 1;
        if j < end && self.tokens[j].is_op("&") {
            j += 1;
        }
        if j >= end || self.tokens[j].tok.kind != PhpTokenKind::Word {
            return None;
        }
        let fn_name = self.tokens[j].tok.text.clone();
        j += 1;
        if j >= end || !self.tokens[j].is_punct("(") {
            return None;
        }

        let open_paren = j;
        let close_paren = self.find_matching(open_paren, end, "(", ")")?;

        let is_constructor = matches!(scope, ScopeKind::ClassBody(_))
            && fn_name.eq_ignore_ascii_case("__construct");
        let (params, promoted_props) =
            self.parse_params(open_paren + 1, close_paren, is_constructor);

        if let ScopeKind::ClassBody(class_idx) = scope {
            for prop in promoted_props {
                if !self.classes[class_idx].declared_properties.contains(&prop) {
                    self.classes[class_idx].declared_properties.push(prop);
                }
            }
        }

        let mut k = close_paren + 1;
        let mut return_type = None;
        if k < end && self.tokens[k].is_punct(":") {
            k += 1;
            let rt_start = k;
            while k < end && !self.tokens[k].is_punct("{") && !self.tokens[k].is_punct(";") {
                k += 1;
            }
            if k > rt_start {
                let start_b = self.tokens[rt_start].tok.span.start_byte;
                let end_b = self.tokens[k - 1].tok.span.end_byte;
                let rt_str = self.source[start_b..end_b].trim().to_string();
                self.inspect_type_markers(rt_start, k, &rt_str);
                return_type = Some(rt_str);
            }
        }

        while k < end && !self.tokens[k].is_punct("{") && !self.tokens[k].is_punct(";") {
            k += 1;
        }
        if k >= end {
            return None;
        }

        let sig_start = self.tokens[idx].tok.span.start_byte;
        let sig_end = self.tokens[k - 1].tok.span.end_byte;
        let signature_span = lexer::span_from_bytes(self.source, sig_start, sig_end);

        let has_return_type_will_change = pending_attrs
            .iter()
            .any(|a| a.matches_short_name("ReturnTypeWillChange"));

        let (body_span, full_end_byte, next_idx) = if self.tokens[k].is_punct("{") {
            let close_brace = self.find_matching(k, end, "{", "}")?;
            let b_span = lexer::span_from_bytes(
                self.source,
                self.tokens[k].tok.span.start_byte,
                self.tokens[close_brace].tok.span.end_byte,
            );
            let owner_class = match scope {
                ScopeKind::ClassBody(cidx) => Some(cidx),
                _ => None,
            };
            self.parse_range(
                k + 1,
                close_brace,
                ScopeKind::FunctionBody { owner_class },
            );
            (
                Some(b_span),
                self.tokens[close_brace].tok.span.end_byte,
                close_brace + 1,
            )
        } else {
            // Método abstracto o de interfaz terminado en ';'
            (None, self.tokens[k].tok.span.end_byte, k + 1)
        };

        let full_span = lexer::span_from_bytes(self.source, sig_start, full_end_byte);

        let summary = FunctionSummary {
            name: fn_name,
            visibility,
            is_static,
            params,
            return_type,
            has_return_type_will_change,
            signature_span,
            span: full_span,
            body_span,
        };

        match scope {
            ScopeKind::ClassBody(class_idx) => self.classes[class_idx].methods.push(summary),
            _ => self.functions.push(summary),
        }

        Some(next_idx)
    }

    fn parse_params(
        &mut self,
        start: usize,
        end: usize,
        is_constructor: bool,
    ) -> (Vec<ParamSummary>, Vec<String>) {
        let mut params = Vec::new();
        let mut promoted_props = Vec::new();
        if start >= end {
            return (params, promoted_props);
        }

        let mut slices: Vec<(usize, usize)> = Vec::new();
        let mut p_start = start;
        let mut depth = 0usize;
        let mut saw_trailing_comma = false;

        for idx in start..end {
            let t = &self.tokens[idx];
            if t.is_punct("(") || t.is_punct("[") || t.is_punct("{") {
                depth += 1;
            } else if t.is_punct(")") || t.is_punct("]") || t.is_punct("}") {
                depth = depth.saturating_sub(1);
            } else if t.is_punct(",") && depth == 0 {
                if p_start < idx {
                    slices.push((p_start, idx));
                }
                p_start = idx + 1;
                if idx + 1 == end {
                    saw_trailing_comma = true;
                }
            }
        }
        if p_start < end {
            slices.push((p_start, end));
        }

        if saw_trailing_comma && !slices.is_empty() {
            self.add_marker(
                PhpVersion::Php80,
                "Coma final en lista de parámetros (PHP >= 8.0)",
            );
        }

        for (s, e) in slices {
            if s >= e {
                continue;
            }
            let full_span = lexer::span_from_bytes(
                self.source,
                self.tokens[s].tok.span.start_byte,
                self.tokens[e - 1].tok.span.end_byte,
            );

            // Saltar atributos #[...] dentro del parámetro
            let mut cur = s;
            while cur + 1 < e && self.tokens[cur].is_punct("#") && self.tokens[cur + 1].is_punct("[")
            {
                self.add_marker(PhpVersion::Php80, "Atributos PHP 8 #[...] (PHP >= 8.0)");
                if let Some(close_b) = self.find_matching(cur + 1, e, "[", "]") {
                    cur = close_b + 1;
                } else {
                    break;
                }
            }

            // Modificadores de promoción de propiedades (PHP 8.0/8.1/8.4)
            let mut is_promoted = false;
            while cur < e {
                if self.tokens[cur].eq_ci("public")
                    || self.tokens[cur].eq_ci("protected")
                    || self.tokens[cur].eq_ci("private")
                {
                    is_promoted = true;
                    cur += 1;
                    // Visibilidad asimétrica PHP 8.4: public(set)
                    if cur + 2 < e
                        && self.tokens[cur].is_punct("(")
                        && self.tokens[cur + 1].eq_ci("set")
                        && self.tokens[cur + 2].is_punct(")")
                    {
                        self.add_marker(
                            PhpVersion::Php84,
                            "Visibilidad asimétrica PHP >= 8.4",
                        );
                        cur += 3;
                    }
                } else if self.tokens[cur].eq_ci("readonly") {
                    is_promoted = true;
                    self.add_marker(PhpVersion::Php81, "Propiedades readonly (PHP >= 8.1)");
                    cur += 1;
                } else {
                    break;
                }
            }

            if is_promoted {
                self.add_marker(
                    PhpVersion::Php80,
                    "Promoción de propiedades en constructor (PHP >= 8.0)",
                );
            }

            // Buscar '=' al nivel 0
            let mut eq_idx: Option<usize> = None;
            let mut d = 0usize;
            for k in cur..e {
                let t = &self.tokens[k];
                if t.is_punct("(") || t.is_punct("[") || t.is_punct("{") {
                    d += 1;
                } else if t.is_punct(")") || t.is_punct("]") || t.is_punct("}") {
                    d = d.saturating_sub(1);
                } else if t.is_op("=") && d == 0 {
                    eq_idx = Some(k);
                    break;
                }
            }

            let before_eq = eq_idx.unwrap_or(e);
            let Some(var_idx) = (cur..before_eq)
                .find(|&k| self.tokens[k].tok.kind == PhpTokenKind::Variable)
            else {
                continue;
            };

            let var_name = self.tokens[var_idx].tok.text.clone();
            if is_constructor && is_promoted {
                let prop_name = var_name.trim_start_matches('$').to_string();
                if !prop_name.is_empty() {
                    promoted_props.push(prop_name);
                }
            }

            // Type hint: entre `cur` y `var_idx` (excluyendo `&` y `...`)
            let mut type_end = var_idx;
            while type_end > cur
                && (self.tokens[type_end - 1].is_op("&") || self.tokens[type_end - 1].is_op("..."))
            {
                type_end -= 1;
            }

            let (type_hint, type_span, is_nullable) = if type_end > cur {
                let start_b = self.tokens[cur].tok.span.start_byte;
                let end_b = self.tokens[type_end - 1].tok.span.end_byte;
                let th = self.source[start_b..end_b].trim().to_string();
                let ts = lexer::span_from_bytes(self.source, start_b, end_b);
                let nullable = self.tokens[cur].is_punct("?")
                    || (cur..type_end).any(|k| {
                        self.tokens[k].eq_ci("null") || self.tokens[k].eq_ci("mixed")
                    });
                self.inspect_type_markers(cur, type_end, &th);
                (Some(th), Some(ts), nullable)
            } else {
                (None, None, false)
            };

            let (has_default, default_is_null) = if let Some(eq_pos) = eq_idx {
                let def_start = eq_pos + 1;
                let def_len = e.saturating_sub(def_start);
                let is_null = (def_len == 1 && self.tokens[def_start].eq_ci("null"))
                    || (def_len == 2
                        && self.tokens[def_start].is_punct("\\")
                        && self.tokens[def_start + 1].eq_ci("null"));
                (true, is_null)
            } else {
                (false, false)
            };

            params.push(ParamSummary {
                name: var_name,
                type_hint,
                is_nullable,
                has_default,
                default_is_null,
                span: full_span,
                type_span,
            });
        }

        (params, promoted_props)
    }

    fn inspect_type_markers(&mut self, start: usize, end: usize, type_str: &str) {
        let mut has_pipe = false;
        let mut has_amp = false;
        let mut has_mixed = false;
        let mut has_never = false;
        let mut count_words = 0usize;
        let mut has_standalone_lit = false;

        for k in start..end {
            let t = &self.tokens[k];
            if t.is_op("|") {
                has_pipe = true;
            } else if t.is_op("&") {
                has_amp = true;
            } else if t.eq_ci("mixed") {
                has_mixed = true;
            } else if t.eq_ci("never") {
                has_never = true;
            } else if t.eq_ci("null") || t.eq_ci("false") || t.eq_ci("true") {
                has_standalone_lit = true;
                count_words += 1;
            } else if t.tok.kind == PhpTokenKind::Word {
                count_words += 1;
            }
        }

        if has_pipe {
            self.add_marker(PhpVersion::Php80, "Union types (PHP >= 8.0)");
        }
        if has_amp {
            self.add_marker(PhpVersion::Php81, "Intersection types (PHP >= 8.1)");
        }
        if has_mixed {
            self.add_marker(PhpVersion::Php80, "Tipo mixed (PHP >= 8.0)");
        }
        if has_never {
            self.add_marker(PhpVersion::Php81, "Tipo de retorno never (PHP >= 8.1)");
        }
        if has_standalone_lit && !has_pipe && !has_amp && count_words == 1 && !type_str.starts_with('?') {
            self.add_marker(
                PhpVersion::Php82,
                "Tipos standalone null/false/true (PHP >= 8.2)",
            );
        }
    }

    fn try_parse_class_member(
        &mut self,
        idx: usize,
        end: usize,
        class_idx: usize,
    ) -> Option<usize> {
        // 1. Constantes de clase (con o sin visibilidad / final / tipo)
        let mut j = idx;
        while j < end
            && (self.tokens[j].eq_ci("public")
                || self.tokens[j].eq_ci("protected")
                || self.tokens[j].eq_ci("private")
                || self.tokens[j].eq_ci("final"))
        {
            j += 1;
        }
        if j < end && self.tokens[j].eq_ci("const") {
            // Verificar constante tipada (PHP 8.3): `const int FOO = 1;`
            let mut k = j + 1;
            let mut depth = 0usize;
            let mut before_eq = Vec::new();
            while k < end && !self.tokens[k].is_punct(";") {
                let t = &self.tokens[k];
                if t.is_punct("(") || t.is_punct("[") || t.is_punct("{") {
                    depth += 1;
                } else if t.is_punct(")") || t.is_punct("]") || t.is_punct("}") {
                    depth = depth.saturating_sub(1);
                } else if t.is_op("=") && depth == 0 {
                    break;
                }
                if depth == 0 {
                    before_eq.push(k);
                }
                k += 1;
            }
            if before_eq.len() >= 2 {
                self.add_marker(
                    PhpVersion::Php83,
                    "Constantes de clase tipadas (PHP >= 8.3)",
                );
            }
            while k < end && !self.tokens[k].is_punct(";") {
                k += 1;
            }
            return Some(if k < end { k + 1 } else { end });
        }

        // 2. Trait `use TraitA, TraitB;` o `use TraitA { ... }`
        if self.tokens[idx].eq_ci("use") {
            let mut k = idx + 1;
            while k < end {
                if self.tokens[k].is_punct(";") {
                    return Some(k + 1);
                }
                if self.tokens[k].is_punct("{") {
                    if let Some(close_b) = self.find_matching(k, end, "{", "}") {
                        return Some(close_b + 1);
                    }
                    return Some(end);
                }
                k += 1;
            }
            return Some(end);
        }

        // 3. Propiedades declaradas: public/protected/private/var/static/readonly
        let mut p = idx;
        let mut saw_prop_mod = false;
        let mut saw_readonly = false;
        while p < end {
            if self.tokens[p].eq_ci("public")
                || self.tokens[p].eq_ci("protected")
                || self.tokens[p].eq_ci("private")
            {
                saw_prop_mod = true;
                p += 1;
                if p + 2 < end
                    && self.tokens[p].is_punct("(")
                    && self.tokens[p + 1].eq_ci("set")
                    && self.tokens[p + 2].is_punct(")")
                {
                    self.add_marker(PhpVersion::Php84, "Visibilidad asimétrica PHP >= 8.4");
                    p += 3;
                }
            } else if self.tokens[p].eq_ci("var") || self.tokens[p].eq_ci("static") {
                saw_prop_mod = true;
                p += 1;
            } else if self.tokens[p].eq_ci("readonly") {
                saw_prop_mod = true;
                saw_readonly = true;
                p += 1;
            } else {
                break;
            }
        }

        if !saw_prop_mod || p >= end {
            return None;
        }
        // Si sigue `function` o `const`, no es propiedad (ya lo cubren los pasos previos si corresponde)
        if self.tokens[p].eq_ci("function") || self.tokens[p].eq_ci("const") {
            return None;
        }

        if saw_readonly {
            self.add_marker(PhpVersion::Php81, "Propiedades readonly (PHP >= 8.1)");
        }

        // Buscar el primer `$prop` y el `;` (o `{` en property hooks PHP 8.4)
        let type_start = p;
        let mut first_var: Option<usize> = None;
        let mut k = p;
        let mut depth = 0usize;
        let mut expecting_prop_name = true;

        while k < end {
            let t = &self.tokens[k];
            if t.is_punct("(") || t.is_punct("[") {
                depth += 1;
            } else if t.is_punct(")") || t.is_punct("]") {
                depth = depth.saturating_sub(1);
            } else if t.is_punct("{") && depth == 0 {
                // Property hooks PHP 8.4: public string $name { get => ...; }
                if let Some(close_b) = self.find_matching(k, end, "{", "}") {
                    k = close_b + 1;
                    break;
                }
                k = end;
                break;
            } else if t.is_punct(";") && depth == 0 {
                k += 1;
                break;
            } else if depth == 0 {
                if t.tok.kind == PhpTokenKind::Variable && expecting_prop_name {
                    if first_var.is_none() {
                        first_var = Some(k);
                    }
                    let prop_name = t.tok.text.trim_start_matches('$').to_string();
                    if !prop_name.is_empty()
                        && !self.classes[class_idx]
                            .declared_properties
                            .contains(&prop_name)
                    {
                        self.classes[class_idx].declared_properties.push(prop_name);
                    }
                } else if t.is_op("=") {
                    expecting_prop_name = false;
                } else if t.is_punct(",") {
                    expecting_prop_name = true;
                }
            }
            k += 1;
        }

        if let Some(fv) = first_var {
            if fv > type_start {
                self.add_marker(PhpVersion::Php74, "Propiedades tipadas (PHP >= 7.4)");
                let start_b = self.tokens[type_start].tok.span.start_byte;
                let end_b = self.tokens[fv - 1].tok.span.end_byte;
                let th = self.source[start_b..end_b].trim().to_string();
                self.inspect_type_markers(type_start, fv, &th);
            }
        }

        Some(k)
    }

    fn match_include_kind(&self, idx: usize) -> Option<IncludeKind> {
        if self.is_member_access(idx) {
            return None;
        }
        let t = &self.tokens[idx];
        if t.eq_ci("include") {
            Some(IncludeKind::Include)
        } else if t.eq_ci("include_once") {
            Some(IncludeKind::IncludeOnce)
        } else if t.eq_ci("require") {
            Some(IncludeKind::Require)
        } else if t.eq_ci("require_once") {
            Some(IncludeKind::RequireOnce)
        } else {
            None
        }
    }

    fn parse_include_statement(&mut self, idx: usize, end: usize, kind: IncludeKind) {
        let expr_start_idx = idx + 1;
        if expr_start_idx >= end {
            return;
        }
        let kw_block = self.tokens[idx].block_id;
        let mut j = expr_start_idx;
        let mut paren_depth = 0usize;
        let mut bracket_depth = 0usize;

        while j < end {
            let t = &self.tokens[j];
            if t.block_id != kw_block {
                break;
            }
            if t.is_punct("(") {
                paren_depth += 1;
            } else if t.is_punct(")") {
                if paren_depth == 0 {
                    break;
                }
                paren_depth -= 1;
            } else if t.is_punct("[") {
                bracket_depth += 1;
            } else if t.is_punct("]") {
                if bracket_depth == 0 {
                    break;
                }
                bracket_depth -= 1;
            } else if paren_depth == 0
                && bracket_depth == 0
                && (t.is_punct(";") || t.is_punct(",") || t.is_punct(":"))
            {
                break;
            }
            j += 1;
        }

        if j <= expr_start_idx {
            return;
        }

        let expr_tokens = &self.tokens[expr_start_idx..j];
        let expr_start_byte = expr_tokens[0].tok.span.start_byte;
        let expr_end_byte = expr_tokens[expr_tokens.len() - 1].tok.span.end_byte;
        let target_expr = self.source[expr_start_byte..expr_end_byte]
            .trim()
            .to_string();
        let span = lexer::span_from_bytes(
            self.source,
            self.tokens[idx].tok.span.start_byte,
            expr_end_byte,
        );

        let (resolved_path, is_dynamic) = self.resolve_include_expr(expr_tokens);

        self.includes.push(IncludeStatement {
            kind,
            target_expr,
            resolved_path,
            is_dynamic,
            span,
        });
    }

    fn resolve_include_expr(&self, mut expr_tokens: &[Tok]) -> (Option<PathBuf>, bool) {
        // Quitar paréntesis externos balanceados: include('a.php') o require_once(__DIR__ . '/a.php')
        while expr_tokens.len() >= 2
            && expr_tokens[0].is_punct("(")
            && expr_tokens[expr_tokens.len() - 1].is_punct(")")
            && is_balanced_outer_parens(expr_tokens)
        {
            expr_tokens = &expr_tokens[1..expr_tokens.len() - 1];
        }

        if expr_tokens.is_empty() {
            return (None, true);
        }

        // Dividir por '.' al nivel 0
        let mut parts: Vec<&[Tok]> = Vec::new();
        let mut start = 0usize;
        let mut depth = 0usize;
        for (idx, t) in expr_tokens.iter().enumerate() {
            if t.is_punct("(") || t.is_punct("[") {
                depth += 1;
            } else if t.is_punct(")") || t.is_punct("]") {
                depth = depth.saturating_sub(1);
            } else if t.is_op(".") && depth == 0 {
                parts.push(&expr_tokens[start..idx]);
                start = idx + 1;
            }
        }
        parts.push(&expr_tokens[start..]);

        let mut base_dir_override: Option<PathBuf> = None;
        let mut combined_str = String::new();
        let mut is_pure_static_string = parts.len() == 1;

        for (p_idx, part) in parts.iter().enumerate() {
            if part.is_empty() {
                return (None, true);
            }
            if part.len() == 1 && part[0].tok.kind == PhpTokenKind::StringLiteral {
                let Some(unquoted) = unquote_static_string(&part[0].tok.text) else {
                    return (None, true);
                };
                combined_str.push_str(&unquoted);
            } else if p_idx == 0 && part.len() == 1 && part[0].eq_ci("__DIR__") {
                is_pure_static_string = false;
                base_dir_override = Some(self.file_dir.clone());
            } else if p_idx == 0 && is_dirname_file_pattern(part) {
                is_pure_static_string = false;
                base_dir_override = Some(self.file_dir.clone());
            } else if p_idx == 0 && is_dirname_dir_pattern(part) {
                is_pure_static_string = false;
                let Some(parent) = self.file_dir.parent() else {
                    return (None, true);
                };
                base_dir_override = Some(parent.to_path_buf());
            } else if part.len() == 1 && part[0].eq_ci("DIRECTORY_SEPARATOR") {
                is_pure_static_string = false;
                combined_str.push('/');
            } else {
                return (None, true);
            }
        }

        let norm_rel_str = combined_str.replace('\\', "/");
        if norm_rel_str.is_empty() {
            return (None, !is_pure_static_string);
        }

        if let Some(base_dir) = base_dir_override {
            let trimmed = norm_rel_str.trim_start_matches('/');
            let joined = base_dir.join(trimmed);
            let normalized = normalize_lexical_rel(&joined);
            return (normalized, false);
        }

        // Ruta literal como 'includes/db.php' o '../config.php'
        if norm_rel_str.starts_with('/') {
            // Ruta absoluta del sistema operativo (no relativa al proyecto)
            let abs = Path::new(&norm_rel_str);
            if abs.starts_with(self.project_root) {
                return (
                    Some(normalize_relative_path(abs, self.project_root)),
                    false,
                );
            }
            return (None, false);
        }

        let from_file_dir = normalize_lexical_rel(&self.file_dir.join(&norm_rel_str));
        let from_root = normalize_lexical_rel(Path::new(&norm_rel_str));

        // Si el proyecto existe en disco, verificar primero respecto a carpeta del archivo, luego project_root.
        if let Some(ref rel_f) = from_file_dir {
            if self.project_root.join(rel_f).exists() {
                return (Some(rel_f.clone()), false);
            }
        }
        if let Some(ref rel_r) = from_root {
            if self.project_root.join(rel_r).exists() {
                return (Some(rel_r.clone()), false);
            }
        }

        // En análisis en memoria (o si aún no existe), preferir relativo a la carpeta del archivo.
        (from_file_dir.or(from_root), false)
    }

    fn parse_global_decl(&mut self, idx: usize, end: usize) {
        let kw_block = self.tokens[idx].block_id;
        for j in (idx + 1)..end {
            let t = &self.tokens[j];
            if t.block_id != kw_block || t.is_punct(";") {
                break;
            }
            if t.tok.kind == PhpTokenKind::Variable && self.globals_seen.insert(t.tok.text.clone())
            {
                self.globals_declared.push(t.tok.text.clone());
            }
        }
    }

    fn check_dynamic_property_write(&mut self, idx: usize, end: usize, class_idx: usize) {
        if idx + 3 >= end {
            return;
        }
        if self.tokens[idx].tok.kind != PhpTokenKind::Variable
            || self.tokens[idx].tok.text != "$this"
        {
            return;
        }
        if !self.tokens[idx + 1].is_op("->") {
            return;
        }
        if self.tokens[idx + 2].tok.kind != PhpTokenKind::Word {
            return;
        }
        let op = &self.tokens[idx + 3];
        if op.tok.kind != PhpTokenKind::Operator
            || !matches!(
                op.tok.text.as_str(),
                "=" | "+=" | "-=" | "*=" | "/=" | ".=" | "%=" | "??=" | "&=" | "|=" | "^="
                    | "<<=" | ">>=" | "**="
            )
        {
            return;
        }

        let prop_name = self.tokens[idx + 2].tok.text.clone();
        let span = lexer::span_from_bytes(
            self.source,
            self.tokens[idx].tok.span.start_byte,
            self.tokens[idx + 2].tok.span.end_byte,
        );
        self.classes[class_idx]
            .dynamic_properties
            .push(DynamicPropertyWrite {
                property_name: prop_name,
                span,
            });
    }

    fn check_new_db_driver(&mut self, idx: usize, end: usize) {
        let mut k = idx + 1;
        let mut last_word: Option<String> = None;
        while k < end {
            let t = &self.tokens[k];
            if t.is_punct("\\") {
                k += 1;
            } else if t.tok.kind == PhpTokenKind::Word {
                last_word = Some(t.tok.text.clone());
                k += 1;
            } else {
                break;
            }
        }

        if let Some(cls) = last_word {
            let line = self.tokens[idx].tok.span.start_line;
            if cls.eq_ignore_ascii_case("PDO") {
                self.saw_pdo = true;
                self.db_interactions.push(DbInteraction {
                    driver: "pdo".to_string(),
                    kind: "connect".to_string(),
                    line,
                    snippet: self.snippet_for_line(line),
                });
            } else if cls.eq_ignore_ascii_case("mysqli") {
                self.saw_mysqli = true;
                self.db_interactions.push(DbInteraction {
                    driver: "mysqli".to_string(),
                    kind: "connect".to_string(),
                    line,
                    snippet: self.snippet_for_line(line),
                });
            }
        }
    }

    fn try_parse_call_site(&mut self, idx: usize, end: usize) -> Option<usize> {
        // Caso A: llamada a método `$obj->method(` o `$obj?->method(`
        if (self.tokens[idx].is_op("->") || self.tokens[idx].is_op("?->"))
            && idx + 2 < end
            && self.tokens[idx + 1].tok.kind == PhpTokenKind::Word
            && self.tokens[idx + 2].is_punct("(")
        {
            let name = self.tokens[idx + 1].tok.text.clone();
            let method_start_byte = self.tokens[idx + 1].tok.span.start_byte;
            let line = self.tokens[idx + 1].tok.span.start_line;
            let open_paren = idx + 2;
            let close_paren = self.find_matching(open_paren, end, "(", ")")?;
            let args = self.parse_call_args(open_paren + 1, close_paren);
            let span = lexer::span_from_bytes(
                self.source,
                method_start_byte,
                self.tokens[close_paren].tok.span.end_byte,
            );

            let lower = name.to_ascii_lowercase();
            if matches!(lower.as_str(), "query" | "prepare" | "execute") {
                let kind = if lower == "prepare" {
                    "prepare"
                } else {
                    "query"
                };
                self.db_interactions.push(DbInteraction {
                    driver: "__method__".to_string(),
                    kind: kind.to_string(),
                    line,
                    snippet: self.snippet_for_line(line),
                });
            }

            self.calls.push(FunctionCallSite {
                name,
                is_method_call: true,
                is_static_call: false,
                args,
                span,
            });
            return Some(open_paren + 1);
        }

        // Caso B y C: nombre cualificado `Foo\bar(` o `Class::method(`
        if !self.is_prev_ns_or_member(idx)
            && (self.tokens[idx].tok.kind == PhpTokenKind::Word || self.tokens[idx].is_punct("\\"))
            && !self.prev_is_non_call_keyword(idx)
        {
            let mut k = idx;
            let mut qname = String::new();
            let mut last_was_word = false;
            while k < end {
                let t = &self.tokens[k];
                if t.is_punct("\\") {
                    qname.push('\\');
                    last_was_word = false;
                    k += 1;
                } else if t.tok.kind == PhpTokenKind::Word {
                    qname.push_str(&t.tok.text);
                    last_was_word = true;
                    k += 1;
                } else {
                    break;
                }
            }

            if !last_was_word || qname.is_empty() {
                return None;
            }

            // Caso B: llamada estática `Class::method(`
            if k + 2 < end
                && self.tokens[k].is_op("::")
                && self.tokens[k + 1].tok.kind == PhpTokenKind::Word
                && self.tokens[k + 2].is_punct("(")
            {
                let class_clean = qname.trim_start_matches('\\').to_string();
                let method_name = self.tokens[k + 1].tok.text.clone();
                let open_paren = k + 2;
                let close_paren = self.find_matching(open_paren, end, "(", ")")?;
                let args = self.parse_call_args(open_paren + 1, close_paren);
                let span = lexer::span_from_bytes(
                    self.source,
                    self.tokens[idx].tok.span.start_byte,
                    self.tokens[close_paren].tok.span.end_byte,
                );
                let full_name = format!("{class_clean}::{method_name}");
                let line = self.tokens[idx].tok.span.start_line;

                let last_seg = class_clean.rsplit('\\').next().unwrap_or(&class_clean);
                if last_seg.eq_ignore_ascii_case("PDO") {
                    self.saw_pdo = true;
                } else if last_seg.eq_ignore_ascii_case("DB") {
                    let m_lower = method_name.to_ascii_lowercase();
                    let kind = if m_lower == "connection" {
                        "connect"
                    } else {
                        "query"
                    };
                    self.db_interactions.push(DbInteraction {
                        driver: "laravel_db".to_string(),
                        kind: kind.to_string(),
                        line,
                        snippet: self.snippet_for_line(line),
                    });
                }

                self.calls.push(FunctionCallSite {
                    name: full_name,
                    is_method_call: false,
                    is_static_call: true,
                    args,
                    span,
                });
                return Some(open_paren + 1);
            }

            // Caso C: llamada a función standalone `foo(` o `\strlen(`
            if k < end && self.tokens[k].is_punct("(") {
                let fn_clean = qname.trim_start_matches('\\').to_string();
                let fn_lower = fn_clean.to_ascii_lowercase();

                if is_control_construct(&fn_lower) {
                    return None;
                }

                let open_paren = k;
                let close_paren = self.find_matching(open_paren, end, "(", ")")?;
                let args = self.parse_call_args(open_paren + 1, close_paren);
                let span = lexer::span_from_bytes(
                    self.source,
                    self.tokens[idx].tok.span.start_byte,
                    self.tokens[close_paren].tok.span.end_byte,
                );
                let line = self.tokens[idx].tok.span.start_line;

                self.record_function_db_and_version_markers(&fn_lower, line);

                self.calls.push(FunctionCallSite {
                    name: fn_clean,
                    is_method_call: false,
                    is_static_call: false,
                    args,
                    span,
                });
                return Some(open_paren + 1);
            }
        }

        None
    }

    fn prev_is_non_call_keyword(&self, idx: usize) -> bool {
        if idx == 0 {
            return false;
        }
        let mut check_idx = idx - 1;
        if self.tokens[check_idx].is_op("&") && check_idx > 0 {
            check_idx -= 1;
        }
        let p = &self.tokens[check_idx];
        p.eq_ci("function")
            || p.eq_ci("new")
            || p.eq_ci("class")
            || p.eq_ci("interface")
            || p.eq_ci("trait")
            || p.eq_ci("enum")
            || p.eq_ci("extends")
            || p.eq_ci("implements")
            || p.eq_ci("namespace")
            || p.eq_ci("use")
            || p.eq_ci("const")
            || p.eq_ci("instanceof")
    }

    fn parse_call_args(&mut self, start: usize, end: usize) -> Vec<CallArg> {
        let mut args = Vec::new();
        if start >= end {
            return args;
        }

        let mut arg_start = start;
        let mut depth = 0usize;

        for idx in start..end {
            let t = &self.tokens[idx];
            if t.is_punct("(") || t.is_punct("[") || t.is_punct("{") {
                depth += 1;
            } else if t.is_punct(")") || t.is_punct("]") || t.is_punct("}") {
                depth = depth.saturating_sub(1);
            } else if t.is_punct(",") && depth == 0 {
                if arg_start < idx {
                    self.push_call_arg(&mut args, arg_start, idx);
                }
                arg_start = idx + 1;
            }
        }

        if arg_start < end {
            self.push_call_arg(&mut args, arg_start, end);
        }

        args
    }

    fn push_call_arg(&mut self, args: &mut Vec<CallArg>, start: usize, end: usize) {
        if end - start >= 2
            && self.tokens[start].tok.kind == PhpTokenKind::Word
            && self.tokens[start + 1].is_punct(":")
        {
            self.add_marker(PhpVersion::Php80, "Argumentos nombrados (PHP >= 8.0)");
        }

        let sb = self.tokens[start].tok.span.start_byte;
        let eb = self.tokens[end - 1].tok.span.end_byte;
        let text = self.source[sb..eb].trim().to_string();
        let span = lexer::span_from_bytes(self.source, sb, eb);
        args.push(CallArg { text, span });
    }

    fn record_function_db_and_version_markers(&mut self, fn_lower: &str, line: usize) {
        if fn_lower.starts_with("mysql_") {
            self.add_marker(
                PhpVersion::Php74,
                "Uso de extensión ext-mysql (eliminada en PHP 7.0, código heredado)",
            );
            let kind = match fn_lower {
                "mysql_connect" | "mysql_pconnect" | "mysql_select_db" => "connect",
                _ => "query",
            };
            self.db_interactions.push(DbInteraction {
                driver: "mysql".to_string(),
                kind: kind.to_string(),
                line,
                snippet: self.snippet_for_line(line),
            });
        } else if fn_lower.starts_with("mysqli_") {
            self.saw_mysqli = true;
            let kind = match fn_lower {
                "mysqli_connect" | "mysqli_real_connect" | "mysqli_init" | "mysqli_select_db" => {
                    "connect"
                }
                "mysqli_prepare" | "mysqli_stmt_prepare" => "prepare",
                _ => "query",
            };
            self.db_interactions.push(DbInteraction {
                driver: "mysqli".to_string(),
                kind: kind.to_string(),
                line,
                snippet: self.snippet_for_line(line),
            });
        } else if fn_lower.starts_with("oci_") {
            let kind = match fn_lower {
                "oci_connect" | "oci_pconnect" | "oci_new_connect" => "connect",
                "oci_parse" | "oci_bind_by_name" | "oci_bind_array_by_name" => "prepare",
                _ => "query",
            };
            self.db_interactions.push(DbInteraction {
                driver: "oci8".to_string(),
                kind: kind.to_string(),
                line,
                snippet: self.snippet_for_line(line),
            });
        } else if matches!(fn_lower, "create_function" | "each") {
            self.add_marker(
                PhpVersion::Php74,
                "Funciones heredadas eliminadas antes de PHP 8.0 (create_function/each)",
            );
        }
    }

    fn scan_string_for_superglobals(&mut self, idx: usize) {
        const NAMES: &[&str] = &[
            "$_GET",
            "$_POST",
            "$_REQUEST",
            "$_SESSION",
            "$_COOKIE",
            "$_FILES",
            "$_SERVER",
            "$GLOBALS",
        ];
        let text = &self.tokens[idx].tok.text;
        let base_line = self.tokens[idx].tok.span.start_line;
        let bytes = text.as_bytes();
        let mut i = 0usize;
        let mut line_offset = 0usize;

        while i < bytes.len() {
            if bytes[i] == b'\\' {
                i += 1;
                if i < bytes.len() {
                    i += text[i..].chars().next().map_or(1, char::len_utf8);
                }
                continue;
            }
            if bytes[i] == b'\n' {
                line_offset += 1;
                i += 1;
                continue;
            }
            if bytes[i] == b'$' {
                let rem = &text[i..];
                let mut matched = false;
                for &sg in NAMES {
                    if rem.starts_with(sg) {
                        let next_b = rem.as_bytes().get(sg.len()).copied();
                        let is_word_end = !matches!(
                            next_b,
                            Some(b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_')
                        );
                        if is_word_end {
                            self.superglobals.push((sg.to_string(), base_line + line_offset));
                            i += sg.len();
                            matched = true;
                            break;
                        }
                    }
                }
                if matched {
                    continue;
                }
            }
            i += text[i..].chars().next().map_or(1, char::len_utf8);
        }
    }
}

fn is_superglobal(name: &str) -> bool {
    matches!(
        name,
        "$_GET"
            | "$_POST"
            | "$_REQUEST"
            | "$_SESSION"
            | "$_COOKIE"
            | "$_FILES"
            | "$_SERVER"
            | "$GLOBALS"
    )
}

fn is_declaration_modifier(tok: &Tok) -> bool {
    tok.eq_ci("abstract")
        || tok.eq_ci("final")
        || tok.eq_ci("readonly")
        || tok.eq_ci("public")
        || tok.eq_ci("protected")
        || tok.eq_ci("private")
        || tok.eq_ci("static")
        || tok.eq_ci("var")
}

fn is_control_construct(lower: &str) -> bool {
    matches!(
        lower,
        "if" | "elseif"
            | "while"
            | "for"
            | "foreach"
            | "switch"
            | "catch"
            | "match"
            | "declare"
            | "return"
            | "throw"
            | "yield"
            | "clone"
            | "fn"
            | "function"
            | "use"
            | "class"
            | "public"
            | "protected"
            | "private"
            | "array"
            | "list"
            | "echo"
            | "print"
            | "include"
            | "include_once"
            | "require"
            | "require_once"
    )
}

fn is_balanced_outer_parens(tokens: &[Tok]) -> bool {
    if tokens.len() < 2 || !tokens[0].is_punct("(") || !tokens[tokens.len() - 1].is_punct(")") {
        return false;
    }
    let mut depth = 0usize;
    for (idx, t) in tokens.iter().enumerate() {
        if t.is_punct("(") {
            depth += 1;
        } else if t.is_punct(")") {
            depth -= 1;
            if depth == 0 && idx + 1 < tokens.len() {
                return false;
            }
        }
    }
    depth == 0
}

fn is_dirname_file_pattern(tokens: &[Tok]) -> bool {
    tokens.len() == 4
        && tokens[0].eq_ci("dirname")
        && tokens[1].is_punct("(")
        && tokens[2].eq_ci("__FILE__")
        && tokens[3].is_punct(")")
}

fn is_dirname_dir_pattern(tokens: &[Tok]) -> bool {
    let direct_dir = tokens.len() == 4
        && tokens[0].eq_ci("dirname")
        && tokens[1].is_punct("(")
        && tokens[2].eq_ci("__DIR__")
        && tokens[3].is_punct(")");
    let nested_file = tokens.len() == 7
        && tokens[0].eq_ci("dirname")
        && tokens[1].is_punct("(")
        && tokens[2].eq_ci("dirname")
        && tokens[3].is_punct("(")
        && tokens[4].eq_ci("__FILE__")
        && tokens[5].is_punct(")")
        && tokens[6].is_punct(")");
    direct_dir || nested_file
}

fn unquote_static_string(raw: &str) -> Option<String> {
    if raw.len() < 2 {
        return None;
    }
    if raw.starts_with('\'') && raw.ends_with('\'') {
        let inner = &raw[1..raw.len() - 1];
        return Some(inner.replace("\\'", "'").replace("\\\\", "\\"));
    }
    if raw.starts_with('"') && raw.ends_with('"') {
        let inner = &raw[1..raw.len() - 1];
        // Detectar interpolación no escapada `$` dentro de comillas dobles
        let bytes = inner.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == b'$' {
                return None;
            }
            i += 1;
        }
        return Some(inner.replace("\\\"", "\"").replace("\\\\", "\\"));
    }
    None
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

/// Normaliza una ruta respecto a `project_root` usando separadores `/` limpios.
pub(crate) fn normalize_relative_path(path: &Path, project_root: &Path) -> PathBuf {
    let p_norm = path.to_string_lossy().replace('\\', "/");
    let r_norm = project_root
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_string();

    let stripped = if !r_norm.is_empty() && r_norm != "." {
        if let Some(rest) = strip_prefix_platform(&p_norm, &r_norm) {
            rest.trim_start_matches('/').to_string()
        } else {
            p_norm
        }
    } else {
        p_norm
    };

    normalize_lexical_rel(Path::new(&stripped)).unwrap_or_else(|| PathBuf::from(&stripped))
}

fn strip_prefix_platform<'a>(path: &'a str, root: &str) -> Option<&'a str> {
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

fn normalize_lexical_rel(path: &Path) -> Option<PathBuf> {
    let raw = path.to_string_lossy().replace('\\', "/");
    let mut stack: Vec<String> = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                stack.pop()?;
            }
            other => {
                // Evitar prefijos de disco al construir rutas relativas
                if stack.is_empty() && matches!(Path::new(other).components().next(), Some(Component::Prefix(_))) {
                    stack.push(other.to_string());
                } else {
                    stack.push(other.to_string());
                }
            }
        }
    }
    if stack.is_empty() {
        Some(PathBuf::from("."))
    } else {
        Some(PathBuf::from(stack.join("/")))
    }
}
