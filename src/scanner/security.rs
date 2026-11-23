use crate::models::{FileSummary, SecurityCategory, SecurityFinding, Severity};
use crate::parser::lexer::{PhpToken, PhpTokenKind};
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

const SUPERGLOBALS: &[&str] = &["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"];

/// Analiza las vulnerabilidades de seguridad estática únicamente dentro de los bloques PHP de un archivo.
pub fn scan_security_file(
    path: &Path,
    source: &str,
    summary: &FileSummary,
) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();
    let mut block_tokens: Vec<Vec<PhpToken>> = Vec::new();

    for block in summary.blocks.iter().filter(|b| b.is_php) {
        block_tokens.push(crate::parser::tokenize_php_block(source, block));
    }

    let has_upload_validation = detect_upload_validation(&block_tokens);
    let tainted_vars = collect_tainted_variables(&block_tokens);

    for tokens in &block_tokens {
        let sig: Vec<&PhpToken> = tokens
            .iter()
            .filter(|t| !matches!(t.kind, PhpTokenKind::Comment | PhpTokenKind::Whitespace))
            .collect();

        if sig.is_empty() {
            continue;
        }

        scan_calls_and_constructs(
            path,
            source,
            &sig,
            has_upload_validation,
            &tainted_vars,
            &mut findings,
        );
        scan_backticks(path, source, &sig, &tainted_vars, &mut findings);
        scan_sql_statements(path, source, &sig, &tainted_vars, &mut findings);
    }

    findings
}

fn scan_calls_and_constructs(
    path: &Path,
    source: &str,
    sig: &[&PhpToken],
    has_upload_validation: bool,
    tainted_vars: &HashSet<String>,
    findings: &mut Vec<SecurityFinding>,
) {
    let mut i = 0;
    while i < sig.len() {
        let tok = sig[i];

        // 1. include / include_once / require / require_once dinámico
        if tok.kind == PhpTokenKind::Word
            && is_include_keyword(&tok.text)
            && is_standalone_construct(sig, i)
        {
            let stmt_end = find_statement_end(sig, i + 1);
            let expr_tokens = &sig[i + 1..stmt_end];
            if has_user_input(expr_tokens, tainted_vars) {
                let end_byte = expr_tokens
                    .last()
                    .map(|t| t.span.end_byte)
                    .unwrap_or(tok.span.end_byte);
                let direct_sg = expr_tokens.iter().any(|t| is_superglobal_token(t));
                findings.push(make_finding(
                    path,
                    source,
                    SecurityCategory::DynamicIncludeLfi,
                    if direct_sg {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    tok.span.start_line,
                    tok.span.start_col,
                    tok.span.start_byte,
                    end_byte,
                    "Inclusión dinámica de archivo controlada por entrada de usuario (riesgo LFI/RFI).".to_string(),
                    "Reemplaza por una lista blanca (switch/array) de rutas permitidas y valida con basename()/realpath().".to_string(),
                ));
            }
            i = stmt_end;
            continue;
        }

        // 2. Llamadas a funciones / constructos con paréntesis
        if tok.kind == PhpTokenKind::Word
            && i + 1 < sig.len()
            && sig[i + 1].text == "("
            && is_standalone_call(sig, i)
        {
            let lower = tok.text.to_ascii_lowercase();
            if let Some((close_idx, args)) = extract_paren_range(sig, i + 1) {
                let all_arg_tokens = if i + 2 <= close_idx {
                    &sig[i + 2..close_idx]
                } else {
                    &[]
                };
                let end_byte = sig[close_idx].span.end_byte;
                let has_sg = all_arg_tokens.iter().any(|t| is_superglobal_token(t));
                let has_taint = has_user_input(all_arg_tokens, tainted_vars);

                match lower.as_str() {
                    "eval" => {
                        if let Some(decoder) = detect_backdoor_decoder(all_arg_tokens) {
                            findings.push(make_finding(
                                path,
                                source,
                                SecurityCategory::BackdoorPattern,
                                Severity::Critical,
                                tok.span.start_line,
                                tok.span.start_col,
                                tok.span.start_byte,
                                end_byte,
                                format!("Patrón típico de webshell detectado: eval({decoder}(...))."),
                                "Inspecciona el origen del archivo de inmediato; elimina la puerta trasera y rota credenciales.".to_string(),
                            ));
                        } else {
                            let sev = if has_taint {
                                Severity::Critical
                            } else {
                                Severity::High
                            };
                            findings.push(make_finding(
                                path,
                                source,
                                SecurityCategory::RemoteCodeExecution,
                                sev,
                                tok.span.start_line,
                                tok.span.start_col,
                                tok.span.start_byte,
                                end_byte,
                                "Uso de eval() permite ejecución arbitraria de código PHP.".to_string(),
                                "Elimina eval() y reemplaza por lógica explícita, closures o plantillas seguras.".to_string(),
                            ));
                        }
                    }
                    "assert" => {
                        if is_risky_assert_args(all_arg_tokens) {
                            if let Some(decoder) = detect_backdoor_decoder(all_arg_tokens) {
                                findings.push(make_finding(
                                    path,
                                    source,
                                    SecurityCategory::BackdoorPattern,
                                    Severity::Critical,
                                    tok.span.start_line,
                                    tok.span.start_col,
                                    tok.span.start_byte,
                                    end_byte,
                                    format!("Patrón sospechoso de backdoor con assert({decoder}(...))."),
                                    "Audita el archivo en busca de compromiso y elimina el código ofuscado.".to_string(),
                                ));
                            } else {
                                findings.push(make_finding(
                                    path,
                                    source,
                                    SecurityCategory::RemoteCodeExecution,
                                    if has_taint {
                                        Severity::Critical
                                    } else {
                                        Severity::High
                                    },
                                    tok.span.start_line,
                                    tok.span.start_col,
                                    tok.span.start_byte,
                                    end_byte,
                                    "Uso de assert() con expresión/variable dinámica (ejecutable como código en PHP < 8.0 y deprecado para strings en 8.x).".to_string(),
                                    "Usa validaciones condicionales explícitas (if/throw) en lugar de assert() sobre datos dinámicos.".to_string(),
                                ));
                            }
                        }
                    }
                    "create_function" => {
                        findings.push(make_finding(
                            path,
                            source,
                            SecurityCategory::RemoteCodeExecution,
                            if has_taint {
                                Severity::Critical
                            } else {
                                Severity::High
                            },
                            tok.span.start_line,
                            tok.span.start_col,
                            tok.span.start_byte,
                            end_byte,
                            "create_function() evalúa código dinámicamente (equivalente a eval) y fue eliminada en PHP 8.0.".to_string(),
                            "Reemplaza por una función anónima / closure nativo: function(...) { ... }.".to_string(),
                        ));
                    }
                    "preg_replace" => {
                        if let Some((a0_start, a0_end)) = args.first().copied() {
                            if preg_pattern_has_eval_modifier(&sig[a0_start..a0_end]) {
                                let is_backdoor = detect_backdoor_decoder(all_arg_tokens).is_some();
                                let (cat, sev, desc) = if is_backdoor {
                                    (
                                        SecurityCategory::BackdoorPattern,
                                        Severity::Critical,
                                        "preg_replace() con modificador /e y decodificación ofuscada (firma típica de webshell).".to_string(),
                                    )
                                } else {
                                    (
                                        SecurityCategory::RemoteCodeExecution,
                                        if has_taint {
                                            Severity::Critical
                                        } else {
                                            Severity::High
                                        },
                                        "preg_replace() con modificador /e ejecuta el reemplazo como código PHP (eliminado en PHP 7.0+).".to_string(),
                                    )
                                };
                                findings.push(make_finding(
                                    path,
                                    source,
                                    cat,
                                    sev,
                                    tok.span.start_line,
                                    tok.span.start_col,
                                    tok.span.start_byte,
                                    end_byte,
                                    desc,
                                    "Migra a preg_replace_callback() eliminando el modificador /e del patrón regex.".to_string(),
                                ));
                            }
                        }
                    }
                    "shell_exec" | "exec" | "system" | "passthru" | "popen" | "proc_open" => {
                        let sev = if has_sg || has_taint {
                            Severity::Critical
                        } else {
                            Severity::High
                        };
                        findings.push(make_finding(
                            path,
                            source,
                            SecurityCategory::CommandInjection,
                            sev,
                            tok.span.start_line,
                            tok.span.start_col,
                            tok.span.start_byte,
                            end_byte,
                            format!(
                                "Ejecución de comando del sistema mediante {lower}(){}.",
                                if has_sg || has_taint {
                                    " con posible entrada de usuario"
                                } else {
                                    ""
                                }
                            ),
                            "Evita llamadas al shell o sanitiza estrictamente argumentos con escapeshellarg() y listas blancas.".to_string(),
                        ));
                    }
                    "unserialize" => {
                        let has_allowed_classes_false = args.get(1).is_some_and(|&(s, e)| {
                            let opt = &sig[s..e];
                            let joined = opt
                                .iter()
                                .map(|t| t.text.to_ascii_lowercase())
                                .collect::<Vec<_>>()
                                .join(" ");
                            joined.contains("allowed_classes") && joined.contains("false")
                        });
                        if !has_allowed_classes_false {
                            let sev = if has_sg || has_taint {
                                Severity::Critical
                            } else {
                                Severity::High
                            };
                            findings.push(make_finding(
                                path,
                                source,
                                SecurityCategory::UnsafeDeserialization,
                                sev,
                                tok.span.start_line,
                                tok.span.start_col,
                                tok.span.start_byte,
                                end_byte,
                                "Deserialización insegura con unserialize() sin restringir allowed_classes => false.".to_string(),
                                "Usa json_decode() para datos externos o pasa ['allowed_classes' => false] como segundo argumento.".to_string(),
                            ));
                        }
                    }
                    "move_uploaded_file" => {
                        if !has_upload_validation {
                            let raw_files_name = all_arg_tokens.iter().any(|t| {
                                t.text == "$_FILES" || is_superglobal_token(t)
                            });
                            let uses_basename = all_arg_tokens
                                .iter()
                                .any(|t| t.kind == PhpTokenKind::Word && t.text.eq_ignore_ascii_case("basename"));
                            let sev = if raw_files_name && !uses_basename {
                                Severity::Critical
                            } else {
                                Severity::High
                            };
                            findings.push(make_finding(
                                path,
                                source,
                                SecurityCategory::ArbitraryFileUpload,
                                sev,
                                tok.span.start_line,
                                tok.span.start_col,
                                tok.span.start_byte,
                                end_byte,
                                "move_uploaded_file() sin validación visible de extensión o tipo MIME real en el mismo archivo.".to_string(),
                                "Valida la extensión con lista blanca, verifica el MIME real con finfo_file(), renombra con ID aleatorio y guarda fuera del webroot.".to_string(),
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }

        i += 1;
    }
}

fn scan_backticks(
    path: &Path,
    source: &str,
    sig: &[&PhpToken],
    tainted_vars: &HashSet<String>,
    findings: &mut Vec<SecurityFinding>,
) {
    let mut i = 0;
    while i < sig.len() {
        let tok = sig[i];

        // Caso A: el lexer emitió todo el backtick como StringLiteral empezando con '`'
        if tok.kind == PhpTokenKind::StringLiteral && tok.text.starts_with('`') {
            let has_sg = SUPERGLOBALS.iter().any(|sg| tok.text.contains(sg));
            let has_taint = has_sg
                || tainted_vars
                    .iter()
                    .any(|v| tok.text.contains(v.as_str()));
            findings.push(make_finding(
                path,
                source,
                SecurityCategory::CommandInjection,
                if has_taint {
                    Severity::Critical
                } else {
                    Severity::High
                },
                tok.span.start_line,
                tok.span.start_col,
                tok.span.start_byte,
                tok.span.end_byte,
                "Ejecución de comandos del sistema mediante operador backtick (`...`).".to_string(),
                "Reemplaza backticks por APIs nativas de PHP o shell_exec() con escapeshellarg() y validación estricta.".to_string(),
            ));
            i += 1;
            continue;
        }

        // Caso B: el lexer emitió '`' como Operator/Punctuation de apertura y cierre
        if matches!(tok.kind, PhpTokenKind::Operator | PhpTokenKind::Punctuation)
            && tok.text == "`"
        {
            if let Some(rel_end) = sig[i + 1..].iter().position(|t| {
                matches!(t.kind, PhpTokenKind::Operator | PhpTokenKind::Punctuation)
                    && t.text == "`"
            }) {
                let close_idx = i + 1 + rel_end;
                let inner = &sig[i + 1..close_idx];
                let has_taint = has_user_input(inner, tainted_vars);
                findings.push(make_finding(
                    path,
                    source,
                    SecurityCategory::CommandInjection,
                    if has_taint {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    tok.span.start_line,
                    tok.span.start_col,
                    tok.span.start_byte,
                    sig[close_idx].span.end_byte,
                    "Ejecución de comandos del sistema mediante operador backtick (`...`).".to_string(),
                    "Reemplaza backticks por APIs nativas de PHP o shell_exec() con escapeshellarg() y validación estricta.".to_string(),
                ));
                i = close_idx + 1;
                continue;
            }
        }

        i += 1;
    }
}

fn scan_sql_statements(
    path: &Path,
    source: &str,
    sig: &[&PhpToken],
    tainted_vars: &HashSet<String>,
    findings: &mut Vec<SecurityFinding>,
) {
    let mut start = 0;
    while start < sig.len() {
        let end = find_statement_end(sig, start);
        let stmt = &sig[start..end];
        if !stmt.is_empty() {
            inspect_sql_statement(path, source, stmt, tainted_vars, findings);
        }
        start = end.saturating_add(1);
    }
}

fn inspect_sql_statement(
    path: &Path,
    source: &str,
    stmt: &[&PhpToken],
    tainted_vars: &HashSet<String>,
    findings: &mut Vec<SecurityFinding>,
) {
    let Some(sql_tok) = stmt
        .iter()
        .copied()
        .find(|t| t.kind == PhpTokenKind::StringLiteral && looks_like_sql_query(&t.text))
    else {
        return;
    };

    // 1. Interpolación directa dentro de literal con comillas dobles / heredoc
    let is_interpolable_string =
        sql_tok.text.starts_with('"') || (sql_tok.text.starts_with("<<<") && !sql_tok.text.starts_with("<<<'"));

    if is_interpolable_string {
        let sg_in_str = SUPERGLOBALS.iter().any(|sg| sql_tok.text.contains(sg));
        let taint_in_str = !sg_in_str
            && tainted_vars
                .iter()
                .any(|v| sql_tok.text.contains(v.as_str()));

        if sg_in_str || taint_in_str {
            findings.push(make_finding(
                path,
                source,
                SecurityCategory::SqlInjectionRisk,
                if sg_in_str {
                    Severity::Critical
                } else {
                    Severity::High
                },
                sql_tok.span.start_line,
                sql_tok.span.start_col,
                sql_tok.span.start_byte,
                sql_tok.span.end_byte,
                "Interpolación directa de entrada de usuario dentro de una consulta SQL.".to_string(),
                "Usa sentencias preparadas (PDO::prepare / mysqli_prepare) con marcadores de parámetros (? o :nombre).".to_string(),
            ));
            return;
        }
    }

    // 2. Concatenación con '.' en la misma sentencia SQL (evitando falsos positivos en prepare(...)->execute([$_GET]))
    let has_concat = stmt.iter().any(|t| t.text == ".");
    if has_concat && has_user_input(stmt, tainted_vars) {
        let direct_sg = stmt.iter().any(|t| is_superglobal_token(t));
        let first = stmt.first().expect("stmt no vacío");
        let last = stmt.last().expect("stmt no vacío");
        findings.push(make_finding(
            path,
            source,
            SecurityCategory::SqlInjectionRisk,
            if direct_sg {
                Severity::Critical
            } else {
                Severity::High
            },
            first.span.start_line,
            first.span.start_col,
            first.span.start_byte,
            last.span.end_byte,
            "Concatenación de superglobal o variable controlada por el usuario en consulta SQL.".to_string(),
            "Usa sentencias preparadas parametrizadas (PDO/MySQLi) en lugar de concatenar cadenas SQL.".to_string(),
        ));
    }
}

fn looks_like_sql_query(literal: &str) -> bool {
    static SQL_RE: OnceLock<Regex> = OnceLock::new();
    let re = SQL_RE.get_or_init(|| {
        Regex::new(
            r#"(?is)\b(?:SELECT\s+.+?\s+FROM|INSERT\s+(?:IGNORE\s+)?INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|REPLACE\s+INTO)\b"#,
        )
        .expect("regex válido")
    });
    re.is_match(literal)
}

fn detect_upload_validation(block_tokens: &[Vec<PhpToken>]) -> bool {
    let mut saw_pathinfo = false;
    let mut saw_in_array = false;
    let mut saw_ext_const_or_literal = false;

    for tokens in block_tokens {
        for tok in tokens {
            if matches!(tok.kind, PhpTokenKind::Comment | PhpTokenKind::Whitespace) {
                continue;
            }
            if tok.kind == PhpTokenKind::Word {
                let lower = tok.text.to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "finfo_open"
                        | "finfo_file"
                        | "mime_content_type"
                        | "exif_imagetype"
                        | "getimagesize"
                        | "pathinfo_extension"
                ) {
                    return true;
                }
                if lower == "pathinfo" {
                    saw_pathinfo = true;
                }
                if lower == "in_array" {
                    saw_in_array = true;
                }
            } else if tok.kind == PhpTokenKind::StringLiteral {
                let lower = tok.text.to_ascii_lowercase();
                if lower.contains("jpg")
                    || lower.contains("jpeg")
                    || lower.contains("png")
                    || lower.contains("gif")
                    || lower.contains("pdf")
                    || lower.contains("webp")
                    || lower.contains("image/")
                    || lower.contains("application/pdf")
                {
                    saw_ext_const_or_literal = true;
                }
            }
        }
    }

    (saw_pathinfo && saw_in_array) || (saw_in_array && saw_ext_const_or_literal)
}

fn collect_tainted_variables(block_tokens: &[Vec<PhpToken>]) -> HashSet<String> {
    let mut tainted = HashSet::new();
    for tokens in block_tokens {
        let sig: Vec<&PhpToken> = tokens
            .iter()
            .filter(|t| !matches!(t.kind, PhpTokenKind::Comment | PhpTokenKind::Whitespace))
            .collect();
        let mut i = 0;
        while i + 2 < sig.len() {
            if sig[i].kind == PhpTokenKind::Variable && sig[i + 1].text == "=" {
                let end = find_statement_end(sig.as_slice(), i + 2);
                let rhs = &sig[i + 2..end];
                let sanitized = rhs.first().is_some_and(|t| {
                    let lower = t.text.to_ascii_lowercase();
                    matches!(lower.as_str(), "intval" | "floatval" | "boolval")
                }) || (rhs.len() >= 3
                    && rhs[0].text == "("
                    && matches!(
                        rhs[1].text.to_ascii_lowercase().as_str(),
                        "int" | "integer" | "float" | "double" | "bool" | "boolean"
                    ));

                if !sanitized && rhs.iter().any(|t| is_superglobal_token(t)) {
                    tainted.insert(sig[i].text.clone());
                }
                i = end;
                continue;
            }
            i += 1;
        }
    }
    tainted
}

fn is_superglobal_token(tok: &PhpToken) -> bool {
    tok.kind == PhpTokenKind::Variable && SUPERGLOBALS.contains(&tok.text.as_str())
}

fn has_user_input(tokens: &[&PhpToken], tainted_vars: &HashSet<String>) -> bool {
    for tok in tokens {
        if is_superglobal_token(tok) {
            return true;
        }
        if tok.kind == PhpTokenKind::Variable && tainted_vars.contains(&tok.text) {
            return true;
        }
        if tok.kind == PhpTokenKind::StringLiteral
            && (tok.text.starts_with('"')
                || (tok.text.starts_with("<<<") && !tok.text.starts_with("<<<'")))
        {
            if SUPERGLOBALS.iter().any(|sg| tok.text.contains(sg))
                || tainted_vars.iter().any(|v| tok.text.contains(v.as_str()))
            {
                return true;
            }
        }
    }
    false
}

fn is_include_keyword(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "include" | "include_once" | "require" | "require_once"
    )
}

fn is_standalone_construct(sig: &[&PhpToken], idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    !matches!(sig[idx - 1].text.as_str(), "->" | "?->" | "::" | "function" | "const")
}

fn is_standalone_call(sig: &[&PhpToken], idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    let prev = sig[idx - 1].text.as_str();
    if matches!(prev, "->" | "?->" | "::" | "function" | "new" | "const") {
        return false;
    }
    if prev == "\\" && idx >= 2 && sig[idx - 2].kind == PhpTokenKind::Word {
        return false;
    }
    true
}

fn detect_backdoor_decoder(arg_tokens: &[&PhpToken]) -> Option<&'static str> {
    for (idx, tok) in arg_tokens.iter().enumerate() {
        if tok.kind == PhpTokenKind::Word {
            let lower = tok.text.to_ascii_lowercase();
            let matched = match lower.as_str() {
                "base64_decode" => Some("base64_decode"),
                "gzinflate" => Some("gzinflate"),
                "gzuncompress" => Some("gzuncompress"),
                "str_rot13" => Some("str_rot13"),
                "hex2bin" => Some("hex2bin"),
                _ => None,
            };
            if let Some(name) = matched {
                if arg_tokens.get(idx + 1).is_some_and(|n| n.text == "(") {
                    return Some(name);
                }
            }
        }
    }
    None
}

fn is_risky_assert_args(arg_tokens: &[&PhpToken]) -> bool {
    if arg_tokens.is_empty() {
        return false;
    }
    let has_comparison = arg_tokens.iter().any(|t| {
        matches!(
            t.text.as_str(),
            "===" | "!==" | "==" | "!=" | "<" | ">" | "<=" | ">=" | "instanceof"
        )
    });
    if has_comparison {
        return false;
    }

    arg_tokens.iter().any(|t| {
        t.kind == PhpTokenKind::Variable
            || t.text == "."
            || (t.kind == PhpTokenKind::StringLiteral && t.text.contains('('))
            || (t.kind == PhpTokenKind::Word
                && !matches!(
                    t.text.to_ascii_lowercase().as_str(),
                    "true" | "false" | "null"
                ))
    })
}

fn preg_pattern_has_eval_modifier(arg0_tokens: &[&PhpToken]) -> bool {
    for tok in arg0_tokens {
        if tok.kind != PhpTokenKind::StringLiteral {
            continue;
        }
        let raw = tok.text.as_str();
        let inner = if (raw.starts_with('\'') && raw.ends_with('\''))
            || (raw.starts_with('"') && raw.ends_with('"'))
        {
            if raw.len() >= 2 {
                &raw[1..raw.len() - 1]
            } else {
                continue;
            }
        } else {
            continue;
        };

        let mut chars = inner.chars();
        let Some(open_delim) = chars.next() else {
            continue;
        };
        let close_delim = match open_delim {
            '(' => ')',
            '[' => ']',
            '{' => '}',
            '<' => '>',
            other => other,
        };
        let paired = open_delim != close_delim;
        let body = chars.as_str();
        let mut pair_depth = 1usize;
        let mut escaped = false;
        let mut rest_after_close = None;

        for (byte_idx, ch) in body.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if paired && ch == open_delim {
                pair_depth += 1;
                continue;
            }
            if ch == close_delim {
                if paired {
                    pair_depth = pair_depth.saturating_sub(1);
                    if pair_depth == 0 {
                        rest_after_close = Some(&body[byte_idx + ch.len_utf8()..]);
                        break;
                    }
                } else {
                    rest_after_close = Some(&body[byte_idx + ch.len_utf8()..]);
                    break;
                }
            }
        }

        if let Some(modifiers) = rest_after_close {
            if modifiers.contains('e') {
                return true;
            }
        }
    }
    false
}

fn extract_paren_range(
    sig: &[&PhpToken],
    open_idx: usize,
) -> Option<(usize, Vec<(usize, usize)>)> {
    if sig.get(open_idx)?.text != "(" {
        return None;
    }

    let mut depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut args = Vec::new();
    let mut arg_start = open_idx + 1;

    for idx in open_idx..sig.len() {
        let text = sig[idx].text.as_str();
        match text {
            "(" => depth += 1,
            ")" => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    if arg_start < idx {
                        args.push((arg_start, idx));
                    }
                    return Some((idx, args));
                }
            }
            "[" if depth == 1 => bracket_depth += 1,
            "]" if depth == 1 => bracket_depth = bracket_depth.saturating_sub(1),
            "{" if depth == 1 => brace_depth += 1,
            "}" if depth == 1 => brace_depth = brace_depth.saturating_sub(1),
            "," if depth == 1 && bracket_depth == 0 && brace_depth == 0 => {
                if arg_start < idx {
                    args.push((arg_start, idx));
                }
                arg_start = idx + 1;
            }
            _ => {}
        }
    }

    None
}

fn find_statement_end(sig: &[&PhpToken], from: usize) -> usize {
    let mut paren = 0usize;
    let mut bracket = 0usize;
    for (offset, tok) in sig[from..].iter().enumerate() {
        match tok.text.as_str() {
            "(" => paren += 1,
            ")" => paren = paren.saturating_sub(1),
            "[" => bracket += 1,
            "]" => bracket = bracket.saturating_sub(1),
            ";" | "{" | "}" if paren == 0 && bracket == 0 => return from + offset,
            _ => {}
        }
    }
    sig.len()
}

fn make_finding(
    path: &Path,
    source: &str,
    category: SecurityCategory,
    severity: Severity,
    line: usize,
    column: usize,
    start_byte: usize,
    end_byte: usize,
    description: String,
    remediation: String,
) -> SecurityFinding {
    let snippet = safe_slice(source, start_byte, end_byte)
        .chars()
        .take(180)
        .collect::<String>()
        .replace('\n', " ")
        .trim()
        .to_string();

    let id = build_security_id(path, category, line, column, start_byte);

    SecurityFinding {
        id,
        severity,
        category,
        file: path.to_path_buf(),
        line,
        column,
        snippet,
        description,
        remediation,
    }
}

fn safe_slice(source: &str, start: usize, end: usize) -> &str {
    if start <= end
        && end <= source.len()
        && source.is_char_boundary(start)
        && source.is_char_boundary(end)
    {
        &source[start..end]
    } else {
        ""
    }
}

fn build_security_id(
    path: &Path,
    category: SecurityCategory,
    line: usize,
    column: usize,
    start_byte: usize,
) -> String {
    let code = match category {
        SecurityCategory::RemoteCodeExecution => "RCE",
        SecurityCategory::CommandInjection => "CMD",
        SecurityCategory::UnsafeDeserialization => "DESER",
        SecurityCategory::DynamicIncludeLfi => "LFI",
        SecurityCategory::SqlInjectionRisk => "SQLI",
        SecurityCategory::ArbitraryFileUpload => "UPLOAD",
        SecurityCategory::BackdoorPattern => "SHELL",
    };
    let hash_input = format!(
        "{}:{}:{}:{}:{}",
        path.to_string_lossy(),
        code,
        line,
        column,
        start_byte
    );
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in hash_input.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("SEC-{code}-{hash:08x}")
}
