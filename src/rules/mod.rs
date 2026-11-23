use crate::models::{
    ClassSummary, DecisionBucket, FileSummary, FunctionSummary, MigrationFinding, PhpVersion,
    ResolutionStatus, RuleCategory, Span,
};
use crate::parser::lexer::{span_from_bytes, PhpToken, PhpTokenKind};
use std::collections::HashSet;
use std::path::Path;

/// Evalúa todas las reglas de compatibilidad PHP para los saltos seleccionados sobre un archivo.
pub fn evaluate_file(
    file_path: &Path,
    source: &str,
    summary: &FileSummary,
    hops: &[PhpVersion],
) -> Vec<MigrationFinding> {
    if hops.is_empty() {
        return Vec::new();
    }

    let hop_set: HashSet<PhpVersion> = hops.iter().copied().collect();
    let mut findings = Vec::new();

    // Tokenizar una sola vez cada bloque PHP del archivo
    let mut block_sigs: Vec<Vec<PhpToken>> = Vec::new();
    for block in summary.blocks.iter().filter(|b| b.is_php) {
        let tokens = crate::parser::tokenize_php_block(source, block);
        let sig: Vec<PhpToken> = tokens
            .into_iter()
            .filter(|t| !matches!(t.kind, PhpTokenKind::Comment | PhpTokenKind::Whitespace))
            .collect();
        if !sig.is_empty() {
            block_sigs.push(sig);
        }
    }

    // Reglas basadas en tokens por bloque PHP
    for sig in &block_sigs {
        if hop_set.contains(&PhpVersion::Php80) {
            check_php80_tokens(file_path, source, sig, &mut findings);
        }
        if hop_set.contains(&PhpVersion::Php81) {
            check_php81_tokens(file_path, source, sig, &mut findings);
        }
        if hop_set.contains(&PhpVersion::Php82) {
            check_php82_tokens(file_path, source, sig, &mut findings);
        }
        if hop_set.contains(&PhpVersion::Php83) {
            check_php83_tokens(file_path, source, sig, &mut findings);
        }
        if hop_set.contains(&PhpVersion::Php84) {
            check_php84_tokens(file_path, source, sig, &mut findings);
        }
        if hop_set.contains(&PhpVersion::Php85) {
            check_php85_tokens(file_path, source, sig, &mut findings);
        }
    }

    // Reglas basadas en estructura AST (funciones, métodos y clases)
    let funcs = collect_deduplicated_functions(summary);

    if hop_set.contains(&PhpVersion::Php80) {
        check_php80_required_after_optional(file_path, source, &funcs, &mut findings);
    }
    if hop_set.contains(&PhpVersion::Php81) {
        check_php81_interface_return_types(file_path, source, &summary.classes, &mut findings);
    }
    if hop_set.contains(&PhpVersion::Php82) {
        check_php82_dynamic_properties(file_path, source, &summary.classes, &mut findings);
    }
    if hop_set.contains(&PhpVersion::Php84) {
        check_php84_implicit_nullable(file_path, source, &funcs, &mut findings);
    }
    if hop_set.contains(&PhpVersion::Php85) {
        check_php85_sleep_wakeup(file_path, source, &summary.classes, &mut findings);
    }

    findings
}

// ============================================================================
// Reglas PHP 8.0
// ============================================================================

fn check_php80_tokens(
    file_path: &Path,
    source: &str,
    sig: &[PhpToken],
    findings: &mut Vec<MigrationFinding>,
) {
    let mut curly_offset_closes: HashSet<usize> = HashSet::new();

    for i in 0..sig.len() {
        let tok = &sig[i];

        // 1. Acceso a array/string con llaves: $var{idx} -> $var[idx]
        if tok.text == "{" && is_curly_offset_open(sig, i, &curly_offset_closes) {
            if let Some(close_idx) = find_matching_brace(sig, i) {
                let inner_tokens = &sig[i + 1..close_idx];
                if is_valid_offset_expr(inner_tokens) {
                    curly_offset_closes.insert(close_idx);

                    let prev_is_standalone_var = i > 0
                        && sig[i - 1].kind == PhpTokenKind::Variable
                        && (i < 2
                            || !matches!(
                                sig[i - 2].text.as_str(),
                                "->" | "?->" | "::" | "$"
                            ));

                    let (span, replacement) = if prev_is_standalone_var {
                        let start = sig[i - 1].span.start_byte;
                        let end = sig[close_idx].span.end_byte;
                        let var_text = safe_slice(source, sig[i - 1].span.start_byte, sig[i - 1].span.end_byte);
                        let inner_text = safe_slice(
                            source,
                            sig[i].span.end_byte,
                            sig[close_idx].span.start_byte,
                        );
                        (
                            span_from_bytes(source, start, end),
                            format!("{var_text}[{inner_text}]"),
                        )
                    } else {
                        let start = sig[i].span.start_byte;
                        let end = sig[close_idx].span.end_byte;
                        let inner_text = safe_slice(
                            source,
                            sig[i].span.end_byte,
                            sig[close_idx].span.start_byte,
                        );
                        (
                            span_from_bytes(source, start, end),
                            format!("[{inner_text}]"),
                        )
                    };

                    if let Some(f) = build_finding(
                        file_path,
                        source,
                        "PHP80-CURLY-OFFSET",
                        PhpVersion::Php80,
                        DecisionBucket::GreenAutoFix,
                        RuleCategory::DeprecatedSyntax,
                        span,
                        Some(replacement),
                        "El acceso a desplazamientos de array/string con llaves `{...}` fue eliminado en PHP 8.0.".to_string(),
                        "Mantiene exactamente la misma semántica de lectura/escritura reemplazando `{...}` por `[...]`.".to_string(),
                    ) {
                        findings.push(f);
                    }
                }
            }
        }

        // 2. Cast (real) -> (float)
        if is_cast_token_sequence(sig, i, &["real"]) {
            let span = span_from_bytes(source, sig[i].span.start_byte, sig[i + 2].span.end_byte);
            if let Some(f) = build_finding(
                file_path,
                source,
                "PHP80-CAST-REAL",
                PhpVersion::Php80,
                DecisionBucket::GreenAutoFix,
                RuleCategory::DeprecatedSyntax,
                span,
                Some("(float)".to_string()),
                "El cast `(real)` fue eliminado en PHP 8.0; debe usarse `(float)`.".to_string(),
                "Equivalente 1:1 en tiempo de ejecución sin cambiar tipos ni precisión.".to_string(),
            ) {
                findings.push(f);
            }
        }

        // 3 y 4. Funciones eliminadas PHP 8.0 y extensión mysql_*
        if tok.kind == PhpTokenKind::Word
            && i + 1 < sig.len()
            && sig[i + 1].text == "("
            && is_standalone_call(sig, i)
        {
            if let Some((close_idx, args)) = extract_paren_range(sig, i + 1) {
                let lower = tok.text.to_ascii_lowercase();
                let call_span = span_from_bytes(source, tok.span.start_byte, sig[close_idx].span.end_byte);

                if lower.starts_with("mysql_") {
                    if let Some(f) = build_finding(
                        file_path,
                        source,
                        "PHP80-MYSQL-EXT",
                        PhpVersion::Php80,
                        DecisionBucket::RedBlocker,
                        RuleCategory::ExtensionRemoved,
                        call_span,
                        None,
                        format!(
                            "La función `{}` de la extensión ext-mysql fue eliminada y provoca error fatal en PHP 7.0/8.0+.",
                            tok.text
                        ),
                        "Requiere migrar la capa de datos a `mysqli_*` o `PDO` con sentencias preparadas.".to_string(),
                    ) {
                        findings.push(f);
                    }
                } else {
                    match lower.as_str() {
                        "each" => {
                            let repl = if args.len() == 1 {
                                let (a0_s, a0_e) = args[0];
                                let arg_code = safe_slice(
                                    source,
                                    sig[a0_s].span.start_byte,
                                    sig[a0_e - 1].span.end_byte,
                                )
                                .trim();
                                Some(format!("[key({arg_code}), current({arg_code})]"))
                            } else {
                                None
                            };
                            if let Some(f) = build_finding(
                                file_path,
                                source,
                                "PHP80-REMOVED-EACH",
                                PhpVersion::Php80,
                                DecisionBucket::YellowNeedsDecision,
                                RuleCategory::RemovedFunction,
                                call_span,
                                repl,
                                "La función `each()` fue eliminada en PHP 8.0.".to_string(),
                                "Si se usa tras `reset()` en un único paso equivale a `[key($arr), current($arr)]`; si está dentro de un bucle `while`, reescribe con `foreach ($arr as $k => $v)` para avanzar el puntero.".to_string(),
                            ) {
                                findings.push(f);
                            }
                        }
                        "create_function" => {
                            if let Some(f) = build_finding(
                                file_path,
                                source,
                                "PHP80-REMOVED-CREATE-FUNCTION",
                                PhpVersion::Php80,
                                DecisionBucket::RedBlocker,
                                RuleCategory::RemovedFunction,
                                call_span,
                                None,
                                "La función `create_function()` fue eliminada en PHP 8.0 (y representa riesgo RCE).".to_string(),
                                "Reemplaza por una función anónima / closure nativo `function(...) { ... }` o arrow function `fn(...) => ...`.".to_string(),
                            ) {
                                findings.push(f);
                            }
                        }
                        "money_format" => {
                            if let Some(f) = build_finding(
                                file_path,
                                source,
                                "PHP80-REMOVED-MONEY-FORMAT",
                                PhpVersion::Php80,
                                DecisionBucket::YellowNeedsDecision,
                                RuleCategory::RemovedFunction,
                                call_span,
                                None,
                                "La función `money_format()` fue eliminada en PHP 8.0.".to_string(),
                                "Usa `NumberFormatter::formatCurrency()` de la extensión intl o `number_format()`.".to_string(),
                            ) {
                                findings.push(f);
                            }
                        }
                        "get_magic_quotes_gpc" | "get_magic_quotes_runtime" => {
                            let repl = if args.is_empty() {
                                Some("false".to_string())
                            } else {
                                None
                            };
                            if let Some(f) = build_finding(
                                file_path,
                                source,
                                "PHP80-REMOVED-MAGIC-QUOTES",
                                PhpVersion::Php80,
                                DecisionBucket::YellowNeedsDecision,
                                RuleCategory::RemovedFunction,
                                call_span,
                                repl,
                                format!("`{}()` fue eliminada en PHP 8.0 (siempre retornaba `false` desde PHP 5.4).", tok.text),
                                "Sustituye por `false` y simplifica las ramas condicionales heredadas de magic_quotes.".to_string(),
                            ) {
                                findings.push(f);
                            }
                        }
                        "restore_include_path" => {
                            let repl = if args.is_empty() {
                                Some("ini_restore('include_path')".to_string())
                            } else {
                                None
                            };
                            if let Some(f) = build_finding(
                                file_path,
                                source,
                                "PHP80-REMOVED-RESTORE-INCLUDE-PATH",
                                PhpVersion::Php80,
                                DecisionBucket::YellowNeedsDecision,
                                RuleCategory::RemovedFunction,
                                call_span,
                                repl,
                                "`restore_include_path()` fue eliminada en PHP 8.0.".to_string(),
                                "Reemplaza por `ini_restore('include_path')`.".to_string(),
                            ) {
                                findings.push(f);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // 5. Comparación débil riesgosa: == 0, == "", == '', != 0, != "", != ''
        if matches!(tok.text.as_str(), "==" | "!=" | "<>") {
            let strict_op = if tok.text == "==" { "===" } else { "!==" };

            // Operando derecho
            if i + 1 < sig.len() && is_zero_or_empty_string(&sig[i + 1]) {
                let rhs_followed_by_arith = sig.get(i + 2).is_some_and(|n| {
                    matches!(n.text.as_str(), "." | "+" | "-" | "*" | "/" | "%" | "**")
                });
                if !rhs_followed_by_arith {
                    let rhs_raw = safe_slice(source, sig[i + 1].span.start_byte, sig[i + 1].span.end_byte);
                    let span = span_from_bytes(source, tok.span.start_byte, sig[i + 1].span.end_byte);
                    if let Some(f) = build_finding(
                        file_path,
                        source,
                        "PHP80-LOOSE-COMPARISON",
                        PhpVersion::Php80,
                        DecisionBucket::YellowNeedsDecision,
                        RuleCategory::LooseComparisonRisk,
                        span,
                        Some(format!("{strict_op} {rhs_raw}")),
                        format!(
                            "Comparación débil `{}` frente a `{}`. En PHP 8.0 cambió la semántica string-número: por ejemplo `0 == \"abc\"` pasó de `true` a `false` y `0 == \"\"` pasó a `false`.",
                            tok.text, rhs_raw
                        ),
                        "Evalúa si el operando izquierdo puede ser cadena o booleano; usa comparación estricta `===` / `!==` si el tipo coincide.".to_string(),
                    ) {
                        findings.push(f);
                    }
                }
            } else if i > 0 && is_zero_or_empty_string(&sig[i - 1]) {
                // Estilo Yoda: 0 == $x / "" != $x
                let lhs_preceded_by_arith = i >= 2
                    && matches!(
                        sig[i - 2].text.as_str(),
                        "." | "+" | "-" | "*" | "/" | "%" | "**"
                    );
                if !lhs_preceded_by_arith {
                    let lhs_raw = safe_slice(source, sig[i - 1].span.start_byte, sig[i - 1].span.end_byte);
                    let span = span_from_bytes(source, sig[i - 1].span.start_byte, tok.span.end_byte);
                    if let Some(f) = build_finding(
                        file_path,
                        source,
                        "PHP80-LOOSE-COMPARISON",
                        PhpVersion::Php80,
                        DecisionBucket::YellowNeedsDecision,
                        RuleCategory::LooseComparisonRisk,
                        span,
                        Some(format!("{lhs_raw} {strict_op}")),
                        format!(
                            "Comparación débil `{lhs_raw} {}` en riesgo por el cambio de PHP 8.0 donde `0 == \"abc\"` ahora evalúa `false`.",
                            tok.text
                        ),
                        "Verifica el tipo esperado en tiempo de ejecución y cambia a comparación estricta `===` / `!==` cuando corresponda.".to_string(),
                    ) {
                        findings.push(f);
                    }
                }
            }
        }
    }
}

fn check_php80_required_after_optional(
    file_path: &Path,
    source: &str,
    funcs: &[&FunctionSummary],
    findings: &mut Vec<MigrationFinding>,
) {
    for func in funcs {
        let mut first_optional_name: Option<&str> = None;

        for param in &func.params {
            let raw_param = safe_slice(source, param.span.start_byte, param.span.end_byte);
            let is_variadic = param.name.starts_with("...") || raw_param.contains("...");
            if is_variadic {
                continue;
            }

            if param.has_default {
                if first_optional_name.is_none() {
                    first_optional_name = Some(param.name.as_str());
                }
            } else if let Some(opt_name) = first_optional_name {
                if let Some(f) = build_finding(
                    file_path,
                    source,
                    "PHP80-REQ-AFTER-OPT",
                    PhpVersion::Php80,
                    DecisionBucket::YellowNeedsDecision,
                    RuleCategory::SignatureMismatch,
                    func.signature_span,
                    None,
                    format!(
                        "En `{}()`, el parámetro obligatorio `{}` aparece después del parámetro opcional `{}` (deprecado desde PHP 8.0).",
                        func.name, param.name, opt_name
                    ),
                    "Elimina el valor por defecto del parámetro anterior o reordena los parámetros (cuidado con callers existentes).".to_string(),
                ) {
                    findings.push(f);
                }
                break;
            }
        }
    }
}

// ============================================================================
// Reglas PHP 8.1
// ============================================================================

fn check_php81_tokens(
    file_path: &Path,
    source: &str,
    sig: &[PhpToken],
    findings: &mut Vec<MigrationFinding>,
) {
    for i in 0..sig.len() {
        let tok = &sig[i];

        // FILTER_SANITIZE_STRING / FILTER_SANITIZE_STRIPPED
        if tok.kind == PhpTokenKind::Word
            && matches!(
                tok.text.as_str(),
                "FILTER_SANITIZE_STRING" | "FILTER_SANITIZE_STRIPPED"
            )
            && is_standalone_const(sig, i)
        {
            if let Some(f) = build_finding(
                file_path,
                source,
                "PHP81-FILTER-SANITIZE-STRING",
                PhpVersion::Php81,
                DecisionBucket::YellowNeedsDecision,
                RuleCategory::DeprecatedSyntax,
                tok.span,
                None,
                format!("La constante `{}` fue deprecada en PHP 8.1.", tok.text),
                "Reemplaza por `htmlspecialchars($val, ENT_QUOTES, 'UTF-8')` para salida HTML o `strip_tags()` / validación explícita.".to_string(),
            ) {
                findings.push(f);
            }
        }

        if tok.kind == PhpTokenKind::Word
            && i + 1 < sig.len()
            && sig[i + 1].text == "("
            && is_standalone_call(sig, i)
        {
            if let Some((close_idx, args)) = extract_paren_range(sig, i + 1) {
                let lower = tok.text.to_ascii_lowercase();

                // strftime / gmstrftime
                if matches!(lower.as_str(), "strftime" | "gmstrftime") {
                    let call_span =
                        span_from_bytes(source, tok.span.start_byte, sig[close_idx].span.end_byte);
                    if let Some(f) = build_finding(
                        file_path,
                        source,
                        "PHP81-STRFTIME",
                        PhpVersion::Php81,
                        DecisionBucket::YellowNeedsDecision,
                        RuleCategory::DeprecatedSyntax,
                        call_span,
                        None,
                        format!("La función `{}()` fue deprecada en PHP 8.1.", tok.text),
                        "Migra a `DateTimeImmutable::format()` o `IntlDateFormatter` para formatos localizados.".to_string(),
                    ) {
                        findings.push(f);
                    }
                    continue;
                }

                // Funciones internas que ya no admiten null en PHP 8.1
                let checked_arg_idx = match lower.as_str() {
                    "strlen" | "trim" | "ltrim" | "rtrim" | "htmlspecialchars" | "htmlentities"
                    | "strpos" | "strtolower" | "strtoupper" | "substr" => Some(0usize),
                    "explode" => Some(1usize),
                    "str_replace" => Some(2usize),
                    _ => None,
                };

                if let Some(arg_idx) = checked_arg_idx {
                    if let Some(&(arg_start, arg_end)) = args.get(arg_idx) {
                        let arg_tokens = &sig[arg_start..arg_end];
                        let allow_array = lower == "str_replace";
                        if !is_safe_non_null_string_arg(arg_tokens, allow_array) {
                            let arg_span = span_from_bytes(
                                source,
                                arg_tokens[0].span.start_byte,
                                arg_tokens[arg_tokens.len() - 1].span.end_byte,
                            );
                            let arg_code = safe_slice(source, arg_span.start_byte, arg_span.end_byte);
                            let suggested = if allow_array {
                                format!("{arg_code} ?? ''")
                            } else if is_simple_coalesce_target(arg_tokens) {
                                format!("{arg_code} ?? ''")
                            } else {
                                format!("(string)({arg_code} ?? '')")
                            };

                            if let Some(f) = build_finding(
                                file_path,
                                source,
                                "PHP81-NULL-STRING-ARG",
                                PhpVersion::Php81,
                                DecisionBucket::YellowNeedsDecision,
                                RuleCategory::TypeSafety,
                                arg_span,
                                Some(suggested),
                                format!(
                                    "En PHP 8.1+, pasar `null` al argumento #{} de `{}()` emite aviso de deprecación (`Passing null to parameter ... of type string is deprecated`).",
                                    arg_idx + 1,
                                    tok.text
                                ),
                                "Asegura el valor frente a `null` con `?? ''` o `(string)($arg ?? '')` si la variable puede llegar nula desde BD/request.".to_string(),
                            ) {
                                findings.push(f);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn is_safe_non_null_string_arg(arg_tokens: &[PhpToken], allow_array: bool) -> bool {
    if arg_tokens.is_empty() {
        return true;
    }

    // Literal de string o concatenación con '.' a nivel superior
    if arg_tokens.len() == 1
        && matches!(
            arg_tokens[0].kind,
            PhpTokenKind::StringLiteral | PhpTokenKind::Number
        )
    {
        return true;
    }

    // Ya tiene operador null-coalescing `??`
    if arg_tokens.iter().any(|t| t.text == "??") {
        return true;
    }

    // Cast explícito a (string) al inicio
    if arg_tokens.len() >= 3
        && arg_tokens[0].text == "("
        && arg_tokens[1].kind == PhpTokenKind::Word
        && arg_tokens[1].text.eq_ignore_ascii_case("string")
        && arg_tokens[2].text == ")"
    {
        return true;
    }

    // Concatenación con '.' a profundidad 0 siempre produce string en PHP
    let mut depth = 0usize;
    for t in arg_tokens {
        match t.text.as_str() {
            "(" | "[" => depth += 1,
            ")" | "]" => depth = depth.saturating_sub(1),
            "." if depth == 0 => return true,
            _ => {}
        }
    }

    // Llamadas que retornan string no-nulo o constantes mágicas
    if arg_tokens[0].kind == PhpTokenKind::Word {
        let lower = arg_tokens[0].text.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "strval"
                | "sprintf"
                | "implode"
                | "join"
                | "date"
                | "number_format"
                | "__dir__"
                | "__file__"
                | "__function__"
                | "__class__"
                | "php_eol"
        ) {
            return true;
        }
        if allow_array && lower == "array" && arg_tokens.get(1).is_some_and(|t| t.text == "(") {
            return true;
        }
    }

    if allow_array && arg_tokens[0].text == "[" {
        return true;
    }

    false
}

fn is_simple_coalesce_target(arg_tokens: &[PhpToken]) -> bool {
    // Variable simple, propiedad `$this->foo`, acceso `$arr['k']` o llamada sin operadores binarios externos
    let mut depth = 0usize;
    for t in arg_tokens {
        match t.text.as_str() {
            "(" | "[" => depth += 1,
            ")" | "]" => depth = depth.saturating_sub(1),
            "+" | "-" | "*" | "/" | "%" | "?" | ":" | "&&" | "||" | "==" | "===" | "!="
            | "!==" | "<" | ">" | "<=" | ">=" | "and" | "or" | "xor"
                if depth == 0 =>
            {
                return false;
            }
            _ => {}
        }
    }
    true
}

fn check_php81_interface_return_types(
    file_path: &Path,
    source: &str,
    classes: &[ClassSummary],
    findings: &mut Vec<MigrationFinding>,
) {
    for class in classes {
        let interfaces: HashSet<String> = class
            .implements
            .iter()
            .map(|iface| {
                iface
                    .trim_start_matches('\\')
                    .rsplit('\\')
                    .next()
                    .unwrap_or(iface)
                    .to_ascii_lowercase()
            })
            .collect();

        if interfaces.is_empty() {
            continue;
        }

        for method in &class.methods {
            if method.return_type.is_some() || method.has_return_type_will_change {
                continue;
            }

            let method_lower = method.name.to_ascii_lowercase();
            let matching_iface = match method_lower.as_str() {
                "jsonserialize" if interfaces.contains("jsonserializable") => {
                    Some("JsonSerializable")
                }
                "offsetexists" | "offsetget" | "offsetset" | "offsetunset"
                    if interfaces.contains("arrayaccess") =>
                {
                    Some("ArrayAccess")
                }
                "current" | "key" | "next" | "rewind" | "valid"
                    if interfaces.contains("iterator") =>
                {
                    Some("Iterator")
                }
                "getiterator" if interfaces.contains("iteratoraggregate") => {
                    Some("IteratorAggregate")
                }
                "count" if interfaces.contains("countable") => Some("Countable"),
                "serialize" | "unserialize" if interfaces.contains("serializable") => {
                    Some("Serializable")
                }
                _ => None,
            };

            let Some(iface_name) = matching_iface else {
                continue;
            };

            // Anclar antes de '(' para no solaparse con parámetros (ej. ImplicitNullable en PHP 8.4)
            let sig_str = safe_slice(
                source,
                method.signature_span.start_byte,
                method.signature_span.end_byte,
            );
            if sig_str.is_empty() || sig_str.contains("ReturnTypeWillChange") {
                continue;
            }

            let anchor_end = if let Some(paren_rel) = sig_str.find('(') {
                let prefix = sig_str[..paren_rel].trim_end();
                method.signature_span.start_byte + prefix.len()
            } else {
                method.signature_span.end_byte
            };

            if anchor_end <= method.signature_span.start_byte {
                continue;
            }

            let anchor_span = span_from_bytes(source, method.signature_span.start_byte, anchor_end);
            let anchor_code = safe_slice(source, anchor_span.start_byte, anchor_span.end_byte);
            let indent = extract_line_indent(source, anchor_span.start_byte);
            let replacement = format!("#[\\ReturnTypeWillChange]\n{indent}{anchor_code}");

            if let Some(f) = build_finding(
                file_path,
                source,
                "PHP81-RETURN-TYPE-WILL-CHANGE",
                PhpVersion::Php81,
                DecisionBucket::GreenAutoFix,
                RuleCategory::SignatureMismatch,
                anchor_span,
                Some(replacement),
                format!(
                    "El método `{}::{}()` implementa `{iface_name}` sin tipo de retorno declarado ni atributo `#[\\ReturnTypeWillChange]` (deprecado en PHP 8.1).",
                    class.name, method.name
                ),
                "Agrega `#[\\ReturnTypeWillChange]` sin alterar el tipo de retorno real ni romper clases hijas.".to_string(),
            ) {
                findings.push(f);
            }
        }
    }
}

// ============================================================================
// Reglas PHP 8.2
// ============================================================================

fn check_php82_tokens(
    file_path: &Path,
    source: &str,
    sig: &[PhpToken],
    findings: &mut Vec<MigrationFinding>,
) {
    for i in 0..sig.len() {
        let tok = &sig[i];

        // 1. utf8_encode / utf8_decode
        if tok.kind == PhpTokenKind::Word
            && i + 1 < sig.len()
            && sig[i + 1].text == "("
            && is_standalone_call(sig, i)
        {
            let lower = tok.text.to_ascii_lowercase();
            if lower == "utf8_encode" || lower == "utf8_decode" {
                if let Some((close_idx, args)) = extract_paren_range(sig, i + 1) {
                    let call_span =
                        span_from_bytes(source, tok.span.start_byte, sig[close_idx].span.end_byte);
                    let (bucket, replacement) = if args.len() == 1 {
                        let (a0_s, a0_e) = args[0];
                        let arg_code = safe_slice(
                            source,
                            sig[a0_s].span.start_byte,
                            sig[a0_e - 1].span.end_byte,
                        )
                        .trim();
                        let repl = if lower == "utf8_encode" {
                            format!("mb_convert_encoding({arg_code}, 'UTF-8', 'ISO-8859-1')")
                        } else {
                            format!("mb_convert_encoding({arg_code}, 'ISO-8859-1', 'UTF-8')")
                        };
                        (DecisionBucket::GreenAutoFix, Some(repl))
                    } else {
                        (DecisionBucket::YellowNeedsDecision, None)
                    };

                    if let Some(f) = build_finding(
                        file_path,
                        source,
                        "PHP82-UTF8-ENCODE-DECODE",
                        PhpVersion::Php82,
                        bucket,
                        RuleCategory::DeprecatedSyntax,
                        call_span,
                        replacement,
                        format!("`{}()` fue deprecada en PHP 8.2 (y será eliminada en 9.0).", tok.text),
                        "Reemplaza por `mb_convert_encoding()` preservando la conversión ISO-8859-1 <-> UTF-8 (requiere ext-mbstring).".to_string(),
                    ) {
                        findings.push(f);
                    }
                }
            }
        }

        // 2. Interpolación deprecada "${var}" en strings dobles / heredocs
        if tok.kind == PhpTokenKind::StringLiteral {
            check_deprecated_dollar_brace_interpolation(file_path, source, tok, findings);
        }
    }
}

fn check_deprecated_dollar_brace_interpolation(
    file_path: &Path,
    source: &str,
    tok: &PhpToken,
    findings: &mut Vec<MigrationFinding>,
) {
    let raw = tok.text.as_str();
    let is_interpolable =
        raw.starts_with('"') || (raw.starts_with("<<<") && !raw.starts_with("<<<'"));
    if !is_interpolable {
        return;
    }

    let bytes = raw.as_bytes();
    let mut idx = 0usize;
    while idx + 2 < bytes.len() {
        if bytes[idx] == b'$' && bytes[idx + 1] == b'{' && !is_escaped_at(bytes, idx) {
            if let Some(close_rel) = find_closing_interp_brace(&raw[idx + 2..]) {
                let inner = &raw[idx + 2..idx + 2 + close_rel];
                let abs_start = tok.span.start_byte + idx;
                let abs_end = tok.span.start_byte + idx + 2 + close_rel + 1;

                if safe_slice(source, abs_start, abs_end) == &raw[idx..idx + 2 + close_rel + 1] {
                    let span = span_from_bytes(source, abs_start, abs_end);
                    let trimmed = inner.trim();
                    let (bucket, repl) = if is_simple_php_var_interp(trimmed) {
                        (DecisionBucket::GreenAutoFix, format!("{{${trimmed}}}"))
                    } else {
                        (DecisionBucket::YellowNeedsDecision, format!("{{${trimmed}}}"))
                    };

                    if let Some(f) = build_finding(
                        file_path,
                        source,
                        "PHP82-STRING-INTERPOLATION",
                        PhpVersion::Php82,
                        bucket,
                        RuleCategory::DeprecatedSyntax,
                        span,
                        Some(repl),
                        "La interpolación de cadenas `${var}` fue deprecada en PHP 8.2.".to_string(),
                        "Migra a `{$var}` manteniendo exactamente el mismo resultado en la cadena.".to_string(),
                    ) {
                        findings.push(f);
                    }
                }
                idx = idx + 2 + close_rel + 1;
                continue;
            }
        }
        idx += 1;
    }
}

fn is_escaped_at(bytes: &[u8], pos: usize) -> bool {
    let mut backslashes = 0usize;
    let mut p = pos;
    while p > 0 {
        p -= 1;
        if bytes[p] == b'\\' {
            backslashes += 1;
        } else {
            break;
        }
    }
    backslashes % 2 == 1
}

fn find_closing_interp_brace(slice: &str) -> Option<usize> {
    let mut depth = 1usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for (idx, ch) in slice.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && (in_single || in_double) {
            escaped = true;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if !in_single && !in_double {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
        }
    }
    None
}

fn is_simple_php_var_interp(inner: &str) -> bool {
    let Some(first) = inner.chars().next() else {
        return false;
    };
    first.is_ascii_alphabetic() || first == '_'
}

fn check_php82_dynamic_properties(
    file_path: &Path,
    source: &str,
    classes: &[ClassSummary],
    findings: &mut Vec<MigrationFinding>,
) {
    for class in classes {
        if class.has_allow_dynamic_properties || class.dynamic_properties.is_empty() {
            continue;
        }
        if class
            .extends
            .as_deref()
            .is_some_and(|e| e.trim_start_matches('\\').eq_ignore_ascii_case("stdClass"))
        {
            continue;
        }

        let header_code = safe_slice(
            source,
            class.header_span.start_byte,
            class.header_span.end_byte,
        );
        if header_code.is_empty() {
            continue;
        }

        let mut seen = HashSet::new();
        let mut prop_list = Vec::new();
        for dp in &class.dynamic_properties {
            if seen.insert(dp.property_name.clone()) {
                prop_list.push(format!("${} (L{})", dp.property_name, dp.span.start_line));
            }
        }

        let indent = extract_line_indent(source, class.header_span.start_byte);
        let replacement = format!("#[\\AllowDynamicProperties]\n{indent}{header_code}");

        if let Some(f) = build_finding(
            file_path,
            source,
            "PHP82-DYNAMIC-PROPERTY",
            PhpVersion::Php82,
            DecisionBucket::YellowNeedsDecision,
            RuleCategory::DynamicProperty,
            class.header_span,
            Some(replacement),
            format!(
                "La clase `{}` asigna propiedades dinámicas no declaradas: {} (deprecado en PHP 8.2).",
                class.name,
                prop_list.join(", ")
            ),
            "Declara explícitamente las propiedades en la clase o añade el atributo `#[\\AllowDynamicProperties]` en la cabecera.".to_string(),
        ) {
            findings.push(f);
        }
    }
}

// ============================================================================
// Reglas PHP 8.3
// ============================================================================

fn check_php83_tokens(
    file_path: &Path,
    source: &str,
    sig: &[PhpToken],
    findings: &mut Vec<MigrationFinding>,
) {
    for i in 0..sig.len() {
        let tok = &sig[i];
        if tok.kind == PhpTokenKind::Word
            && i + 1 < sig.len()
            && sig[i + 1].text == "("
            && is_standalone_call(sig, i)
        {
            let lower = tok.text.to_ascii_lowercase();
            if lower == "get_class" || lower == "get_parent_class" {
                if let Some((close_idx, args)) = extract_paren_range(sig, i + 1) {
                    if args.is_empty() {
                        let call_span = span_from_bytes(
                            source,
                            tok.span.start_byte,
                            sig[close_idx].span.end_byte,
                        );
                        let repl = if lower == "get_class" {
                            "self::class".to_string()
                        } else {
                            "parent::class".to_string()
                        };
                        if let Some(f) = build_finding(
                            file_path,
                            source,
                            "PHP83-GET-CLASS-NO-ARGS",
                            PhpVersion::Php83,
                            DecisionBucket::GreenAutoFix,
                            RuleCategory::DeprecatedSyntax,
                            call_span,
                            Some(repl.clone()),
                            format!(
                                "Llamar a `{}()` sin argumentos fue deprecado en PHP 8.3.",
                                tok.text
                            ),
                            format!("Reemplazo directo por `{repl}` dentro del contexto de clase."),
                        ) {
                            findings.push(f);
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Reglas PHP 8.4
// ============================================================================

fn check_php84_tokens(
    file_path: &Path,
    source: &str,
    sig: &[PhpToken],
    findings: &mut Vec<MigrationFinding>,
) {
    for i in 0..sig.len() {
        let tok = &sig[i];

        if tok.kind == PhpTokenKind::Word
            && tok.text == "E_STRICT"
            && is_standalone_const(sig, i)
        {
            if let Some(f) = build_finding(
                file_path,
                source,
                "PHP84-ESTRICT",
                PhpVersion::Php84,
                DecisionBucket::YellowNeedsDecision,
                RuleCategory::DeprecatedSyntax,
                tok.span,
                None,
                "La constante `E_STRICT` fue deprecada en PHP 8.4.".to_string(),
                "Elimina `E_STRICT` de máscaras `error_reporting(...)` (ya está cubierta por `E_ALL`).".to_string(),
            ) {
                findings.push(f);
            }
        }

        if tok.kind == PhpTokenKind::Word
            && i + 1 < sig.len()
            && sig[i + 1].text == "("
            && is_standalone_call(sig, i)
        {
            if let Some((close_idx, _)) = extract_paren_range(sig, i + 1) {
                let lower = tok.text.to_ascii_lowercase();
                let call_span =
                    span_from_bytes(source, tok.span.start_byte, sig[close_idx].span.end_byte);

                if matches!(
                    lower.as_str(),
                    "oci_connect"
                        | "oci_pconnect"
                        | "oci_new_connect"
                        | "imap_open"
                        | "pspell_new"
                        | "pspell_new_personal"
                        | "pspell_new_config"
                ) {
                    if let Some(f) = build_finding(
                        file_path,
                        source,
                        "PHP84-PECL-EXTENSION",
                        PhpVersion::Php84,
                        DecisionBucket::RedBlocker,
                        RuleCategory::ExtensionRemoved,
                        call_span,
                        None,
                        format!(
                            "La apertura `{}` depende de una extensión desacoplada del core a PECL en PHP 8.4+.",
                            tok.text
                        ),
                        "Instala la extensión vía PECL (ej. `oci8` + Oracle Instant Client) en PHP 8.5; las consultas SQL y llamadas posteriores `oci_parse`/`oci_execute` no requieren reescritura.".to_string(),
                    ) {
                        findings.push(f);
                    }
                } else if matches!(
                    lower.as_str(),
                    "mysqli_ping" | "mysqli_kill" | "mysqli_refresh"
                ) {
                    if let Some(f) = build_finding(
                        file_path,
                        source,
                        "PHP84-MYSQLI-DEPRECATED",
                        PhpVersion::Php84,
                        DecisionBucket::YellowNeedsDecision,
                        RuleCategory::DeprecatedSyntax,
                        call_span,
                        None,
                        format!("La función `{}()` fue deprecada en PHP 8.4.", tok.text),
                        "Reemplaza por reconexión explícita o sentencias SQL (`KILL`, `FLUSH`) según el caso.".to_string(),
                    ) {
                        findings.push(f);
                    }
                }
            }
        }
    }
}

fn check_php84_implicit_nullable(
    file_path: &Path,
    source: &str,
    funcs: &[&FunctionSummary],
    findings: &mut Vec<MigrationFinding>,
) {
    for func in funcs {
        for param in &func.params {
            let (Some(type_hint), Some(type_span)) = (&param.type_hint, param.type_span) else {
                continue;
            };
            if param.is_nullable || !param.default_is_null {
                continue;
            }
            let trimmed_hint = type_hint.trim();
            if trimmed_hint.starts_with('?')
                || trimmed_hint.contains('|')
                || trimmed_hint.eq_ignore_ascii_case("mixed")
                || trimmed_hint.eq_ignore_ascii_case("null")
            {
                continue;
            }

            let original_type = safe_slice(source, type_span.start_byte, type_span.end_byte);
            if original_type.is_empty() || original_type.trim_start().starts_with('?') {
                continue;
            }

            let (bucket, replacement) = if trimmed_hint.contains('&') {
                (
                    DecisionBucket::YellowNeedsDecision,
                    format!("({original_type})|null"),
                )
            } else {
                (DecisionBucket::GreenAutoFix, format!("?{original_type}"))
            };

            if let Some(f) = build_finding(
                file_path,
                source,
                "PHP84-IMPLICIT-NULLABLE",
                PhpVersion::Php84,
                bucket,
                RuleCategory::ImplicitNullable,
                type_span,
                Some(replacement),
                format!(
                    "Parámetro `{}` en `{}()` es implícitamente anulable (`{original_type} {} = null`), deprecado en PHP 8.4.",
                    param.name, func.name, param.name
                ),
                "Declara la nulabilidad explícitamente (`?Tipo`) sin cambiar la firma aceptada por los callers.".to_string(),
            ) {
                findings.push(f);
            }
        }
    }
}

// ============================================================================
// Reglas PHP 8.5
// ============================================================================

fn check_php85_tokens(
    file_path: &Path,
    source: &str,
    sig: &[PhpToken],
    findings: &mut Vec<MigrationFinding>,
) {
    // Seguimiento de alcance para distinguir `switch { case X; }` de `enum { case X; }`
    let mut brace_stack: Vec<BraceScope> = Vec::new();

    let mut i = 0;
    while i < sig.len() {
        let tok = &sig[i];

        // Actualizar pila de llaves para distinguir switch vs enum/otros
        if tok.text == "{" {
            let kind = classify_open_brace_scope(sig, i);
            brace_stack.push(kind);
        } else if tok.text == "}" {
            brace_stack.pop();
        }

        // 1. Casts no canónicos: (integer), (boolean), (double), (binary)
        if is_cast_token_sequence(sig, i, &["integer", "boolean", "double", "binary"]) {
            let lower = sig[i + 1].text.to_ascii_lowercase();
            let canonical = match lower.as_str() {
                "integer" => "(int)",
                "boolean" => "(bool)",
                "double" => "(float)",
                "binary" => "(string)",
                _ => unreachable!(),
            };
            let span = span_from_bytes(source, sig[i].span.start_byte, sig[i + 2].span.end_byte);
            if let Some(f) = build_finding(
                file_path,
                source,
                "PHP85-NONCANONICAL-CAST",
                PhpVersion::Php85,
                DecisionBucket::GreenAutoFix,
                RuleCategory::DeprecatedSyntax,
                span,
                Some(canonical.to_string()),
                format!("El cast no canónico `({})` fue deprecado en PHP 8.5.", sig[i + 1].text),
                format!("Reemplazo seguro por el cast canónico `{canonical}`."),
            ) {
                findings.push(f);
            }
        }

        // 2. Terminador `case X;` o `default;` dentro de `switch`
        if tok.kind == PhpTokenKind::Word
            && matches!(tok.text.to_ascii_lowercase().as_str(), "case" | "default")
            && brace_stack.last().copied() == Some(BraceScope::Switch)
        {
            if let Some(semi_idx) = find_switch_case_semicolon(sig, i + 1) {
                if let Some(f) = build_finding(
                    file_path,
                    source,
                    "PHP85-SWITCH-CASE-SEMICOLON",
                    PhpVersion::Php85,
                    DecisionBucket::GreenAutoFix,
                    RuleCategory::DeprecatedSyntax,
                    sig[semi_idx].span,
                    Some(":".to_string()),
                    "Terminar una cláusula `case` o `default` de `switch` con `;` está deprecado en PHP 8.5.".to_string(),
                    "Cambia `;` por `:` manteniendo exactamente el flujo de control del `switch`.".to_string(),
                ) {
                    findings.push(f);
                }
            }
        }

        // 3. Operador backtick `cmd`
        if tok.kind == PhpTokenKind::StringLiteral && tok.text.starts_with('`') {
            let inner = tok
                .text
                .strip_prefix('`')
                .and_then(|s| s.strip_suffix('`'))
                .unwrap_or(&tok.text);
            let escaped = inner.replace('"', "\\\"");
            if let Some(f) = build_finding(
                file_path,
                source,
                "PHP85-BACKTICK-OPERATOR",
                PhpVersion::Php85,
                DecisionBucket::YellowNeedsDecision,
                RuleCategory::DeprecatedSyntax,
                tok.span,
                Some(format!("shell_exec(\"{escaped}\")")),
                "El operador backtick (`` `...` ``) está deprecado en PHP 8.5.".to_string(),
                "Reemplaza por `shell_exec(...)` validando y escapando los argumentos con `escapeshellarg()`.".to_string(),
            ) {
                findings.push(f);
            }
        } else if matches!(tok.kind, PhpTokenKind::Operator | PhpTokenKind::Punctuation)
            && tok.text == "`"
        {
            if let Some(rel_end) = sig[i + 1..].iter().position(|t| {
                matches!(t.kind, PhpTokenKind::Operator | PhpTokenKind::Punctuation)
                    && t.text == "`"
            }) {
                let close_idx = i + 1 + rel_end;
                let span =
                    span_from_bytes(source, tok.span.start_byte, sig[close_idx].span.end_byte);
                let inner = safe_slice(
                    source,
                    tok.span.end_byte,
                    sig[close_idx].span.start_byte,
                );
                let escaped = inner.replace('"', "\\\"");
                if let Some(f) = build_finding(
                    file_path,
                    source,
                    "PHP85-BACKTICK-OPERATOR",
                    PhpVersion::Php85,
                    DecisionBucket::YellowNeedsDecision,
                    RuleCategory::DeprecatedSyntax,
                    span,
                    Some(format!("shell_exec(\"{escaped}\")")),
                    "El operador backtick (`` `...` ``) está deprecado en PHP 8.5.".to_string(),
                    "Reemplaza por `shell_exec(...)` y audita la seguridad del comando.".to_string(),
                ) {
                    findings.push(f);
                }
                i = close_idx + 1;
                continue;
            }
        }

        // 4. `$arr[null]` -> `$arr['']`
        if i + 2 < sig.len()
            && tok.text == "["
            && sig[i + 1].kind == PhpTokenKind::Word
            && sig[i + 1].text.eq_ignore_ascii_case("null")
            && sig[i + 2].text == "]"
            && is_array_offset_open(sig, i)
        {
            if let Some(f) = build_finding(
                file_path,
                source,
                "PHP85-NULL-ARRAY-OFFSET",
                PhpVersion::Php85,
                DecisionBucket::YellowNeedsDecision,
                RuleCategory::TypeSafety,
                sig[i + 1].span,
                Some("''".to_string()),
                "Usar `null` como índice de array (`$arr[null]`) está deprecado en PHP 8.5.".to_string(),
                "Revisa si la clave nula es intencionada (equivale a `''`) o si indica una variable sin inicializar.".to_string(),
            ) {
                findings.push(f);
            }
        }

        // 6a. Constantes MHASH_*
        if tok.kind == PhpTokenKind::Word
            && tok.text.starts_with("MHASH_")
            && is_standalone_const(sig, i)
        {
            if let Some(f) = build_finding(
                file_path,
                source,
                "PHP85-MHASH-CONST",
                PhpVersion::Php85,
                DecisionBucket::YellowNeedsDecision,
                RuleCategory::DeprecatedSyntax,
                tok.span,
                None,
                format!("La constante `{}` de mhash fue deprecada en PHP 8.5.", tok.text),
                "Migra a la extensión `hash` usando nombres de algoritmo en cadena (ej. `'sha256'`, `'md5'`).".to_string(),
            ) {
                findings.push(f);
            }
        }

        // 6b. Funciones mhash*
        if tok.kind == PhpTokenKind::Word
            && i + 1 < sig.len()
            && sig[i + 1].text == "("
            && is_standalone_call(sig, i)
        {
            let lower = tok.text.to_ascii_lowercase();
            if lower.starts_with("mhash") {
                if let Some((close_idx, _)) = extract_paren_range(sig, i + 1) {
                    let call_span =
                        span_from_bytes(source, tok.span.start_byte, sig[close_idx].span.end_byte);
                    if let Some(f) = build_finding(
                        file_path,
                        source,
                        "PHP85-MHASH-FUNC",
                        PhpVersion::Php85,
                        DecisionBucket::YellowNeedsDecision,
                        RuleCategory::DeprecatedSyntax,
                        call_span,
                        None,
                        format!("La función `{}()` de ext-mhash fue deprecada en PHP 8.5.", tok.text),
                        "Migra a `hash()`, `hash_hmac()`, `hash_hkdf()` o `hash_pbkdf2()` según la operación criptográfica.".to_string(),
                    ) {
                        findings.push(f);
                    }
                }
            }
        }

        i += 1;
    }
}

fn check_php85_sleep_wakeup(
    file_path: &Path,
    source: &str,
    classes: &[ClassSummary],
    findings: &mut Vec<MigrationFinding>,
) {
    for class in classes {
        for method in &class.methods {
            let lower = method.name.to_ascii_lowercase();
            if lower == "__sleep" || lower == "__wakeup" {
                let target_magic = if lower == "__sleep" {
                    "__serialize(): array"
                } else {
                    "__unserialize(array $data): void"
                };
                if let Some(f) = build_finding(
                    file_path,
                    source,
                    "PHP85-SLEEP-WAKEUP",
                    PhpVersion::Php85,
                    DecisionBucket::YellowNeedsDecision,
                    RuleCategory::DeprecatedSyntax,
                    method.signature_span,
                    None,
                    format!(
                        "El método mágico `{}::{}()` fue deprecado en PHP 8.5.",
                        class.name, method.name
                    ),
                    format!("Migra la serialización personalizada a `{target_magic}`."),
                ) {
                    findings.push(f);
                }
            }
        }
    }
}

// ============================================================================
// Helpers de análisis sintáctico y construcción exacta de Spans
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BraceScope {
    Switch,
    Other,
}

fn classify_open_brace_scope(sig: &[PhpToken], brace_idx: usize) -> BraceScope {
    if brace_idx == 0 {
        return BraceScope::Other;
    }
    if sig[brace_idx - 1].text == ")" {
        // Buscar '(' coincidente hacia atrás
        let mut depth = 0usize;
        let mut idx = brace_idx - 1;
        loop {
            match sig[idx].text.as_str() {
                ")" => depth += 1,
                "(" => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        if idx > 0
                            && sig[idx - 1].kind == PhpTokenKind::Word
                            && sig[idx - 1].text.eq_ignore_ascii_case("switch")
                        {
                            return BraceScope::Switch;
                        }
                        break;
                    }
                }
                _ => {}
            }
            if idx == 0 {
                break;
            }
            idx -= 1;
        }
    }
    BraceScope::Other
}

fn find_switch_case_semicolon(sig: &[PhpToken], from: usize) -> Option<usize> {
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;

    for (offset, tok) in sig[from..].iter().enumerate() {
        match tok.text.as_str() {
            "(" => paren += 1,
            ")" => paren = paren.saturating_sub(1),
            "[" => bracket += 1,
            "]" => bracket = bracket.saturating_sub(1),
            "{" => brace += 1,
            "}" => {
                if brace == 0 {
                    return None;
                }
                brace -= 1;
            }
            ":" if paren == 0 && bracket == 0 && brace == 0 => return None,
            ";" if paren == 0 && bracket == 0 && brace == 0 => return Some(from + offset),
            _ => {}
        }
    }
    None
}

fn is_curly_offset_open(
    sig: &[PhpToken],
    brace_idx: usize,
    known_curly_closes: &HashSet<usize>,
) -> bool {
    if brace_idx == 0 {
        return false;
    }
    let prev = &sig[brace_idx - 1];

    match prev.kind {
        PhpTokenKind::Variable => {
            if brace_idx >= 2
                && matches!(
                    sig[brace_idx - 2].text.to_ascii_lowercase().as_str(),
                    "class" | "new" | "function" | "fn" | "use" | "namespace"
                )
            {
                return false;
            }
            if brace_idx >= 2 && sig[brace_idx - 2].text == "$" {
                return false;
            }
            true
        }
        PhpTokenKind::Word => {
            brace_idx >= 2 && matches!(sig[brace_idx - 2].text.as_str(), "->" | "?->" | "::")
        }
        PhpTokenKind::Punctuation | PhpTokenKind::Operator => match prev.text.as_str() {
            "]" => true,
            "}" => known_curly_closes.contains(&(brace_idx - 1)),
            ")" => is_call_paren_before_curly(sig, brace_idx - 1),
            _ => false,
        },
        _ => false,
    }
}

fn is_call_paren_before_curly(sig: &[PhpToken], close_paren_idx: usize) -> bool {
    let mut depth = 0usize;
    let mut idx = close_paren_idx;
    loop {
        match sig[idx].text.as_str() {
            ")" => depth += 1,
            "(" => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    if idx == 0 {
                        return false;
                    }
                    let before = &sig[idx - 1];
                    if before.kind == PhpTokenKind::Variable {
                        return true;
                    }
                    if before.kind == PhpTokenKind::Word {
                        let lower = before.text.to_ascii_lowercase();
                        if matches!(
                            lower.as_str(),
                            "if" | "elseif"
                                | "while"
                                | "for"
                                | "foreach"
                                | "switch"
                                | "catch"
                                | "declare"
                                | "match"
                                | "function"
                                | "fn"
                                | "use"
                                | "list"
                                | "array"
                                | "isset"
                                | "empty"
                                | "unset"
                                | "eval"
                        ) {
                            return false;
                        }
                        if idx >= 2
                            && sig[idx - 2].kind == PhpTokenKind::Word
                            && sig[idx - 2].text.eq_ignore_ascii_case("function")
                        {
                            return false;
                        }
                        if idx >= 3
                            && sig[idx - 2].text == "&"
                            && sig[idx - 3].kind == PhpTokenKind::Word
                            && sig[idx - 3].text.eq_ignore_ascii_case("function")
                        {
                            return false;
                        }
                        return true;
                    }
                    return false;
                }
            }
            _ => {}
        }
        if idx == 0 {
            return false;
        }
        idx -= 1;
    }
}

fn find_matching_brace(sig: &[PhpToken], open_idx: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, tok) in sig[open_idx..].iter().enumerate() {
        if tok.text == "{" {
            depth += 1;
        } else if tok.text == "}" {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(open_idx + offset);
            }
        }
    }
    None
}

fn is_valid_offset_expr(inner: &[PhpToken]) -> bool {
    if inner.is_empty() {
        return false;
    }
    for tok in inner {
        if tok.text == ";" || tok.text == "{" || tok.text == "}" {
            return false;
        }
        if tok.kind == PhpTokenKind::Word
            && matches!(
                tok.text.to_ascii_lowercase().as_str(),
                "return" | "echo" | "if" | "foreach" | "for" | "while" | "switch" | "throw"
            )
        {
            return false;
        }
    }
    true
}

fn is_cast_token_sequence(sig: &[PhpToken], idx: usize, names: &[&str]) -> bool {
    if idx + 2 >= sig.len() {
        return false;
    }
    if sig[idx].text != "("
        || sig[idx + 1].kind != PhpTokenKind::Word
        || sig[idx + 2].text != ")"
    {
        return false;
    }
    let lower = sig[idx + 1].text.to_ascii_lowercase();
    if !names.contains(&lower.as_str()) {
        return false;
    }

    if idx > 0 {
        let prev = &sig[idx - 1];
        if matches!(prev.kind, PhpTokenKind::Variable | PhpTokenKind::Number | PhpTokenKind::StringLiteral) {
            return false;
        }
        if prev.kind == PhpTokenKind::Word
            && !matches!(
                prev.text.to_ascii_lowercase().as_str(),
                "return" | "echo" | "print" | "throw" | "yield" | "case" | "and" | "or" | "xor"
            )
        {
            return false;
        }
        if matches!(prev.text.as_str(), ")" | "]" | "->" | "?->" | "::") {
            return false;
        }
    }

    if idx + 3 < sig.len() {
        let next = &sig[idx + 3];
        if matches!(next.text.as_str(), ";" | ")" | "," | "]" | ":" | "{") {
            return false;
        }
    } else {
        return false;
    }

    true
}

fn is_array_offset_open(sig: &[PhpToken], bracket_idx: usize) -> bool {
    if bracket_idx == 0 {
        return false;
    }
    let prev = &sig[bracket_idx - 1];
    match prev.kind {
        PhpTokenKind::Variable | PhpTokenKind::StringLiteral => true,
        PhpTokenKind::Word => !matches!(
            prev.text.to_ascii_lowercase().as_str(),
            "return"
                | "echo"
                | "print"
                | "throw"
                | "yield"
                | "case"
                | "match"
                | "and"
                | "or"
                | "xor"
                | "new"
                | "else"
        ),
        _ => matches!(prev.text.as_str(), "]" | ")" | "}"),
    }
}

fn is_zero_or_empty_string(tok: &PhpToken) -> bool {
    if tok.kind == PhpTokenKind::Number {
        return tok.text == "0";
    }
    if tok.kind == PhpTokenKind::StringLiteral {
        return tok.text == "\"\"" || tok.text == "''";
    }
    false
}

fn is_standalone_call(sig: &[PhpToken], idx: usize) -> bool {
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

fn is_standalone_const(sig: &[PhpToken], idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    let prev = sig[idx - 1].text.as_str();
    if matches!(prev, "->" | "?->" | "::" | "function" | "const") {
        return false;
    }
    if idx + 1 < sig.len() && sig[idx + 1].text == "(" {
        return false;
    }
    true
}

fn extract_paren_range(
    sig: &[PhpToken],
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

fn collect_deduplicated_functions(summary: &FileSummary) -> Vec<&FunctionSummary> {
    let mut seen_starts: HashSet<usize> = HashSet::new();
    let mut result = Vec::new();

    for f in &summary.functions {
        if seen_starts.insert(f.signature_span.start_byte) {
            result.push(f);
        }
    }
    for c in &summary.classes {
        for m in &c.methods {
            if seen_starts.insert(m.signature_span.start_byte) {
                result.push(m);
            }
        }
    }
    result
}

fn extract_line_indent(source: &str, byte_pos: usize) -> String {
    if byte_pos > source.len() || !source.is_char_boundary(byte_pos) {
        return String::new();
    }
    let before = &source[..byte_pos];
    let line_start = before.rfind('\n').map(|p| p + 1).unwrap_or(0);
    source[line_start..byte_pos]
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect()
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

#[allow(clippy::too_many_arguments)]
fn build_finding(
    file_path: &Path,
    source: &str,
    rule_id: &str,
    target_step: PhpVersion,
    bucket: DecisionBucket,
    category: RuleCategory,
    span: Span,
    suggested_replacement: Option<String>,
    explanation: String,
    logic_impact: String,
) -> Option<MigrationFinding> {
    if span.is_empty()
        || span.end_byte > source.len()
        || !source.is_char_boundary(span.start_byte)
        || !source.is_char_boundary(span.end_byte)
    {
        return None;
    }

    let original_code = source[span.start_byte..span.end_byte].to_string();
    let id = build_finding_id(file_path, rule_id, span.start_byte, span.end_byte);

    Some(MigrationFinding {
        id,
        rule_id: rule_id.to_string(),
        target_step,
        bucket,
        category,
        file: file_path.to_path_buf(),
        span,
        original_code,
        suggested_replacement,
        explanation,
        logic_impact,
        status: ResolutionStatus::Pending,
    })
}

fn build_finding_id(file_path: &Path, rule_id: &str, start: usize, end: usize) -> String {
    let input = format!("{}:{}:{}:{}", file_path.to_string_lossy(), rule_id, start, end);
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in input.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{rule_id}-{hash:08x}")
}
