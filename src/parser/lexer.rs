use crate::models::{CodeBlock, PhpBlockKind, Span};

/// Categorías léxicas de tokens PHP emitidas por el lexer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhpTokenKind {
    Word,
    Variable,
    StringLiteral,
    Number,
    Comment,
    Operator,
    Punctuation,
    Whitespace,
}

/// Token léxico de PHP con su texto fuente y rango exacto en bytes/líneas/columnas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpToken {
    pub kind: PhpTokenKind,
    pub text: String,
    pub span: Span,
}

/// Índice de inicio de líneas para calcular `Span` en O(log L) manteniendo exactitud UTF-8.
struct LineIndex {
    line_starts: Vec<usize>,
}

impl LineIndex {
    fn new(source: &str) -> Self {
        let mut line_starts = Vec::with_capacity(source.len() / 32 + 1);
        line_starts.push(0);
        for (idx, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(idx + 1);
            }
        }
        Self { line_starts }
    }

    fn line_col(&self, source: &str, byte_pos: usize) -> (usize, usize) {
        let pos = floor_char_boundary(source, byte_pos.min(source.len()));
        let line_idx = self
            .line_starts
            .partition_point(|&start| start <= pos)
            .saturating_sub(1);
        let line_start = self.line_starts[line_idx];
        let col = source[line_start..pos].chars().count() + 1;
        (line_idx + 1, col)
    }

    fn span(&self, source: &str, start_byte: usize, end_byte: usize) -> Span {
        let start = floor_char_boundary(source, start_byte.min(source.len()));
        let end = floor_char_boundary(source, end_byte.min(source.len())).max(start);
        let (start_line, start_col) = self.line_col(source, start);
        let (end_line, end_col) = self.line_col(source, end);
        Span {
            start_byte: start,
            end_byte: end,
            start_line,
            start_col,
            end_line,
            end_col,
        }
    }
}

/// Ajusta un índice de bytes hacia atrás hasta el límite de carácter UTF-8 válido más cercano.
fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// Calcula un `Span` con coordenadas línea/columna base 1 y precisión UTF-8 a partir de offsets en bytes.
pub fn span_from_bytes(source: &str, start_byte: usize, end_byte: usize) -> Span {
    let start = floor_char_boundary(source, start_byte.min(source.len()));
    let end = floor_char_boundary(source, end_byte.min(source.len())).max(start);

    let mut line = 1usize;
    let mut col = 1usize;
    for ch in source[..start].chars() {
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    let start_line = line;
    let start_col = col;

    for ch in source[start..end].chars() {
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }

    Span {
        start_byte: start,
        end_byte: end,
        start_line,
        start_col,
        end_line: line,
        end_col: col,
    }
}

/// Divide un archivo fuente en segmentos HTML/CSS/JS (`is_php: false`) y bloques PHP (`is_php: true`).
///
/// Soporta `<?php`, `<?=` y `<?` (evitando confundir declaraciones `<?xml`), e ignora `?>`
/// cuando aparece dentro de comentarios (`//`, `#`, `/*...*/`) o literales de cadena
/// (`'...'`, `"..."` y heredoc/nowdoc).
pub fn split_blocks(source: &str) -> Vec<CodeBlock> {
    if source.is_empty() {
        return Vec::new();
    }

    let line_index = LineIndex::new(source);
    let bytes = source.as_bytes();
    let len = bytes.len();

    let mut blocks = Vec::new();
    let mut pos = 0usize;
    let mut block_start = 0usize;
    let mut in_php = false;
    let mut php_kind = PhpBlockKind::Standard;

    while pos < len {
        if !in_php {
            let Some(rel) = source[pos..].find("<?") else {
                break;
            };
            let tag_pos = pos + rel;
            let rest = &source[tag_pos..];
            let rest_bytes = rest.as_bytes();

            if rest.len() >= 5
                && rest[..5].eq_ignore_ascii_case("<?php")
                && (rest.len() == 5
                    || matches!(rest_bytes[5], b' ' | b'\t' | b'\r' | b'\n')
                    || rest_bytes[5..].starts_with(b"?>"))
            {
                if tag_pos > block_start {
                    blocks.push(CodeBlock {
                        is_php: false,
                        kind: None,
                        span: line_index.span(source, block_start, tag_pos),
                    });
                }
                in_php = true;
                php_kind = PhpBlockKind::Standard;
                block_start = tag_pos;
                pos = tag_pos + 5;
            } else if rest_bytes.starts_with(b"<?=") {
                if tag_pos > block_start {
                    blocks.push(CodeBlock {
                        is_php: false,
                        kind: None,
                        span: line_index.span(source, block_start, tag_pos),
                    });
                }
                in_php = true;
                php_kind = PhpBlockKind::ShortEcho;
                block_start = tag_pos;
                pos = tag_pos + 3;
            } else if rest.len() >= 5
                && rest[..5].eq_ignore_ascii_case("<?xml")
                && !is_ident_continue_byte(rest_bytes.get(5).copied())
            {
                // Mantener declaraciones <?xml ...?> como contenido no-PHP.
                pos = tag_pos + 5;
            } else {
                if tag_pos > block_start {
                    blocks.push(CodeBlock {
                        is_php: false,
                        kind: None,
                        span: line_index.span(source, block_start, tag_pos),
                    });
                }
                in_php = true;
                php_kind = PhpBlockKind::ShortOpen;
                block_start = tag_pos;
                pos = tag_pos + 2;
            }
        } else {
            let b = bytes[pos];
            if b == b'?' && bytes.get(pos + 1) == Some(&b'>') {
                let end = pos + 2;
                blocks.push(CodeBlock {
                    is_php: true,
                    kind: Some(php_kind),
                    span: line_index.span(source, block_start, end),
                });
                in_php = false;
                pos = end;
                block_start = end;
            } else if b == b'\'' {
                pos = scan_single_quoted_string(source, pos, len);
            } else if b == b'"' {
                pos = scan_double_quoted_string(source, pos, len);
            } else if b == b'/' && bytes.get(pos + 1) == Some(&b'/') {
                pos = scan_line_comment(source, pos + 2, len);
            } else if b == b'#' && bytes.get(pos + 1) != Some(&b'[') {
                pos = scan_line_comment(source, pos + 1, len);
            } else if b == b'/' && bytes.get(pos + 1) == Some(&b'*') {
                pos = scan_block_comment(source, pos + 2, len);
            } else if b == b'<' && bytes[pos..len].starts_with(b"<<<") {
                if let Some(hd_end) = scan_heredoc_or_nowdoc(source, pos, len) {
                    pos = hd_end;
                } else {
                    pos += 1;
                }
            } else {
                pos += next_char_len(source, pos);
            }
        }
    }

    if block_start < len {
        blocks.push(CodeBlock {
            is_php: in_php,
            kind: if in_php { Some(php_kind) } else { None },
            span: line_index.span(source, block_start, len),
        });
    }

    blocks
}

/// Tokeniza un `CodeBlock` de PHP produciendo tokens con offsets exactos respecto al `source` completo.
///
/// Para bloques no-PHP devuelve un vector vacío. Conserva los `StringLiteral` dobles completos
/// (incluyendo interpolaciones `${var}` / `{$var}`) para su inspección posterior.
pub fn tokenize_block(source: &str, block: &CodeBlock) -> Vec<PhpToken> {
    if !block.is_php {
        return Vec::new();
    }

    let line_index = LineIndex::new(source);
    let bytes = source.as_bytes();
    let mut pos = floor_char_boundary(source, block.span.start_byte.min(source.len()));
    let end = floor_char_boundary(source, block.span.end_byte.min(source.len())).max(pos);

    // Saltar etiqueta de apertura si el CodeBlock la incluye.
    let slice = &source[pos..end];
    if slice.len() >= 5
        && slice[..5].eq_ignore_ascii_case("<?php")
        && (slice.len() == 5
            || matches!(slice.as_bytes()[5], b' ' | b'\t' | b'\r' | b'\n')
            || slice.as_bytes()[5..].starts_with(b"?>"))
    {
        pos += 5;
    } else if slice.as_bytes().starts_with(b"<?=") {
        pos += 3;
    } else if slice.as_bytes().starts_with(b"<?") {
        pos += 2;
    }

    let mut tokens = Vec::new();

    while pos < end {
        // Detener en la etiqueta de cierre `?>` al final del bloque (fuera de cadenas/comentarios).
        if pos + 2 == end && bytes[pos] == b'?' && bytes[pos + 1] == b'>' {
            break;
        }

        let b = bytes[pos];

        // Espacios en blanco
        if is_whitespace_byte(b)
            || (b >= 0x80
                && source[pos..end]
                    .chars()
                    .next()
                    .is_some_and(char::is_whitespace))
        {
            let start = pos;
            while pos < end {
                let nb = bytes[pos];
                if is_whitespace_byte(nb) {
                    pos += 1;
                } else if nb >= 0x80
                    && source[pos..end]
                        .chars()
                        .next()
                        .is_some_and(char::is_whitespace)
                {
                    pos += next_char_len(source, pos);
                } else {
                    break;
                }
            }
            push_token(
                &mut tokens,
                &line_index,
                source,
                PhpTokenKind::Whitespace,
                start,
                pos,
            );
            continue;
        }

        // Comentarios //, # (no #[ atributo), /* ... */
        if b == b'/' && pos + 1 < end && bytes[pos + 1] == b'/' {
            let start = pos;
            pos = scan_line_comment(source, pos + 2, end);
            push_token(
                &mut tokens,
                &line_index,
                source,
                PhpTokenKind::Comment,
                start,
                pos,
            );
            continue;
        }
        if b == b'#' && bytes.get(pos + 1) != Some(&b'[') {
            let start = pos;
            pos = scan_line_comment(source, pos + 1, end);
            push_token(
                &mut tokens,
                &line_index,
                source,
                PhpTokenKind::Comment,
                start,
                pos,
            );
            continue;
        }
        if b == b'/' && pos + 1 < end && bytes[pos + 1] == b'*' {
            let start = pos;
            pos = scan_block_comment(source, pos + 2, end);
            push_token(
                &mut tokens,
                &line_index,
                source,
                PhpTokenKind::Comment,
                start,
                pos,
            );
            continue;
        }

        // Cadenas '...' y "..."
        if b == b'\'' {
            let start = pos;
            pos = scan_single_quoted_string(source, pos, end);
            push_token(
                &mut tokens,
                &line_index,
                source,
                PhpTokenKind::StringLiteral,
                start,
                pos,
            );
            continue;
        }
        if b == b'"' {
            let start = pos;
            pos = scan_double_quoted_string(source, pos, end);
            push_token(
                &mut tokens,
                &line_index,
                source,
                PhpTokenKind::StringLiteral,
                start,
                pos,
            );
            continue;
        }

        // Heredoc / Nowdoc <<<LABEL
        if b == b'<' && bytes[pos..end].starts_with(b"<<<") {
            if let Some(hd_end) = scan_heredoc_or_nowdoc(source, pos, end) {
                let start = pos;
                pos = hd_end;
                push_token(
                    &mut tokens,
                    &line_index,
                    source,
                    PhpTokenKind::StringLiteral,
                    start,
                    pos,
                );
                continue;
            }
        }

        // Variables $ident y ${ident}
        if b == b'$' {
            let start = pos;
            if pos + 2 < end && bytes[pos + 1] == b'{' {
                let ident_start = pos + 2;
                let ident_end = scan_ident(source, ident_start, end);
                if ident_end > ident_start && ident_end < end && bytes[ident_end] == b'}' {
                    pos = ident_end + 1;
                    push_token(
                        &mut tokens,
                        &line_index,
                        source,
                        PhpTokenKind::Variable,
                        start,
                        pos,
                    );
                    continue;
                }
            } else if pos + 1 < end && is_ident_start_byte(bytes[pos + 1]) {
                pos = scan_ident(source, pos + 1, end);
                push_token(
                    &mut tokens,
                    &line_index,
                    source,
                    PhpTokenKind::Variable,
                    start,
                    pos,
                );
                continue;
            }
            // '$' suelto (ej. $$var)
            pos += 1;
            push_token(
                &mut tokens,
                &line_index,
                source,
                PhpTokenKind::Operator,
                start,
                pos,
            );
            continue;
        }

        // Números (enteros, flotantes, hex, binario, octal y separadores '_')
        if b.is_ascii_digit() || (b == b'.' && pos + 1 < end && bytes[pos + 1].is_ascii_digit()) {
            let start = pos;
            pos = scan_number(bytes, pos, end);
            push_token(
                &mut tokens,
                &line_index,
                source,
                PhpTokenKind::Number,
                start,
                pos,
            );
            continue;
        }

        // Palabras (keywords e identificadores)
        if is_ident_start_byte(b) {
            let start = pos;
            pos = scan_ident(source, pos, end);
            push_token(
                &mut tokens,
                &line_index,
                source,
                PhpTokenKind::Word,
                start,
                pos,
            );
            continue;
        }

        // Operadores multi-carácter (del más largo al más corto)
        let rem = &bytes[pos..end];
        if let Some(op_len) = match_multi_char_operator(rem) {
            let start = pos;
            pos += op_len;
            push_token(
                &mut tokens,
                &line_index,
                source,
                PhpTokenKind::Operator,
                start,
                pos,
            );
            continue;
        }

        // Puntuación (incluyendo '#' de atributo '#[', '\', '{', '}', etc.)
        if matches!(
            b,
            b'{' | b'}' | b'(' | b')' | b'[' | b']' | b';' | b',' | b':' | b'?' | b'\\' | b'#'
        ) {
            let start = pos;
            pos += 1;
            push_token(
                &mut tokens,
                &line_index,
                source,
                PhpTokenKind::Punctuation,
                start,
                pos,
            );
            continue;
        }

        // Operadores de un carácter
        if matches!(
            b,
            b'+' | b'-'
                | b'*'
                | b'/'
                | b'%'
                | b'='
                | b'<'
                | b'>'
                | b'!'
                | b'&'
                | b'|'
                | b'^'
                | b'~'
                | b'.'
                | b'@'
                | b'`'
        ) {
            let start = pos;
            pos += 1;
            push_token(
                &mut tokens,
                &line_index,
                source,
                PhpTokenKind::Operator,
                start,
                pos,
            );
            continue;
        }

        // Fallback seguro para cualquier carácter inesperado
        let start = pos;
        pos += next_char_len(source, pos);
        push_token(
            &mut tokens,
            &line_index,
            source,
            PhpTokenKind::Punctuation,
            start,
            pos,
        );
    }

    tokens
}

fn push_token(
    tokens: &mut Vec<PhpToken>,
    line_index: &LineIndex,
    source: &str,
    kind: PhpTokenKind,
    start: usize,
    end: usize,
) {
    tokens.push(PhpToken {
        kind,
        text: source[start..end].to_string(),
        span: line_index.span(source, start, end),
    });
}

fn next_char_len(source: &str, pos: usize) -> usize {
    source[pos..]
        .chars()
        .next()
        .map_or(1, char::len_utf8)
}

fn is_whitespace_byte(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

fn is_ident_start_byte(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b >= 0x80
}

fn is_ident_continue_byte(opt: Option<u8>) -> bool {
    matches!(
        opt,
        Some(b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | 0x80..=0xff)
    )
}

fn scan_ident(source: &str, mut pos: usize, end: usize) -> usize {
    let bytes = source.as_bytes();
    while pos < end {
        let b = bytes[pos];
        if b.is_ascii_alphanumeric() || b == b'_' {
            pos += 1;
        } else if b >= 0x80 {
            let step = next_char_len(source, pos);
            if pos + step <= end {
                pos += step;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    pos
}

fn scan_line_comment(source: &str, mut pos: usize, end: usize) -> usize {
    let bytes = source.as_bytes();
    while pos < end {
        if bytes[pos] == b'\n' || bytes[pos] == b'\r' {
            break;
        }
        pos += next_char_len(source, pos);
    }
    pos
}

fn scan_block_comment(source: &str, mut pos: usize, end: usize) -> usize {
    let bytes = source.as_bytes();
    while pos < end {
        if bytes[pos] == b'*' && pos + 1 < end && bytes[pos + 1] == b'/' {
            return pos + 2;
        }
        pos += next_char_len(source, pos);
    }
    end
}

fn scan_single_quoted_string(source: &str, mut pos: usize, end: usize) -> usize {
    let bytes = source.as_bytes();
    if pos >= end || bytes[pos] != b'\'' {
        return pos;
    }
    pos += 1;
    while pos < end {
        let b = bytes[pos];
        if b == b'\\' {
            pos += 1;
            if pos < end {
                pos += next_char_len(source, pos);
            }
        } else if b == b'\'' {
            return pos + 1;
        } else {
            pos += next_char_len(source, pos);
        }
    }
    end
}

fn scan_double_quoted_string(source: &str, mut pos: usize, end: usize) -> usize {
    let bytes = source.as_bytes();
    if pos >= end || bytes[pos] != b'"' {
        return pos;
    }
    pos += 1;
    let mut interp_brace_depth = 0usize;

    while pos < end {
        let b = bytes[pos];
        if b == b'\\' {
            pos += 1;
            if pos < end {
                pos += next_char_len(source, pos);
            }
            continue;
        }

        if interp_brace_depth == 0 {
            if b == b'"' {
                return pos + 1;
            } else if b == b'{' && pos + 1 < end && bytes[pos + 1] == b'$' {
                interp_brace_depth = 1;
                pos += 2;
            } else if b == b'$' && pos + 1 < end && bytes[pos + 1] == b'{' {
                interp_brace_depth = 1;
                pos += 2;
            } else {
                pos += next_char_len(source, pos);
            }
        } else if b == b'{' {
            interp_brace_depth += 1;
            pos += 1;
        } else if b == b'}' {
            interp_brace_depth -= 1;
            pos += 1;
        } else if b == b'\'' {
            pos = scan_single_quoted_string(source, pos, end);
        } else if b == b'"' {
            pos = scan_simple_quoted_for_interp(source, pos, end);
        } else {
            pos += next_char_len(source, pos);
        }
    }
    end
}

fn scan_simple_quoted_for_interp(source: &str, mut pos: usize, end: usize) -> usize {
    let bytes = source.as_bytes();
    pos += 1;
    while pos < end {
        let b = bytes[pos];
        if b == b'\\' {
            pos += 1;
            if pos < end {
                pos += next_char_len(source, pos);
            }
        } else if b == b'"' {
            return pos + 1;
        } else {
            pos += next_char_len(source, pos);
        }
    }
    end
}

fn scan_heredoc_or_nowdoc(source: &str, start: usize, end: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if start + 3 > end || &bytes[start..start + 3] != b"<<<" {
        return None;
    }
    let mut p = start + 3;
    while p < end && matches!(bytes[p], b' ' | b'\t') {
        p += 1;
    }
    if p >= end {
        return None;
    }

    let quote = match bytes[p] {
        b'\'' | b'"' => {
            let q = bytes[p];
            p += 1;
            Some(q)
        }
        _ => None,
    };

    if p >= end || !is_ident_start_byte(bytes[p]) {
        return None;
    }
    let label_start = p;
    p = scan_ident(source, p, end);
    let label_end = p;
    if label_end == label_start {
        return None;
    }
    let label = &bytes[label_start..label_end];

    if let Some(q) = quote {
        if p >= end || bytes[p] != q {
            return None;
        }
        p += 1;
    }

    while p < end && matches!(bytes[p], b' ' | b'\t') {
        p += 1;
    }
    if p >= end {
        return None;
    }
    if bytes[p] == b'\r' {
        p += 1;
        if p < end && bytes[p] == b'\n' {
            p += 1;
        }
    } else if bytes[p] == b'\n' {
        p += 1;
    } else {
        return None;
    }

    while p < end {
        while p < end && matches!(bytes[p], b' ' | b'\t') {
            p += 1;
        }
        if p + label.len() <= end && &bytes[p..p + label.len()] == label {
            let after = bytes[..end].get(p + label.len()).copied();
            if !is_ident_continue_byte(after) {
                return Some(p + label.len());
            }
        }
        while p < end && bytes[p] != b'\n' {
            p += next_char_len(source, p);
        }
        if p < end && bytes[p] == b'\n' {
            p += 1;
        }
    }

    Some(end)
}

fn scan_number(bytes: &[u8], start: usize, end: usize) -> usize {
    let mut pos = start;
    if bytes[pos] == b'0' && pos + 1 < end {
        match bytes[pos + 1] {
            b'x' | b'X' => {
                pos += 2;
                while pos < end && (bytes[pos].is_ascii_hexdigit() || bytes[pos] == b'_') {
                    pos += 1;
                }
                return pos;
            }
            b'b' | b'B' => {
                pos += 2;
                while pos < end && matches!(bytes[pos], b'0' | b'1' | b'_') {
                    pos += 1;
                }
                return pos;
            }
            b'o' | b'O' => {
                pos += 2;
                while pos < end && (matches!(bytes[pos], b'0'..=b'7') || bytes[pos] == b'_') {
                    pos += 1;
                }
                return pos;
            }
            _ => {}
        }
    }

    while pos < end && (bytes[pos].is_ascii_digit() || bytes[pos] == b'_') {
        pos += 1;
    }

    if pos < end && bytes[pos] == b'.' {
        // Evitar confundir con concatenación si hay otro '.' inmediatamente después,
        // pero permitir '.5' o '1.5' o '1.'.
        if pos + 1 >= end || bytes[pos + 1] != b'.' {
            pos += 1;
            while pos < end && (bytes[pos].is_ascii_digit() || bytes[pos] == b'_') {
                pos += 1;
            }
        }
    }

    if pos < end && matches!(bytes[pos], b'e' | b'E') {
        let mut exp_pos = pos + 1;
        if exp_pos < end && matches!(bytes[exp_pos], b'+' | b'-') {
            exp_pos += 1;
        }
        if exp_pos < end && bytes[exp_pos].is_ascii_digit() {
            pos = exp_pos;
            while pos < end && (bytes[pos].is_ascii_digit() || bytes[pos] == b'_') {
                pos += 1;
            }
        }
    }

    pos
}

fn match_multi_char_operator(rem: &[u8]) -> Option<usize> {
    const OPS_3: &[&[u8]] = &[
        b"===", b"!==", b"<=>", b"??=", b"**=", b"<<=", b">>=", b"...", b"?->",
    ];
    for op in OPS_3 {
        if rem.starts_with(op) {
            return Some(3);
        }
    }

    const OPS_2: &[&[u8]] = &[
        b"->", b"=>", b"::", b"==", b"!=", b"<>", b"<=", b">=", b"??", b"++", b"--", b"**",
        b"&&", b"||", b"<<", b">>", b"+=", b"-=", b"*=", b"/=", b"%=", b".=", b"&=", b"|=", b"^=",
    ];
    for op in OPS_2 {
        if rem.starts_with(op) {
            return Some(2);
        }
    }

    None
}
