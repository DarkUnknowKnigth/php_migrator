pub mod ast;
pub mod lexer;

use std::path::Path;

use crate::models::{CodeBlock, FileSummary};

/// Parsea un archivo PHP o PHP+HTML mixto y construye su resumen estructural `FileSummary`.
pub fn parse_file(path: &Path, project_root: &Path, source: &str) -> FileSummary {
    ast::analyze_file(path, project_root, source)
}

/// Divide un código fuente en segmentos HTML/CSS/JS y bloques PHP (`<?php`, `<?=`, `<?`).
pub fn parse_php_blocks(source: &str) -> Vec<CodeBlock> {
    lexer::split_blocks(source)
}

/// Tokeniza un `CodeBlock` PHP conservando offsets exactos en bytes sobre `source`.
pub fn tokenize_php_block(source: &str, block: &CodeBlock) -> Vec<lexer::PhpToken> {
    lexer::tokenize_block(source, block)
}
