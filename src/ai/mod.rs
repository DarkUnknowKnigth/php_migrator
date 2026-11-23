//! Módulo de asistencia IA BYOK (Bring Your Own Key) con sanitización de secretos.

pub mod catalog;
pub mod client;
pub mod optimizer;

pub use catalog::{
    builtin_catalog, find_provider, load_saved_config, render_token_help_for_provider,
    resolve_api_key_from_env, save_config_metadata, AiConfig, AiProtocol, AiProviderInfo,
    TOKEN_GUIDE_MARKDOWN,
};
pub use client::{
    ask_ai_batch_for_file, ask_ai_for_finding, build_context_snippet, redact_secrets,
};
pub use optimizer::{
    build_merged_file_batch_context, condense_context_for_finding, estimate_tokens,
    strip_php_comments_and_blank_lines, AiPatternCache, TokenOptimizationStats,
};
