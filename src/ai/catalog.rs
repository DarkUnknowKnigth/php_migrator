use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Protocolo de comunicación HTTP soportado por el proveedor de IA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiProtocol {
    GeminiNative,
    AnthropicMessages,
    OpenAiCompatible,
    OllamaLocal,
}

impl fmt::Display for AiProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AiProtocol::GeminiNative => write!(f, "Gemini Native"),
            AiProtocol::AnthropicMessages => write!(f, "Anthropic Messages"),
            AiProtocol::OpenAiCompatible => write!(f, "OpenAI Compatible"),
            AiProtocol::OllamaLocal => write!(f, "Ollama Local"),
        }
    }
}

fn de_static_str<'de, D>(deserializer: D) -> std::result::Result<&'static str, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <String as Deserialize>::deserialize(deserializer)?;
    Ok(Box::leak(value.into_boxed_str()))
}

fn de_opt_static_str<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<&'static str>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <Option<String> as Deserialize>::deserialize(deserializer)?;
    Ok(value.map(|s| Box::leak(s.into_boxed_str()) as &'static str))
}

fn de_vec_static_str<'de, D>(deserializer: D) -> std::result::Result<Vec<&'static str>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = <Vec<String> as Deserialize>::deserialize(deserializer)?;
    Ok(values
        .into_iter()
        .map(|s| Box::leak(s.into_boxed_str()) as &'static str)
        .collect())
}

/// Metadatos de un proveedor de IA dentro del catálogo BYOK incorporado.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiProviderInfo {
    #[serde(deserialize_with = "de_static_str")]
    pub id: &'static str,
    #[serde(deserialize_with = "de_static_str")]
    pub display_name: &'static str,
    pub protocol: AiProtocol,
    #[serde(deserialize_with = "de_static_str")]
    pub default_base_url: &'static str,
    #[serde(default, deserialize_with = "de_opt_static_str")]
    pub env_var: Option<&'static str>,
    pub requires_token: bool,
    #[serde(deserialize_with = "de_vec_static_str")]
    pub suggested_models: Vec<&'static str>,
    #[serde(deserialize_with = "de_static_str")]
    pub notes: &'static str,
}

/// Configuración activa del asistente de IA (la clave permanece únicamente en memoria o entorno).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    pub provider_id: String,
    pub model: String,
    pub base_url: String,
    pub protocol: AiProtocol,
    pub api_key: Option<String>,
}

/// Estructura auxiliar para persistir metadatos en disco excluyendo cualquier `api_key`.
#[derive(Debug, Serialize, Deserialize)]
struct StoredAiConfig {
    provider_id: String,
    model: String,
    base_url: String,
    protocol: AiProtocol,
}

/// Devuelve el catálogo incorporado con los 9 proveedores de IA BYOK soportados.
pub fn builtin_catalog() -> Vec<AiProviderInfo> {
    vec![
        AiProviderInfo {
            id: "gemini",
            display_name: "Google Gemini",
            protocol: AiProtocol::GeminiNative,
            default_base_url: "https://generativelanguage.googleapis.com/v1beta",
            env_var: Some("GEMINI_API_KEY"),
            requires_token: true,
            suggested_models: vec!["gemini-2.5-pro", "gemini-2.5-flash"],
            notes: "API nativa de Google AI Studio. Usa GEMINI_API_KEY.",
        },
        AiProviderInfo {
            id: "anthropic",
            display_name: "Anthropic Claude",
            protocol: AiProtocol::AnthropicMessages,
            default_base_url: "https://api.anthropic.com/v1",
            env_var: Some("ANTHROPIC_API_KEY"),
            requires_token: true,
            suggested_models: vec!["claude-sonnet-4-20250514", "claude-3-7-sonnet-latest"],
            notes: "API Messages de Anthropic. Usa ANTHROPIC_API_KEY.",
        },
        AiProviderInfo {
            id: "openai",
            display_name: "OpenAI",
            protocol: AiProtocol::OpenAiCompatible,
            default_base_url: "https://api.openai.com/v1",
            env_var: Some("OPENAI_API_KEY"),
            requires_token: true,
            suggested_models: vec!["gpt-4.1", "gpt-4o", "o4-mini"],
            notes: "API oficial de OpenAI. Usa OPENAI_API_KEY.",
        },
        AiProviderInfo {
            id: "deepseek",
            display_name: "DeepSeek",
            protocol: AiProtocol::OpenAiCompatible,
            default_base_url: "https://api.deepseek.com/v1",
            env_var: Some("DEEPSEEK_API_KEY"),
            requires_token: true,
            suggested_models: vec!["deepseek-chat", "deepseek-reasoner"],
            notes: "Endpoint compatible con OpenAI para modelos DeepSeek.",
        },
        AiProviderInfo {
            id: "openrouter",
            display_name: "OpenRouter",
            protocol: AiProtocol::OpenAiCompatible,
            default_base_url: "https://openrouter.ai/api/v1",
            env_var: Some("OPENROUTER_API_KEY"),
            requires_token: true,
            suggested_models: vec![
                "anthropic/claude-sonnet-4",
                "google/gemini-2.5-pro",
                "openai/gpt-4.1",
            ],
            notes: "Router unificado compatible con OpenAI para múltiples modelos.",
        },
        AiProviderInfo {
            id: "groq",
            display_name: "Groq",
            protocol: AiProtocol::OpenAiCompatible,
            default_base_url: "https://api.groq.com/openai/v1",
            env_var: Some("GROQ_API_KEY"),
            requires_token: true,
            suggested_models: vec!["llama-3.3-70b-versatile", "qwen-qwq-32b"],
            notes: "Inferencia rápida LPU compatible con OpenAI. Usa GROQ_API_KEY.",
        },
        AiProviderInfo {
            id: "xai",
            display_name: "xAI Grok",
            protocol: AiProtocol::OpenAiCompatible,
            default_base_url: "https://api.x.ai/v1",
            env_var: Some("XAI_API_KEY"),
            requires_token: true,
            suggested_models: vec!["grok-3", "grok-3-mini"],
            notes: "API de xAI compatible con OpenAI. Usa XAI_API_KEY.",
        },
        AiProviderInfo {
            id: "ollama",
            display_name: "Ollama Local",
            protocol: AiProtocol::OllamaLocal,
            default_base_url: "http://localhost:11434",
            env_var: None,
            requires_token: false,
            suggested_models: vec!["qwen2.5-coder:14b", "deepseek-coder-v2", "llama3.2"],
            notes: "Ejecución local sin token ni envío de código a la nube.",
        },
        AiProviderInfo {
            id: "custom",
            display_name: "Endpoint Custom (OpenAI)",
            protocol: AiProtocol::OpenAiCompatible,
            default_base_url: "http://localhost:8000/v1",
            env_var: Some("CUSTOM_AI_API_KEY"),
            requires_token: false,
            suggested_models: vec!["custom-model"],
            notes: "Servidor personalizado compatible con OpenAI (vLLM, LM Studio, LiteLLM, etc.).",
        },
    ]
}

/// Busca un proveedor por su identificador (insensible a mayúsculas/minúsculas).
pub fn find_provider(id: &str) -> Option<AiProviderInfo> {
    let normalized = id.trim().to_ascii_lowercase();
    builtin_catalog()
        .into_iter()
        .find(|p| p.id == normalized.as_str())
}

/// Intenta resolver la clave API del proveedor desde su variable de entorno asociada.
pub fn resolve_api_key_from_env(provider: &AiProviderInfo) -> Option<String> {
    let var_name = provider.env_var?;
    std::env::var(var_name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn resolve_config_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg));
        }
    }

    #[cfg(windows)]
    if let Some(appdata) = std::env::var_os("APPDATA") {
        if !appdata.is_empty() {
            return Ok(PathBuf::from(appdata));
        }
    }

    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return Ok(PathBuf::from(home).join(".config"));
        }
    }

    if let Some(user_profile) = std::env::var_os("USERPROFILE") {
        if !user_profile.is_empty() {
            return Ok(PathBuf::from(user_profile).join(".config"));
        }
    }

    anyhow::bail!(
        "No se pudo determinar el directorio de configuración del usuario (APPDATA, HOME o USERPROFILE)."
    )
}

fn ai_config_file_path() -> Result<PathBuf> {
    Ok(resolve_config_dir()?
        .join("php-migrator")
        .join("ai_config.toml"))
}

/// Carga los metadatos guardados de IA desde `<config_dir>/php-migrator/ai_config.toml`.
/// Nunca lee credenciales del archivo; si el proveedor define variable de entorno, la resuelve en memoria.
pub fn load_saved_config() -> Result<Option<AiConfig>> {
    let path = ai_config_file_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "No se pudo leer la configuración de IA desde {}",
            path.display()
        )
    })?;

    let stored: StoredAiConfig = toml::from_str(&raw).with_context(|| {
        format!(
            "Formato TOML inválido en la configuración de IA: {}",
            path.display()
        )
    })?;

    let env_key = find_provider(&stored.provider_id)
        .and_then(|provider| resolve_api_key_from_env(&provider));

    Ok(Some(AiConfig {
        provider_id: stored.provider_id,
        model: stored.model,
        base_url: stored.base_url,
        protocol: stored.protocol,
        api_key: env_key,
    }))
}

/// Guarda únicamente los metadatos del proveedor de IA (`provider_id`, `model`, `base_url`, `protocol`)
/// en `<config_dir>/php-migrator/ai_config.toml`, sin escribir `api_key` en disco.
pub fn save_config_metadata(config: &AiConfig) -> Result<()> {
    let path = ai_config_file_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "No se pudo crear el directorio de configuración {}",
                parent.display()
            )
        })?;
    }

    let stored = StoredAiConfig {
        provider_id: config.provider_id.clone(),
        model: config.model.clone(),
        base_url: config.base_url.clone(),
        protocol: config.protocol,
    };

    let serialized = toml::to_string_pretty(&stored)
        .context("Error al serializar metadatos de configuración IA a TOML")?;

    std::fs::write(&path, serialized).with_context(|| {
        format!(
            "No se pudo escribir la configuración de IA en {}",
            path.display()
        )
    })?;

    Ok(())
}

/// Guía Markdown embebida con los pasos para obtener los tokens BYOK de cada proveedor.
pub const TOKEN_GUIDE_MARKDOWN: &str = include_str!("../../docs/COMO_OBTENER_TOKENS_IA.md");

/// Devuelve la guía Markdown completa para obtener tokens de IA, o únicamente
/// la sección correspondiente a `provider_id` si se especifica uno.
pub fn render_token_help_for_provider(provider_id: Option<&str>) -> String {
    let Some(raw_id) = provider_id.map(|s| s.trim().to_ascii_lowercase()) else {
        return TOKEN_GUIDE_MARKDOWN.to_string();
    };
    if raw_id.is_empty() {
        return TOKEN_GUIDE_MARKDOWN.to_string();
    }

    let marker = format!("## [{raw_id}]");
    let mut section_lines: Vec<&str> = Vec::new();
    let mut capturing = false;

    for line in TOKEN_GUIDE_MARKDOWN.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("## [") {
            if capturing {
                break;
            }
            if trimmed.to_ascii_lowercase().starts_with(&marker) {
                capturing = true;
            }
        }
        if capturing {
            section_lines.push(line);
        }
    }

    if section_lines.is_empty() {
        TOKEN_GUIDE_MARKDOWN.to_string()
    } else {
        section_lines.join("\n").trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_contains_nine_expected_providers() {
        let catalog = builtin_catalog();
        assert_eq!(catalog.len(), 9);
        let ids: Vec<&str> = catalog.iter().map(|p| p.id).collect();
        assert_eq!(
            ids,
            vec![
                "gemini",
                "anthropic",
                "openai",
                "deepseek",
                "openrouter",
                "groq",
                "xai",
                "ollama",
                "custom",
            ]
        );
    }

    #[test]
    fn find_provider_is_case_insensitive() {
        let gemini = find_provider("GEMINI").expect("gemini debe existir");
        assert_eq!(gemini.protocol, AiProtocol::GeminiNative);
        assert_eq!(gemini.env_var, Some("GEMINI_API_KEY"));

        let ollama = find_provider("ollama").expect("ollama debe existir");
        assert!(!ollama.requires_token);
        assert_eq!(ollama.protocol, AiProtocol::OllamaLocal);
    }

    #[test]
    fn stored_config_never_serializes_api_key() {
        let stored = StoredAiConfig {
            provider_id: "openai".to_string(),
            model: "gpt-4.1".to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
            protocol: AiProtocol::OpenAiCompatible,
        };
        let toml_text = toml::to_string_pretty(&stored).unwrap();
        assert!(!toml_text.contains("api_key"));
    }
}
