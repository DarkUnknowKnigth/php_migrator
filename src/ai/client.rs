use crate::ai::catalog::{AiConfig, AiProtocol};
use crate::models::{AiResolution, MigrationFinding};
use anyhow::{Context, Result};
use regex::{Captures, Regex};
use serde_json::{json, Value};
use std::sync::OnceLock;
use std::time::Duration;

struct SecretPatterns {
    sk_key: Regex,
    gsk_key: Regex,
    xai_key: Regex,
    google_key: Regex,
    bearer: Regex,
    php_var_sq: Regex,
    php_var_dq: Regex,
    php_arr_sq: Regex,
    php_arr_dq: Regex,
    env_assign: Regex,
    db_connect_sq: Regex,
    db_connect_dq: Regex,
    oci_connect_sq: Regex,
    oci_connect_dq: Regex,
    dsn_pwd: Regex,
    url_creds: Regex,
}

fn secret_patterns() -> &'static SecretPatterns {
    static PATTERNS: OnceLock<SecretPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| SecretPatterns {
        sk_key: Regex::new(r"\bsk-(?:ant-|proj-|or-)?[A-Za-z0-9_\-]{8,}\b")
            .expect("regex sk_key válida"),
        gsk_key: Regex::new(r"\bgsk_[A-Za-z0-9_\-]{12,}\b").expect("regex gsk_key válida"),
        xai_key: Regex::new(r"\bxai-[A-Za-z0-9_\-]{12,}\b").expect("regex xai_key válida"),
        google_key: Regex::new(r"\bAIza[0-9A-Za-z_\-]{12,}\b").expect("regex google_key válida"),
        bearer: Regex::new(r"(?i)\b(Bearer\s+)[A-Za-z0-9\-._~+/]+=*")
            .expect("regex bearer válida"),
        php_var_sq: Regex::new(
            r#"(?i)(\$[a-z0-9_]*(?:pass(?:word|wd)?|secret|token|api_?key|pwd)[a-z0-9_]*\s*=\s*)'([^'\r\n]+)'"#,
        )
        .expect("regex php_var_sq válida"),
        php_var_dq: Regex::new(
            r#"(?i)(\$[a-z0-9_]*(?:pass(?:word|wd)?|secret|token|api_?key|pwd)[a-z0-9_]*\s*=\s*)"([^"\r\n]+)""#,
        )
        .expect("regex php_var_dq válida"),
        php_arr_sq: Regex::new(
            r#"(?i)(['"][a-z0-9_]*(?:pass(?:word|wd)?|secret|token|api_?key|pwd)[a-z0-9_]*['"]\s*=>\s*)'([^'\r\n]+)'"#,
        )
        .expect("regex php_arr_sq válida"),
        php_arr_dq: Regex::new(
            r#"(?i)(['"][a-z0-9_]*(?:pass(?:word|wd)?|secret|token|api_?key|pwd)[a-z0-9_]*['"]\s*=>\s*)"([^"\r\n]+)""#,
        )
        .expect("regex php_arr_dq válida"),
        env_assign: Regex::new(
            r##"(?i)(^|[^$A-Za-z0-9_])([A-Za-z0-9_]*(?:PASSWORD|PASSWD|DB_PASS|SECRET|TOKEN|API_?KEY)\s*=\s*)(?:'([^'\r\n]+)'|"([^"\r\n]+)"|([^\s=;'"#\r\n][^\s;'"#\r\n]*))"##,
        )
        .expect("regex env_assign válida"),
        db_connect_sq: Regex::new(
            r#"(?i)\b((?:mysqli?_connect|new\s+mysqli|new\s+PDO)\s*\([^,;()]+,\s*[^,;()]+,\s*)'([^'\r\n]+)'"#,
        )
        .expect("regex db_connect_sq válida"),
        db_connect_dq: Regex::new(
            r#"(?i)\b((?:mysqli?_connect|new\s+mysqli|new\s+PDO)\s*\([^,;()]+,\s*[^,;()]+,\s*)"([^"\r\n]+)""#,
        )
        .expect("regex db_connect_dq válida"),
        oci_connect_sq: Regex::new(
            r#"(?i)\b(oci_(?:p|new_)?connect\s*\([^,;()]+,\s*)'([^'\r\n]+)'"#,
        )
        .expect("regex oci_connect_sq válida"),
        oci_connect_dq: Regex::new(
            r#"(?i)\b(oci_(?:p|new_)?connect\s*\([^,;()]+,\s*)"([^"\r\n]+)""#,
        )
        .expect("regex oci_connect_dq válida"),
        dsn_pwd: Regex::new(r#"(?i)(;\s*(?:password|pwd)\s*=\s*)([^;\s'"]+)"#)
            .expect("regex dsn_pwd válida"),
        url_creds: Regex::new(r#"(?i)\b([a-z][a-z0-9+.\-]*://[^:/\s'"]+:)([^@\s'"]+)(@)"#)
            .expect("regex url_creds válida"),
    })
}

/// Redacta contraseñas, tokens, claves API y credenciales embebidas antes de enviar contexto a un LLM.
pub fn redact_secrets(input: &str) -> String {
    let p = secret_patterns();

    let out = p.sk_key.replace_all(input, "[REDACTED]");
    let out = p.gsk_key.replace_all(&out, "[REDACTED]");
    let out = p.xai_key.replace_all(&out, "[REDACTED]");
    let out = p.google_key.replace_all(&out, "[REDACTED]");
    let out = p.bearer.replace_all(&out, "${1}[REDACTED]");
    let out = p.php_var_sq.replace_all(&out, "${1}'[REDACTED]'");
    let out = p.php_var_dq.replace_all(&out, "${1}\"[REDACTED]\"");
    let out = p.php_arr_sq.replace_all(&out, "${1}'[REDACTED]'");
    let out = p.php_arr_dq.replace_all(&out, "${1}\"[REDACTED]\"");
    let out = p.env_assign.replace_all(&out, |caps: &Captures<'_>| {
        let lead = &caps[1];
        let key_eq = &caps[2];
        if caps.get(3).is_some() {
            format!("{lead}{key_eq}'[REDACTED]'")
        } else if caps.get(4).is_some() {
            format!("{lead}{key_eq}\"[REDACTED]\"")
        } else {
            format!("{lead}{key_eq}[REDACTED]")
        }
    });
    let out = p.db_connect_sq.replace_all(&out, "${1}'[REDACTED]'");
    let out = p.db_connect_dq.replace_all(&out, "${1}\"[REDACTED]\"");
    let out = p.oci_connect_sq.replace_all(&out, "${1}'[REDACTED]'");
    let out = p.oci_connect_dq.replace_all(&out, "${1}\"[REDACTED]\"");
    let out = p.dsn_pwd.replace_all(&out, "${1}[REDACTED]");
    let out = p.url_creds.replace_all(&out, "${1}[REDACTED]${3}");

    out.into_owned()
}

/// Extrae una ventana de ±15 líneas alrededor del hallazgo, adjunta firmas relacionadas del grafo
/// y aplica sanitización de secretos sobre todo el fragmento resultante.
pub fn build_context_snippet(
    file_content: &str,
    finding: &MigrationFinding,
    related_signatures: &[String],
) -> String {
    let lines: Vec<&str> = file_content.lines().collect();
    let mut buffer = String::new();

    if lines.is_empty() {
        buffer.push_str("// (Archivo vacío)\n");
    } else {
        let start_line = finding.span.start_line.max(1).min(lines.len());
        let end_line = finding.span.end_line.max(start_line).min(lines.len());
        let center_idx = start_line - 1;
        let window_start = center_idx.saturating_sub(15);
        let window_end = (center_idx + 15).min(lines.len() - 1);

        buffer.push_str(&format!(
            "// Archivo: {} (líneas {}-{}, foco {}-{})\n",
            finding.file.display(),
            window_start + 1,
            window_end + 1,
            start_line,
            end_line
        ));

        for (idx, line) in lines
            .iter()
            .enumerate()
            .take(window_end + 1)
            .skip(window_start)
        {
            let line_no = idx + 1;
            let marker = if line_no >= start_line && line_no <= end_line {
                ">"
            } else {
                " "
            };
            buffer.push_str(&format!("{marker} {line_no:>4} | {line}\n"));
        }
    }

    if !related_signatures.is_empty() {
        buffer.push_str("\n// Firmas relacionadas en el grafo de lógica:\n");
        for sig in related_signatures {
            buffer.push_str("// - ");
            buffer.push_str(sig);
            buffer.push('\n');
        }
    }

    redact_secrets(&buffer)
}

/// Consulta al proveedor de IA configurado para resolver un hallazgo de migración y devuelve
/// un `AiResolution` estructurado en JSON usando protocolo compacto para minimizar tokens.
pub async fn ask_ai_for_finding(
    config: &AiConfig,
    finding: &MigrationFinding,
    context_snippet: &str,
) -> Result<AiResolution> {
    let sanitized_snippet = redact_secrets(context_snippet);
    let sanitized_original = redact_secrets(&finding.original_code);

    let system_prompt = concat!(
        "Migrador PHP 7.4->8.5. Preserva la lógica de negocio exacta. ",
        "Responde SOLO JSON válido sin texto extra: ",
        "{\"r\":\"<código PHP reemplazo exacto>\",\"e\":\"<explicación <=12 palabras>\",\"s\":\"<riesgo/nota breve>\"}."
    );

    let user_prompt = format!(
        "Rule:{rule_id}|PHP:{target}|Lines:{start_line}-{end_line}\n\
         Issue:{explanation}\n\
         Original:\n```php\n{original}\n```\n\
         Context:\n```php\n{snippet}\n```",
        rule_id = finding.rule_id,
        target = finding.target_step,
        start_line = finding.span.start_line,
        end_line = finding.span.end_line,
        explanation = finding.explanation,
        original = sanitized_original,
        snippet = sanitized_snippet,
    );

    let raw_text = dispatch_ai_prompt(config, system_prompt, &user_prompt).await?;
    parse_ai_resolution(&raw_text)
}

/// Resuelve hasta múltiples hallazgos del mismo archivo en una sola petición HTTP (lote)
/// compartiendo la ventana fusionada de contexto para ahorrar tokens.
pub async fn ask_ai_batch_for_file(
    config: &AiConfig,
    findings: &[&MigrationFinding],
    merged_context: &str,
) -> Result<Vec<(String, AiResolution)>> {
    if findings.is_empty() {
        return Ok(Vec::new());
    }

    let sanitized_ctx = redact_secrets(merged_context);
    let mut items_list = String::new();
    for f in findings {
        let orig = redact_secrets(f.original_code.trim());
        items_list.push_str(&format!(
            "- id:{}|rule:{}|PHP:{}|L{}: {}\n",
            f.id, f.rule_id, f.target_step, f.span.start_line, orig
        ));
    }

    let system_prompt = concat!(
        "Migrador PHP 7.4->8.5 en lote. Preserva lógica exacta. ",
        "Responde SOLO JSON válido sin texto extra: ",
        "{\"items\":[{\"id\":\"<id>\",\"r\":\"<reemplazo exacto>\",\"e\":\"<=10 palabras\",\"s\":\"<nota>\"}]}."
    );

    let user_prompt = format!(
        "Items:\n{items_list}\nContext:\n```php\n{sanitized_ctx}\n```"
    );

    let raw_text = dispatch_ai_prompt(config, system_prompt, &user_prompt).await?;
    parse_ai_batch_resolutions(&raw_text)
}

async fn dispatch_ai_prompt(
    config: &AiConfig,
    system_prompt: &str,
    user_prompt: &str,
) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .build()
        .context("No se pudo inicializar el cliente HTTP reqwest")?;

    match config.protocol {
        AiProtocol::OpenAiCompatible => {
            call_openai_compatible(&client, config, system_prompt, user_prompt).await
        }
        AiProtocol::GeminiNative => {
            call_gemini_native(&client, config, system_prompt, user_prompt).await
        }
        AiProtocol::AnthropicMessages => {
            call_anthropic_messages(&client, config, system_prompt, user_prompt).await
        }
        AiProtocol::OllamaLocal => {
            call_ollama_local(&client, config, system_prompt, user_prompt).await
        }
    }
}

async fn call_openai_compatible(
    client: &reqwest::Client,
    config: &AiConfig,
    system_prompt: &str,
    user_prompt: &str,
) -> Result<String> {
    let url = format!("{}/chat/completions", config.base_url.trim_end_matches('/'));
    let is_reasoning_model = config.model.starts_with("o1")
        || config.model.starts_with("o3")
        || config.model.starts_with("o4")
        || config.model.contains("reasoner");

    let mut payload = json!({
        "model": config.model,
        "messages": [
            { "role": "system", "content": system_prompt },
            { "role": "user", "content": user_prompt }
        ]
    });
    if !is_reasoning_model {
        payload["temperature"] = json!(0.1);
    }

    let mut req = client.post(&url).json(&payload);
    if let Some(key) = config
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
    {
        req = req.bearer_auth(key);
    }

    let resp = req
        .send()
        .await
        .with_context(|| format!("Fallo de red consultando endpoint OpenAI-compatible ({url})"))?;
    let status = resp.status();
    let body_text = resp
        .text()
        .await
        .context("No se pudo leer el cuerpo de respuesta OpenAI-compatible")?;

    if !status.is_success() {
        anyhow::bail!(
            "Error HTTP {} desde proveedor '{}' ({}): {}",
            status,
            config.provider_id,
            url,
            redact_secrets(&body_text)
        );
    }

    let json_val: Value = serde_json::from_str(&body_text)
        .context("La respuesta OpenAI-compatible no es JSON válido")?;

    let content = &json_val["choices"][0]["message"]["content"];
    if let Some(text) = content.as_str() {
        return Ok(text.to_string());
    }
    if let Some(parts) = content.as_array() {
        let joined: String = parts
            .iter()
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n");
        if !joined.is_empty() {
            return Ok(joined);
        }
    }

    anyhow::bail!("Respuesta OpenAI-compatible sin contenido en choices[0].message.content")
}

async fn call_gemini_native(
    client: &reqwest::Client,
    config: &AiConfig,
    system_prompt: &str,
    user_prompt: &str,
) -> Result<String> {
    let api_key = config
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("El proveedor Google Gemini requiere api_key configurada.")
        })?;

    let url = format!(
        "{}/models/{}:generateContent",
        config.base_url.trim_end_matches('/'),
        config.model.trim()
    );

    let payload = json!({
        "systemInstruction": {
            "parts": [{ "text": system_prompt }]
        },
        "contents": [
            {
                "role": "user",
                "parts": [{ "text": user_prompt }]
            }
        ],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json"
        }
    });

    let resp = client
        .post(&url)
        .query(&[("key", api_key)])
        .json(&payload)
        .send()
        .await
        .with_context(|| format!("Fallo de red consultando Gemini ({url})"))?;

    let status = resp.status();
    let body_text = resp
        .text()
        .await
        .context("No se pudo leer el cuerpo de respuesta de Gemini")?;

    if !status.is_success() {
        anyhow::bail!(
            "Error HTTP {} desde Gemini: {}",
            status,
            redact_secrets(&body_text)
        );
    }

    let json_val: Value =
        serde_json::from_str(&body_text).context("La respuesta de Gemini no es JSON válido")?;

    let parts = json_val["candidates"][0]["content"]["parts"]
        .as_array()
        .ok_or_else(|| {
            anyhow::anyhow!("Respuesta Gemini sin candidates[0].content.parts")
        })?;

    let joined: String = parts
        .iter()
        .filter_map(|part| part.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n");

    if joined.is_empty() {
        anyhow::bail!("Respuesta Gemini sin texto utilizable");
    }

    Ok(joined)
}

async fn call_anthropic_messages(
    client: &reqwest::Client,
    config: &AiConfig,
    system_prompt: &str,
    user_prompt: &str,
) -> Result<String> {
    let api_key = config
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("El proveedor Anthropic Claude requiere api_key configurada.")
        })?;

    let url = format!("{}/messages", config.base_url.trim_end_matches('/'));

    let payload = json!({
        "model": config.model,
        "max_tokens": 2048,
        "system": system_prompt,
        "messages": [
            { "role": "user", "content": user_prompt }
        ],
        "temperature": 0.1
    });

    let resp = client
        .post(&url)
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&payload)
        .send()
        .await
        .with_context(|| format!("Fallo de red consultando Anthropic ({url})"))?;

    let status = resp.status();
    let body_text = resp
        .text()
        .await
        .context("No se pudo leer el cuerpo de respuesta de Anthropic")?;

    if !status.is_success() {
        anyhow::bail!(
            "Error HTTP {} desde Anthropic: {}",
            status,
            redact_secrets(&body_text)
        );
    }

    let json_val: Value =
        serde_json::from_str(&body_text).context("La respuesta de Anthropic no es JSON válido")?;

    let blocks = json_val["content"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Respuesta Anthropic sin arreglo content"))?;

    let joined: String = blocks
        .iter()
        .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|b| b.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n");

    if joined.is_empty() {
        anyhow::bail!("Respuesta Anthropic sin bloques de texto");
    }

    Ok(joined)
}

async fn call_ollama_local(
    client: &reqwest::Client,
    config: &AiConfig,
    system_prompt: &str,
    user_prompt: &str,
) -> Result<String> {
    let url = format!("{}/api/chat", config.base_url.trim_end_matches('/'));

    let payload = json!({
        "model": config.model,
        "stream": false,
        "format": "json",
        "messages": [
            { "role": "system", "content": system_prompt },
            { "role": "user", "content": user_prompt }
        ]
    });

    let mut req = client.post(&url).json(&payload);
    if let Some(key) = config
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
    {
        req = req.bearer_auth(key);
    }

    let resp = req
        .send()
        .await
        .with_context(|| format!("Fallo de red consultando Ollama local ({url})"))?;

    let status = resp.status();
    let body_text = resp
        .text()
        .await
        .context("No se pudo leer el cuerpo de respuesta de Ollama")?;

    if !status.is_success() {
        anyhow::bail!(
            "Error HTTP {} desde Ollama: {}",
            status,
            redact_secrets(&body_text)
        );
    }

    let json_val: Value =
        serde_json::from_str(&body_text).context("La respuesta de Ollama no es JSON válido")?;

    let text = json_val["message"]["content"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Respuesta Ollama sin message.content"))?;

    Ok(text.to_string())
}

fn strip_markdown_code_fences(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let start_fence = trimmed.find("```")?;
    let after_open = &trimmed[start_fence + 3..];
    let body_start = after_open.find('\n').map(|idx| idx + 1).unwrap_or(0);
    let rest = &after_open[body_start..];
    let end_fence = rest.rfind("```")?;
    Some(rest[..end_fence].trim().to_string())
}

fn parse_resolution_from_value(val: &Value) -> Option<AiResolution> {
    let replacement_code = val
        .get("replacement_code")
        .or_else(|| val.get("r"))?
        .as_str()?
        .to_string();
    let explanation = val
        .get("explanation")
        .or_else(|| val.get("e"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let logic_safety_notes = val
        .get("logic_safety_notes")
        .or_else(|| val.get("s"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    Some(AiResolution {
        replacement_code,
        explanation,
        logic_safety_notes,
    })
}

fn parse_resolution_candidate(candidate: &str) -> Option<AiResolution> {
    if let Ok(res) = serde_json::from_str::<AiResolution>(candidate) {
        return Some(res);
    }

    let val: Value = serde_json::from_str(candidate).ok()?;
    parse_resolution_from_value(&val)
}

fn parse_batch_candidate(candidate: &str) -> Option<Vec<(String, AiResolution)>> {
    let val: Value = serde_json::from_str(candidate).ok()?;
    let arr = if let Some(items) = val.get("items").and_then(Value::as_array) {
        items
    } else if let Some(direct) = val.as_array() {
        direct
    } else {
        return None;
    };

    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        if let Some(res) = parse_resolution_from_value(entry) {
            out.push((id.to_string(), res));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn parse_ai_batch_resolutions(raw_text: &str) -> Result<Vec<(String, AiResolution)>> {
    let trimmed = raw_text.trim();
    if let Some(res) = parse_batch_candidate(trimmed) {
        return Ok(res);
    }
    if let Some(unfenced) = strip_markdown_code_fences(trimmed) {
        if let Some(res) = parse_batch_candidate(&unfenced) {
            return Ok(res);
        }
        if let (Some(start), Some(end)) = (unfenced.find('{'), unfenced.rfind('}')) {
            if start < end {
                if let Some(res) = parse_batch_candidate(&unfenced[start..=end]) {
                    return Ok(res);
                }
            }
        }
    }
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if start < end {
            if let Some(res) = parse_batch_candidate(&trimmed[start..=end]) {
                return Ok(res);
            }
        }
    }
    if let (Some(start), Some(end)) = (trimmed.find('['), trimmed.rfind(']')) {
        if start < end {
            if let Some(res) = parse_batch_candidate(&trimmed[start..=end]) {
                return Ok(res);
            }
        }
    }
    anyhow::bail!("No se pudo extraer JSON de lote válido desde la respuesta de la IA.")
}

fn parse_ai_resolution(raw_text: &str) -> Result<AiResolution> {
    let trimmed = raw_text.trim();

    if let Some(res) = parse_resolution_candidate(trimmed) {
        return Ok(res);
    }

    if let Some(unfenced) = strip_markdown_code_fences(trimmed) {
        if let Some(res) = parse_resolution_candidate(&unfenced) {
            return Ok(res);
        }
        if let (Some(start), Some(end)) = (unfenced.find('{'), unfenced.rfind('}')) {
            if start < end {
                if let Some(res) = parse_resolution_candidate(&unfenced[start..=end]) {
                    return Ok(res);
                }
            }
        }
    }

    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if start < end {
            if let Some(res) = parse_resolution_candidate(&trimmed[start..=end]) {
                return Ok(res);
            }
        }
    }

    anyhow::bail!(
        "No se pudo extraer un JSON válido de AiResolution desde la respuesta de la IA."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        DecisionBucket, PhpVersion, ResolutionStatus, RuleCategory, Span,
    };
    use std::path::PathBuf;

    #[test]
    fn redacts_keys_tokens_and_passwords() {
        let input = r#"
            $api = 'sk-1234567890abcdef';
            $g = "AIzaSyDaGmWKa4JsXZ1234567890";
            // Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig
            $password = 'superSecret123';
            $pass = "otraClave!";
            DB_PASSWORD=db_secret_pass
            $conn = mysqli_connect('localhost', 'root', 'myDbSecret', 'app');
        "#;
        let out = redact_secrets(input);
        assert!(!out.contains("sk-1234567890abcdef"));
        assert!(!out.contains("AIzaSyDaGmWKa4JsXZ1234567890"));
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(!out.contains("superSecret123"));
        assert!(!out.contains("otraClave!"));
        assert!(!out.contains("db_secret_pass"));
        assert!(!out.contains("myDbSecret"));
        assert!(out.contains("[REDACTED]"));
        assert!(out.contains("mysqli_connect('localhost', 'root', '[REDACTED]', 'app')"));
    }

    #[test]
    fn builds_redacted_context_snippet_with_signatures() {
        let mut lines = Vec::new();
        for i in 1..=40 {
            if i == 20 {
                lines.push("$password = 'secret123';".to_string());
            } else {
                lines.push(format!("$line_{i} = {i};"));
            }
        }
        let content = lines.join("\n");
        let finding = MigrationFinding {
            id: "f1".to_string(),
            rule_id: "R001".to_string(),
            target_step: PhpVersion::Php85,
            bucket: DecisionBucket::YellowNeedsDecision,
            category: RuleCategory::TypeSafety,
            file: PathBuf::from("src/auth.php"),
            span: Span {
                start_byte: 0,
                end_byte: 10,
                start_line: 20,
                start_col: 1,
                end_line: 20,
                end_col: 10,
            },
            original_code: "$password = 'secret123';".to_string(),
            suggested_replacement: None,
            explanation: "Revisar tipos".to_string(),
            logic_impact: "Autenticación".to_string(),
            status: ResolutionStatus::Pending,
        };
        let snippet = build_context_snippet(&content, &finding, &["function login(string $u): bool".to_string()]);
        assert!(!snippet.contains("secret123"));
        assert!(snippet.contains("[REDACTED]"));
        assert!(snippet.contains("function login(string $u): bool"));
        assert!(snippet.contains("  5 |"));
        assert!(snippet.contains(" 35 |"));
    }

    #[test]
    fn parses_fenced_and_raw_ai_json() {
        let fenced = "Aquí tienes el resultado:\n```json\n{\n  \"replacement_code\": \"str_contains($a, $b)\",\n  \"explanation\": \"Reemplazo seguro\",\n  \"logic_safety_notes\": \"Verifica tipos string\"\n}\n```\n";
        let parsed = parse_ai_resolution(fenced).expect("debe parsear bloque fenced");
        assert_eq!(parsed.replacement_code, "str_contains($a, $b)");
        assert_eq!(parsed.explanation, "Reemplazo seguro");

        let compact = r#"{"r":"[key($a), current($a)]","e":"Reemplazo each()","s":"Verificar reset previo"}"#;
        let parsed_compact = parse_ai_resolution(compact).expect("debe parsear claves cortas");
        assert_eq!(parsed_compact.replacement_code, "[key($a), current($a)]");
        assert_eq!(parsed_compact.explanation, "Reemplazo each()");

        let batch = r#"{"items":[{"id":"M1","r":"(int)$x","e":"Cast canónico","s":""}]}"#;
        let parsed_batch = parse_ai_batch_resolutions(batch).expect("debe parsear lote");
        assert_eq!(parsed_batch.len(), 1);
        assert_eq!(parsed_batch[0].0, "M1");
        assert_eq!(parsed_batch[0].1.replacement_code, "(int)$x");
    }
}
