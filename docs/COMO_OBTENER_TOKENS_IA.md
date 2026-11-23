# Cómo obtener tu Token (API Key) de IA para `php-migrator`

`php-migrator` funciona bajo el modelo **BYOK (Bring Your Own Key)**: tú proporcionas tu propia clave API o usas un modelo local en tu equipo, sin intermediarios. Tu token **nunca se guarda en texto plano** en el proyecto; puedes ingresarlo de forma oculta cuando el asistente lo solicite o exportarlo como variable de entorno.

---

## [gemini] Google Gemini
- **Panel oficial:** https://aistudio.google.com/app/apikey
- **Variable de entorno:** `GEMINI_API_KEY`
- **Formato esperado del token:** `AIza...`
- **Capa gratuita / créditos:** Sí, Google AI Studio ofrece capa gratuita con límites por minuto y opción de pago por uso.
- **Pasos:**
  1. Inicia sesión con tu cuenta de Google en **Google AI Studio** (`https://aistudio.google.com/app/apikey`).
  2. Haz clic en **"Get API key"** → **"Create API key"**.
  3. Selecciona o crea un proyecto de Google Cloud y copia la clave generada (`AIza...`).
  4. Pégala en la consola cuando `php-migrator` te la pida o ejecútala en PowerShell antes: `$env:GEMINI_API_KEY = "AIza..."`.

## [openai] OpenAI
- **Panel oficial:** https://platform.openai.com/api-keys
- **Variable de entorno:** `OPENAI_API_KEY`
- **Formato esperado del token:** `sk-proj-...` o `sk-...`
- **Capa gratuita / créditos:** Requiere saldo/facturación activa en OpenAI Platform (independiente de ChatGPT Plus).
- **Pasos:**
  1. Entra a **OpenAI Platform** (`https://platform.openai.com/api-keys`).
  2. Haz clic en **"Create new secret key"**, asígnale un nombre (ej. `php-migrator`).
  3. Copia el token inmediatamente (`sk-proj-...`), ya que no volverá a mostrarse.
  4. Ingrésalo en el asistente o exporta `$env:OPENAI_API_KEY = "sk-proj-..."`.

## [anthropic] Anthropic Claude
- **Panel oficial:** https://console.anthropic.com/settings/keys
- **Variable de entorno:** `ANTHROPIC_API_KEY`
- **Formato esperado del token:** `sk-ant-...`
- **Capa gratuita / créditos:** Requiere saldo/créditos de API en Anthropic Console (separado de la suscripción web Claude Pro).
- **Pasos:**
  1. Accede a **Anthropic Console** (`https://console.anthropic.com/settings/keys`).
  2. Haz clic en **"Create Key"**, elige tu Workspace y dale un nombre.
  3. Copia la clave generada (`sk-ant-...`).
  4. Ingrésala en el asistente o exporta `$env:ANTHROPIC_API_KEY = "sk-ant-..."`.

## [deepseek] DeepSeek
- **Panel oficial:** https://platform.deepseek.com/api_keys
- **Variable de entorno:** `DEEPSEEK_API_KEY`
- **Formato esperado del token:** `sk-...`
- **Capa gratuita / créditos:** Muy económico; suele otorgar créditos de prueba al registrarse o recargas desde montos bajos.
- **Pasos:**
  1. Inicia sesión en **DeepSeek Platform** (`https://platform.deepseek.com/api_keys`).
  2. Haz clic en **"Create new API key"**.
  3. Copia el token (`sk-...`).
  4. Ingrésalo en el asistente o exporta `$env:DEEPSEEK_API_KEY = "sk-..."`.

## [openrouter] OpenRouter (Multi-modelo)
- **Panel oficial:** https://openrouter.ai/keys
- **Variable de entorno:** `OPENROUTER_API_KEY`
- **Formato esperado del token:** `sk-or-v1-...`
- **Capa gratuita / créditos:** Sí, ofrece modelos gratuitos (`:free`) y acceso unificado a Claude, Gemini, GPT, Llama y Qwen con un solo token.
- **Pasos:**
  1. Entra a **OpenRouter Keys** (`https://openrouter.ai/keys`).
  2. Haz clic en **"Create Key"**, define un nombre y opcionalmente un límite de crédito.
  3. Copia el token (`sk-or-v1-...`).
  4. Ingrésalo en el asistente o exporta `$env:OPENROUTER_API_KEY = "sk-or-v1-..."`.

## [groq] Groq
- **Panel oficial:** https://console.groq.com/keys
- **Variable de entorno:** `GROQ_API_KEY`
- **Formato esperado del token:** `gsk_...`
- **Capa gratuita / créditos:** Sí, cuenta con capa gratuita rápida para inferencia de modelos abiertos (Llama, Qwen).
- **Pasos:**
  1. Inicia sesión en **GroqCloud Console** (`https://console.groq.com/keys`).
  2. Haz clic en **"Create API Key"**.
  3. Copia la clave (`gsk_...`).
  4. Ingrésala en el asistente o exporta `$env:GROQ_API_KEY = "gsk_..."`.

## [xai] xAI Grok
- **Panel oficial:** https://console.x.ai/
- **Variable de entorno:** `XAI_API_KEY`
- **Formato esperado del token:** `xai-...`
- **Capa gratuita / créditos:** Requiere cuenta con facturación/créditos en xAI Console.
- **Pasos:**
  1. Ingresa a **xAI Console** (`https://console.x.ai/`).
  2. Ve a la sección **API Keys** y crea una nueva clave.
  3. Copia el token (`xai-...`).
  4. Ingrésalo en el asistente o exporta `$env:XAI_API_KEY = "xai-..."`.

## [ollama] Ollama Local (100% Privado, Sin Token)
- **Descarga oficial:** https://ollama.com/download
- **Variable de entorno:** No requiere token
- **Formato esperado del token:** Ninguno (se conecta a `http://localhost:11434`)
- **Capa gratuita / créditos:** 100% gratuito y local: tu código PHP nunca sale de tu computadora.
- **Pasos:**
  1. Instala Ollama desde `https://ollama.com/download`.
  2. Descarga un modelo enfocado en código ejecutando en terminal: `ollama pull qwen2.5-coder:14b` (o `ollama pull llama3.2`).
  3. Asegúrate de que el servicio de Ollama esté activo (`ollama serve` o icono en bandeja de Windows).
  4. Elige `ollama` en `php-migrator` y no necesitarás ingresar ningún token.

## [custom] Endpoint Custom (Compatible con OpenAI)
- **URL base configurable:** Ej. `http://localhost:1234/v1` (LM Studio), `http://localhost:8000/v1` (vLLM) o LiteLLM / Azure OpenAI.
- **Variable de entorno:** `CUSTOM_AI_API_KEY` (opcional si tu servidor local no pide autenticación)
- **Pasos:**
  1. Levanta tu servidor compatible con `/v1/chat/completions` (LM Studio, vLLM, LiteLLM, etc.).
  2. Anota la URL base terminando en `/v1`, el nombre exacto del modelo cargado y el token si aplica.
  3. Selecciona `custom` en el catálogo e introduce esos valores cuando el asistente los solicite.
