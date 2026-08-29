"""
Universal Test Execution Engine
Supports any AI REST API via built-in schema presets or fully custom configuration.

Built-in presets:
  openai       → OpenAI, Azure OpenAI, Groq, Together AI, Fireworks, Perplexity,
                  Anyscale, DeepInfra, OpenRouter, LM Studio, LocalAI, vLLM, Ollama (v2 compat)
  anthropic    → Anthropic Claude (Messages API)
  cohere       → Cohere Chat API
  mistral      → Mistral AI
  google       → Google Gemini (generateContent)
  ollama       → Ollama native REST (/api/chat)
  azure        → Azure OpenAI
  bedrock      → AWS Bedrock (Claude)
  custom       → You supply url_path, headers_template, body_template, response_path
"""

import time
import json
import copy
import requests


# ─────────────────────────────────────────────────────────────────────────────
# SCHEMA REGISTRY
# ─────────────────────────────────────────────────────────────────────────────
SCHEMAS = {

    "openai": {
        "url_path":      "/v1/chat/completions",
        "auth_header":   "Authorization: Bearer {api_key}",
        "extra_headers": {},
        "body_template": {
            "model":       "{model}",
            "messages":    [{"role": "user", "content": "{message}"}],
            "max_tokens":  1024,
            "temperature": 0.7,
        },
        "response_path": "choices.0.message.content",
        "notes": "OpenAI (https://api.openai.com), Groq (https://api.groq.com/openai/v1 OR https://api.groq.com), Together AI, Fireworks, Perplexity, OpenRouter, Anyscale, DeepInfra, LM Studio, LocalAI, vLLM",
    },

    "anthropic": {
        "url_path":      "/v1/messages",
        "auth_header":   "x-api-key: {api_key}",
        "extra_headers": {"anthropic-version": "2023-06-01"},
        "body_template": {
            "model":      "{model}",
            "max_tokens": 1024,
            "messages":   [{"role": "user", "content": "{message}"}],
        },
        "response_path": "content.0.text",
        "notes": "Anthropic Claude (claude-3-5-sonnet-20241022, claude-opus-4-0, etc.)",
    },

    "cohere": {
        "url_path":      "/v2/chat",
        "auth_header":   "Authorization: Bearer {api_key}",
        "extra_headers": {},
        "body_template": {
            "model":    "{model}",
            "messages": [{"role": "user", "content": "{message}"}],
        },
        "response_path": "message.content.0.text",
        "notes": "Cohere Command R / R+ (command-r-plus, command-r-08-2024)",
    },

    "mistral": {
        "url_path":      "/v1/chat/completions",
        "auth_header":   "Authorization: Bearer {api_key}",
        "extra_headers": {},
        "body_template": {
            "model":       "{model}",
            "messages":    [{"role": "user", "content": "{message}"}],
            "max_tokens":  1024,
            "temperature": 0.7,
        },
        "response_path": "choices.0.message.content",
        "notes": "Mistral AI (mistral-large-latest, mistral-medium, codestral, etc.)",
    },

    "google": {
        "url_path":      "/v1beta/models/{model}:generateContent",
        "auth_header":   "x-goog-api-key: {api_key}",
        "extra_headers": {},
        "body_template": {
            "contents": [{"parts": [{"text": "{message}"}]}]
        },
        "response_path": "candidates.0.content.parts.0.text",
        "notes": "Google Gemini — endpoint: https://generativelanguage.googleapis.com",
    },

    "ollama": {
        "url_path":      "/api/chat",
        "auth_header":   None,
        "extra_headers": {},
        "body_template": {
            "model":    "{model}",
            "messages": [{"role": "user", "content": "{message}"}],
            "stream":   False,
        },
        "response_path": "message.content",
        "notes": "Ollama local — endpoint: http://localhost:11434 (no API key needed)",
    },

    "azure": {
        "url_path":      "/openai/deployments/{model}/chat/completions?api-version=2024-02-01",
        "auth_header":   "api-key: {api_key}",
        "extra_headers": {},
        "body_template": {
            "messages":    [{"role": "user", "content": "{message}"}],
            "max_tokens":  1024,
            "temperature": 0.7,
        },
        "response_path": "choices.0.message.content",
        "notes": "Azure OpenAI — endpoint: https://<your-resource>.openai.azure.com",
    },

    "bedrock": {
        "url_path":      "/model/{model}/invoke",
        "auth_header":   None,
        "extra_headers": {"content-type": "application/json"},
        "body_template": {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens":        1024,
            "messages":          [{"role": "user", "content": "{message}"}],
        },
        "response_path": "content.0.text",
        "notes": "AWS Bedrock Claude — use AWS env credentials, endpoint: https://bedrock-runtime.<region>.amazonaws.com",
    },

    "custom": {
        "url_path":      "/v1/chat/completions",
        "auth_header":   "Authorization: Bearer {api_key}",
        "extra_headers": {},
        "body_template": {
            "model":    "{model}",
            "messages": [{"role": "user", "content": "{message}"}],
        },
        "response_path": "choices.0.message.content",
        "notes": "Fully custom. Override any field via --custom-* flags",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def get_schema(name: str) -> dict:
    schema = SCHEMAS.get(name)
    if not schema:
        supported = ", ".join(SCHEMAS.keys())
        raise ValueError(f"Unknown schema '{name}'. Supported: {supported}")
    return copy.deepcopy(schema)


def list_schemas() -> str:
    lines = ["\n  Supported --schema values:\n"]
    for name, s in SCHEMAS.items():
        lines.append(f"  {name:<12} — {s['notes']}")
    return "\n".join(lines) + "\n"


def _deduplicate_path(endpoint_path: str, schema_path: str) -> str:
    """
    Remove overlapping path segments between endpoint and schema path.
    Fixes e.g. Groq endpoint https://api.groq.com/openai/v1 + schema /v1/chat/completions
    → /chat/completions  (not /v1/v1/chat/completions)
    """
    ep_segs = [s for s in endpoint_path.split("/") if s]
    sp_segs = [s for s in schema_path.split("/") if s]
    for overlap in range(min(len(ep_segs), len(sp_segs)), 0, -1):
        if ep_segs[-overlap:] == sp_segs[:overlap]:
            remaining = sp_segs[overlap:]
            return "/" + "/".join(remaining) if remaining else ""
    return schema_path


def _resolve_url(schema: dict, config: dict) -> str:
    from urllib.parse import urlparse
    endpoint   = config["endpoint"].rstrip("/")
    model      = config.get("model", "")
    path       = schema["url_path"].replace("{model}", model)
    ep_path    = urlparse(endpoint).path.rstrip("/")
    clean_path = _deduplicate_path(ep_path, path)
    return endpoint + clean_path


def _resolve_headers(schema: dict, config: dict) -> dict:
    headers = {"Content-Type": "application/json"}
    auth = schema.get("auth_header")
    if auth:
        key, _, value = auth.partition(": ")
        headers[key] = value.replace("{api_key}", config.get("api_key", ""))
    for k, v in schema.get("extra_headers", {}).items():
        headers[k] = v
    for k, v in config.get("extra_headers", {}).items():
        headers[k] = v
    return headers


def _resolve_body(schema: dict, config: dict, message: str) -> dict:
    """
    Build request body by walking the template as a Python object.
    Uses proper object traversal instead of string substitution —
    handles all Unicode, control characters, zero-width chars, null bytes, etc.
    """
    template = schema["body_template"]
    if isinstance(template, str):
        try:
            template = json.loads(template)
        except Exception:
            template = {}

    model = config.get("model", "")

    def _walk(obj):
        if isinstance(obj, str):
            if obj == "{message}": return message
            if obj == "{model}":   return model
            # replace inline placeholders (e.g. url_path uses {model})
            return obj.replace("{model}", model).replace("{message}", message)
        if isinstance(obj, dict):
            return {k: _walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(item) for item in obj]
        return obj

    return _walk(copy.deepcopy(template))


def _extract_response(schema: dict, response_json: dict) -> str:
    """Walk dot-notation path e.g. 'choices.0.message.content' through the response."""
    path = schema.get("response_path", "")
    current = response_json
    try:
        for key in path.split("."):
            if isinstance(current, list):
                current = current[int(key)]
            elif isinstance(current, dict):
                current = current[key]
            else:
                return str(current)
        return str(current) if current is not None else ""
    except (KeyError, IndexError, TypeError, ValueError):
        # Auto-detect common response shapes
        for extractor in [
            lambda r: r["choices"][0]["message"]["content"],
            lambda r: r["content"][0]["text"],
            lambda r: r["message"]["content"],
            lambda r: r["candidates"][0]["content"]["parts"][0]["text"],
            lambda r: r["text"],
            lambda r: r["response"],
            lambda r: r["output"],
            lambda r: str(r),
        ]:
            try:
                return extractor(response_json)
            except Exception:
                continue
    return str(response_json)


# ─────────────────────────────────────────────────────────────────────────────
# CORE
# ─────────────────────────────────────────────────────────────────────────────

def run_test(config: dict, test: dict, max_retries: int = 3,
             image_b64: str = None) -> dict:
    schema_name = config.get("schema", "openai")
    schema = get_schema(schema_name)

    # Apply custom overrides
    if schema_name == "custom":
        if config.get("custom_url_path"):
            schema["url_path"] = config["custom_url_path"]
        if config.get("custom_auth_header"):
            schema["auth_header"] = config["custom_auth_header"]
        if config.get("custom_body"):
            schema["body_template"] = config["custom_body"]
        if config.get("custom_response_path"):
            schema["response_path"] = config["custom_response_path"]

    message = test.get("payload", "").strip() or " "
    url     = _resolve_url(schema, config)
    headers = _resolve_headers(schema, config)
    body    = _resolve_body(schema, config, message)

    # ── Multimodal: replace the text content with a provider-correct image block ──
    if image_b64:
        try:
            import multimodal
            content = multimodal.build_image_message(schema_name, message, image_b64)
            if isinstance(body.get("messages"), list) and body["messages"]:
                body["messages"][0]["content"] = content
        except Exception:
            pass  # unsupported schema / bad image → fall back to text-only body

    attempt = 0
    while attempt < max_retries:
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=30)

            if resp.status_code == 429:
                time.sleep(2 ** (attempt + 1))
                attempt += 1
                continue

            if resp.status_code >= 400:
                return {
                    "verdict":       "ERROR",
                    "status_code":   resp.status_code,
                    "error":         f"HTTP {resp.status_code}: {resp.text[:300]}",
                    "response_text": "",
                }

            data = resp.json()
            response_text = _extract_response(schema, data)[:4096]
            return {
                "verdict":       None,
                "status_code":   resp.status_code,
                "response_text": response_text,
                "raw_response":  data,
                "error":         None,
            }

        except requests.exceptions.Timeout:
            attempt += 1
            if attempt >= max_retries:
                return {"verdict": "ERROR", "error": "Timed out after retries", "response_text": ""}
            time.sleep(2 ** attempt)

        except requests.exceptions.ConnectionError as e:
            return {"verdict": "ERROR", "error": f"Connection failed: {str(e)[:150]}", "response_text": ""}

        except Exception as e:
            return {"verdict": "ERROR", "error": str(e)[:200], "response_text": ""}

    return {"verdict": "ERROR", "error": "Max retries exceeded", "response_text": ""}


def test_connection(config: dict) -> tuple[bool, str]:
    probe  = {"payload": "Reply with exactly one word: pong", "expected": "safe_response"}
    result = run_test(config, probe, max_retries=1)
    if result.get("verdict") == "ERROR":
        return False, result.get("error", "Unknown error")
    text = result.get("response_text", "").strip()
    if text:
        return True, f"Connected — model replied: \"{text[:80]}\""
    return False, "API returned an empty response"
