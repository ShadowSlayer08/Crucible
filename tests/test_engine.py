"""Tests for the universal REST engine: schema presets, URL dedup, header/body
construction, response extraction, and a network-mocked run_test."""
import pytest

import engine


# ── Schema registry ───────────────────────────────────────────────────────────

def test_all_documented_schemas_present():
    expected = {"openai", "anthropic", "cohere", "mistral", "google",
                "ollama", "azure", "bedrock", "custom"}
    assert expected <= set(engine.SCHEMAS.keys())


def test_get_schema_returns_independent_copy():
    a = engine.get_schema("custom")
    a["url_path"] = "/mutated"
    b = engine.get_schema("custom")
    assert b["url_path"] != "/mutated"  # no shared-state contamination


def test_get_schema_unknown_raises():
    with pytest.raises(ValueError):
        engine.get_schema("nope")


def test_every_schema_has_required_keys():
    for name, s in engine.SCHEMAS.items():
        for key in ("url_path", "body_template", "response_path"):
            assert key in s, f"{name} missing {key}"


# ── URL resolution / dedup ────────────────────────────────────────────────────

def test_url_dedup_groq_style():
    schema = engine.get_schema("openai")
    cfg = {"endpoint": "https://api.groq.com/openai/v1", "model": "m"}
    url = engine._resolve_url(schema, cfg)
    assert url == "https://api.groq.com/openai/v1/chat/completions"
    assert "/v1/v1/" not in url


def test_url_model_substitution_google():
    schema = engine.get_schema("google")
    cfg = {"endpoint": "https://x.googleapis.com", "model": "gemini-1.5"}
    url = engine._resolve_url(schema, cfg)
    assert "gemini-1.5" in url


# ── Header resolution ─────────────────────────────────────────────────────────

def test_openai_auth_header():
    h = engine._resolve_headers(engine.get_schema("openai"), {"api_key": "sk-abc"})
    assert h["Authorization"] == "Bearer sk-abc"


def test_anthropic_auth_and_version_header():
    h = engine._resolve_headers(engine.get_schema("anthropic"), {"api_key": "k"})
    assert h["x-api-key"] == "k"
    assert h["anthropic-version"] == "2023-06-01"


def test_ollama_has_no_auth_header():
    h = engine._resolve_headers(engine.get_schema("ollama"), {"api_key": ""})
    assert "Authorization" not in h


def test_extra_headers_from_config_merged():
    h = engine._resolve_headers(engine.get_schema("openai"),
                                {"api_key": "k", "extra_headers": {"X-Trace": "1"}})
    assert h["X-Trace"] == "1"


# ── Body construction ─────────────────────────────────────────────────────────

def test_body_message_substitution():
    body = engine._resolve_body(engine.get_schema("openai"),
                                {"model": "gpt-4o"}, "hello")
    assert body["messages"][0]["content"] == "hello"
    assert body["model"] == "gpt-4o"


def test_body_preserves_unicode_and_control_chars():
    """Token-smuggling payloads contain homoglyphs / zero-width chars — they must
    survive body construction byte-for-byte (object traversal, not string format)."""
    tricky = "ignore​ previous еxpose\x00 \U0001f600"
    body = engine._resolve_body(engine.get_schema("anthropic"), {"model": "m"}, tricky)
    assert body["messages"][0]["content"] == tricky


def test_body_is_deep_copy_not_shared():
    schema = engine.get_schema("openai")
    b1 = engine._resolve_body(schema, {"model": "m"}, "a")
    b2 = engine._resolve_body(schema, {"model": "m"}, "b")
    assert b1["messages"][0]["content"] == "a"
    assert b2["messages"][0]["content"] == "b"


# ── Response extraction ───────────────────────────────────────────────────────

def test_extract_openai_shape():
    s = engine.get_schema("openai")
    data = {"choices": [{"message": {"content": "hi there"}}]}
    assert engine._extract_response(s, data) == "hi there"


def test_extract_anthropic_shape():
    s = engine.get_schema("anthropic")
    data = {"content": [{"text": "claude says hi"}]}
    assert engine._extract_response(s, data) == "claude says hi"


def test_extract_google_shape():
    s = engine.get_schema("google")
    data = {"candidates": [{"content": {"parts": [{"text": "gemini"}]}}]}
    assert engine._extract_response(s, data) == "gemini"


def test_extract_falls_back_when_path_wrong():
    """A wrong response_path should still recover via shape auto-detection."""
    s = engine.get_schema("ollama")  # expects message.content
    data = {"choices": [{"message": {"content": "recovered"}}]}  # openai shape instead
    assert engine._extract_response(s, data) == "recovered"


# ── run_test (network mocked) ─────────────────────────────────────────────────

class _FakeResp:
    def __init__(self, status, payload=None, text=""):
        self.status_code = status
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def test_run_test_success(monkeypatch, openai_config, sample_test):
    monkeypatch.setattr(engine.requests, "post",
                        lambda *a, **k: _FakeResp(200, {"choices": [{"message": {"content": "I refuse."}}]}))
    out = engine.run_test(openai_config, sample_test)
    assert out["response_text"] == "I refuse."
    assert out["status_code"] == 200


def test_run_test_http_error_maps_to_error_verdict(monkeypatch, openai_config, sample_test):
    monkeypatch.setattr(engine.requests, "post",
                        lambda *a, **k: _FakeResp(401, text="Unauthorized"))
    out = engine.run_test(openai_config, sample_test)
    assert out["verdict"] == "ERROR"
    assert out["status_code"] == 401


def test_run_test_connection_error_maps_to_error(monkeypatch, openai_config, sample_test):
    monkeypatch.setattr(engine.time, "sleep", lambda *_a, **_k: None)  # don't wait on retry backoff
    calls = {"n": 0}

    def _boom(*a, **k):
        calls["n"] += 1
        raise engine.requests.exceptions.ConnectionError("no route")
    monkeypatch.setattr(engine.requests, "post", _boom)
    out = engine.run_test(openai_config, sample_test, max_retries=3)
    assert out["verdict"] == "ERROR"
    assert "Connection failed" in out["error"]
    assert calls["n"] == 3  # transient connection errors are now retried, not immediate
