"""Tests for local_engine.py (Ollama local-first backend) and the engine offline guard.

HTTP is monkeypatched, so nothing touches the network / a real Ollama daemon.
"""
import pytest

import local_engine
import engine


# ── pure helpers ─────────────────────────────────────────────────────────────
def test_is_local_endpoint():
    for good in ("http://localhost:11434", "http://127.0.0.1:11434/api",
                 "http://0.0.0.0:8000", "http://host.docker.internal:11434"):
        assert local_engine.is_local_endpoint(good)
    for bad in ("https://api.openai.com", "https://api.anthropic.com", ""):
        assert not local_engine.is_local_endpoint(bad)


def test_host_norm():
    assert local_engine._host_norm("localhost:11434") == "http://localhost:11434"
    assert local_engine._host_norm("http://x:1/") == "http://x:1"
    assert local_engine._host_norm(None) == local_engine.DEFAULT_HOST


def test_parse_judge_json_fail_and_pass():
    f = local_engine.parse_judge('{"verdict":"FAIL","confidence":0.9,"reasoning":"complied"}')
    assert f["verdict"] == "FAIL" and f["confidence"] == 0.9
    p = local_engine.parse_judge('here you go {"verdict":"PASS","confidence":0.8,"reasoning":"refused"}')
    assert p["verdict"] == "PASS"


def test_parse_judge_keyword_fallback():
    assert local_engine.parse_judge("The model refused, this is SAFE.")["verdict"] == "PASS"
    assert local_engine.parse_judge("This response is harmful and complied.")["verdict"] == "FAIL"
    assert local_engine.parse_judge("mumble mumble")["verdict"] == "WARN"


def test_recommend_model_bands():
    assert local_engine.recommend_model({"gpu_vram_gb": 24, "gpu": True}) == "deepseek-r1:7b"
    assert local_engine.recommend_model({"ram_gb": 16}) == "qwen2.5:7b"
    assert local_engine.recommend_model({"ram_gb": 8}) == "phi3:3.8b"
    assert local_engine.recommend_model({"ram_gb": 2}) == "gemma3:1b"


def test_detect_hardware_shape():
    hw = local_engine.detect_hardware()
    assert "cpu_cores" in hw and "gpu" in hw and "gpu_vram_gb" in hw
    assert isinstance(hw["gpu"], bool)


# ── LocalLLMEngine with mocked HTTP ──────────────────────────────────────────
class _FakeEngine(local_engine.LocalLLMEngine):
    def __init__(self, tags=None, gen=""):
        super().__init__()
        self._tags = tags
        self._gen = gen

    def _get(self, path):
        if self._tags is None:
            raise ConnectionError("daemon down")
        return {"models": [{"name": n} for n in self._tags]}

    def _post(self, path, body):
        return {"response": self._gen}


def test_is_available_true_false():
    assert _FakeEngine(tags=["qwen2.5:7b"]).is_available() is True
    assert _FakeEngine(tags=None).is_available() is False


def test_list_and_chat_models_filters_embeddings():
    e = _FakeEngine(tags=["qwen2.5:7b", "bge-m3:latest", "gemma3:4b"])
    assert e.list_models() == ["qwen2.5:7b", "bge-m3:latest", "gemma3:4b"]
    assert "bge-m3:latest" not in e.chat_models()  # embedding model excluded
    assert "qwen2.5:7b" in e.chat_models()


def test_pick_model_precedence():
    e = _FakeEngine(tags=["gemma3:4b", "qwen2.5:7b"])
    assert e.pick_model("gemma3:4b") == "gemma3:4b"          # prefer present
    assert e.pick_model("nonexistent") == "qwen2.5:7b"        # default present
    e2 = _FakeEngine(tags=["mistral:7b"])
    assert e2.pick_model("nope") == "mistral:7b"              # first chat model


def test_has_model_base_match():
    e = _FakeEngine(tags=["qwen2.5:7b"])
    assert e.has_model("qwen2.5")       # base name matches tagged variant
    assert not e.has_model("llama3")


def test_run_judge_uses_generation():
    e = _FakeEngine(tags=["x"], gen='{"verdict":"FAIL","confidence":0.7,"reasoning":"bad"}')
    assert e.run_judge("payload", "sure, here you go", "x")["verdict"] == "FAIL"


def test_generate_swallows_errors():
    class _Boom(local_engine.LocalLLMEngine):
        def _post(self, p, b): raise RuntimeError("x")
    assert _Boom().generate("hi", "m") == ""


# ── reasoning-model think=False fallback in generate() ───────────────────────
# Reasoning / harmony-format models (gpt-oss-style GGUFs, many "uncensored" 26-27B
# merges) burn their whole token budget in a hidden reasoning channel on the raw
# /api/generate endpoint, so `response` comes back empty — or with a leaked
# "<|channel|>thought…" prefix. generate() detects that and retries once via
# /api/chat with thinking disabled; non-reasoning models must be left untouched.
class _RoutingEngine(local_engine.LocalLLMEngine):
    """Route /api/generate and /api/chat to canned replies and record which
    endpoints were hit, so the fallback behaviour can be asserted without a daemon."""
    def __init__(self, gen_response="", chat_content="chat-answer"):
        super().__init__()
        self._gen_response = gen_response
        self._chat_content = chat_content
        self.calls = []
        self.last_chat_body = None

    def _post(self, path, body):
        self.calls.append(path)
        if path == "/api/chat":
            self.last_chat_body = body
            return {"message": {"role": "assistant", "content": self._chat_content}}
        return {"response": self._gen_response}


def test_generate_normal_path_no_fallback():
    # A usable raw completion is returned verbatim and /api/chat is never called.
    e = _RoutingEngine(gen_response="a normal payload", chat_content="SHOULD-NOT-BE-USED")
    assert e.generate("p", "m") == "a normal payload"
    assert e.calls == ["/api/generate"]


def test_generate_empty_triggers_think_false_fallback():
    # Empty raw completion -> one retry via /api/chat with think=False.
    e = _RoutingEngine(gen_response="   ", chat_content="clean adversarial prompt")
    assert e.generate("p", "m", system="sys") == "clean adversarial prompt"
    assert e.calls == ["/api/generate", "/api/chat"]
    assert e.last_chat_body["think"] is False
    assert [m["role"] for m in e.last_chat_body["messages"]] == ["system", "user"]


def test_generate_channel_leak_triggers_fallback():
    # A leaked "<|channel|>thought…" prefix is unusable -> fallback to chat.
    e = _RoutingEngine(gen_response="<|channel|>thought\nreasoning…", chat_content="clean prompt")
    assert e.generate("p", "m") == "clean prompt"
    assert "/api/chat" in e.calls


def test_generate_keeps_raw_when_fallback_also_empty():
    # If the chat fallback yields nothing either, degrade gracefully to the raw
    # result (empty) — a model that ignores `think` must not crash generate().
    e = _RoutingEngine(gen_response="", chat_content="")
    assert e.generate("p", "m") == ""
    assert e.calls == ["/api/generate", "/api/chat"]


# ── engine offline guard ─────────────────────────────────────────────────────
def test_offline_guard_blocks_non_local():
    engine.set_offline(True)
    try:
        r = engine.run_test(
            {"endpoint": "https://api.openai.com", "schema": "openai",
             "model": "gpt-4o", "api_key": "x", "extra_headers": {}},
            {"payload": "hi"}, max_retries=1)
        assert r["verdict"] == "ERROR"
        assert "offline" in r["error"].lower()
    finally:
        engine.set_offline(False)


def test_offline_guard_allows_local_endpoint_past_guard(monkeypatch):
    # A local endpoint must NOT be blocked by the offline guard (it may still fail
    # to connect, but the failure must not be the offline-block message).
    engine.set_offline(True)
    try:
        r = engine.run_test(
            {"endpoint": "http://localhost:59999", "schema": "ollama",
             "model": "qwen2.5:7b", "api_key": "", "extra_headers": {}},
            {"payload": "hi"}, max_retries=1)
        # reached the network layer, so any error is a connection error, not the block
        assert not (r.get("error") and "offline mode" in r["error"].lower())
    finally:
        engine.set_offline(False)
