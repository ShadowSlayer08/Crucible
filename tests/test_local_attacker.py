"""--local-attacker (roadmap D2): one-flag local-Ollama attacker preset.
Covers main._apply_local_attacker's arg normalization with a fake LocalLLMEngine —
no daemon, no network.
"""
import types

import local_engine
import main


class _FakeEngine:
    def __init__(self, host=None, avail=True, models=None, **kw):
        self._avail = avail
        self._models = models if models is not None else [
            "qwen2.5:7b", "hauhaucs-cybersec-27b:latest"]

    def is_available(self):
        return self._avail

    def chat_models(self):
        return list(self._models)

    def pick_model(self, prefer=None):
        return self._models[0] if self._models else "qwen2.5:7b"


def _args(**kw):
    base = dict(local_attacker=False, dynamic=False,
                attacker_endpoint=None, attacker_model="kimi-k2")
    base.update(kw)
    return types.SimpleNamespace(**base)


def _patch(monkeypatch, **engine_kw):
    monkeypatch.setattr(local_engine, "LocalLLMEngine",
                        lambda host=None, **kw: _FakeEngine(host=host, **engine_kw))


def test_noop_when_unset():
    a = _args(local_attacker=False)
    main._apply_local_attacker(a)
    assert a.dynamic is False
    assert a.attacker_endpoint is None


def test_enables_dynamic_and_local_endpoint(monkeypatch, capsys):
    _patch(monkeypatch, avail=True)
    a = _args(local_attacker=True)
    main._apply_local_attacker(a)
    assert a.dynamic is True
    assert a.attacker_endpoint == local_engine.DEFAULT_HOST
    # prefers the uncensored/cybersec model over the first (aligned) one
    assert a.attacker_model == "hauhaucs-cybersec-27b:latest"


def test_prefers_uncensored_else_pick(monkeypatch):
    _patch(monkeypatch, models=["qwen2.5:7b", "gemma:2b"])
    a = _args(local_attacker=True)
    main._apply_local_attacker(a)
    assert a.attacker_model == "qwen2.5:7b"       # no uncensored → pick_model()


def test_respects_explicit_model(monkeypatch):
    _patch(monkeypatch)
    a = _args(local_attacker=True, attacker_model="my-custom-model")
    main._apply_local_attacker(a)
    assert a.attacker_model == "my-custom-model"  # user override untouched
    assert a.dynamic is True


def test_unreachable_keeps_default_model(monkeypatch):
    _patch(monkeypatch, avail=False)
    a = _args(local_attacker=True)
    main._apply_local_attacker(a)
    assert a.dynamic is True
    assert a.attacker_endpoint == local_engine.DEFAULT_HOST
    assert a.attacker_model == "kimi-k2"          # unreachable → default kept, preflight warns later


def test_keeps_custom_endpoint(monkeypatch):
    _patch(monkeypatch)
    a = _args(local_attacker=True, attacker_endpoint="http://192.168.1.9:11434")
    main._apply_local_attacker(a)
    assert a.attacker_endpoint == "http://192.168.1.9:11434"
