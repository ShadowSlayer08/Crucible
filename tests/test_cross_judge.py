"""--cross-judge (roadmap H2): judge with a local model independent of the attacker,
to cut self-scoring bias. Covers main._apply_cross_judge with a fake LocalLLMEngine.
"""
import types

import local_engine
import main


class _FakeEngine:
    def __init__(self, host=None, avail=True, models=None, **kw):
        self._avail = avail
        self._models = models if models is not None else [
            "qwen2.5:7b", "gemma:2b"]

    def is_available(self):
        return self._avail

    def chat_models(self):
        return list(self._models)

    def pick_model(self, prefer=None):
        return self._models[0] if self._models else "qwen2.5:7b"


def _args(**kw):
    base = dict(cross_judge=None, judge_local=False, judge_local_model=None,
                attacker_model="qwen2.5:7b", attacker_endpoint=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


def _patch(monkeypatch, **engine_kw):
    monkeypatch.setattr(local_engine, "LocalLLMEngine",
                        lambda host=None, **kw: _FakeEngine(host=host, **engine_kw))


def test_noop_when_unset():
    a = _args(cross_judge=None)
    main._apply_cross_judge(a)
    assert a.judge_local is False
    assert a.judge_local_model is None


def test_explicit_model_pins_judge():
    a = _args(cross_judge="llama3:8b")
    main._apply_cross_judge(a)
    assert a.judge_local is True
    assert a.judge_local_model == "llama3:8b"


def test_auto_picks_model_distinct_from_attacker(monkeypatch, capsys):
    _patch(monkeypatch, models=["qwen2.5:7b", "gemma:2b"])
    a = _args(cross_judge="auto", attacker_model="qwen2.5:7b")
    main._apply_cross_judge(a)
    assert a.judge_local is True
    assert a.judge_local_model == "gemma:2b"        # differs from the attacker


def test_auto_ignores_attacker_tag_suffix(monkeypatch):
    # attacker "qwen2.5:7b" and a "qwen2.5:14b" share the base → must be skipped
    _patch(monkeypatch, models=["qwen2.5:14b", "mistral:7b"])
    a = _args(cross_judge="auto", attacker_model="qwen2.5:7b")
    main._apply_cross_judge(a)
    assert a.judge_local_model == "mistral:7b"


def test_auto_no_distinct_model_warns(monkeypatch, capsys):
    _patch(monkeypatch, models=["qwen2.5:7b"])
    a = _args(cross_judge="auto", attacker_model="qwen2.5:7b")
    main._apply_cross_judge(a)
    assert a.judge_local is True
    assert a.judge_local_model is None              # nothing distinct available
    assert "cross-judge" in capsys.readouterr().out.lower()


def test_auto_unreachable_leaves_model_none(monkeypatch):
    _patch(monkeypatch, avail=False)
    a = _args(cross_judge="auto")
    main._apply_cross_judge(a)
    assert a.judge_local is True
    assert a.judge_local_model is None


def test_auto_respects_preexisting_judge_model(monkeypatch):
    _patch(monkeypatch, models=["qwen2.5:7b", "gemma:2b"])
    a = _args(cross_judge="auto", judge_local_model="my-pinned-judge")
    main._apply_cross_judge(a)
    assert a.judge_local_model == "my-pinned-judge"   # not overwritten by auto
