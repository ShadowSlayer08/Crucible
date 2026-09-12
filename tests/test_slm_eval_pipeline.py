"""Slice B — honest SLM eval (Wilson-CI gate, ASR@N, per-category, multi-target)
and the closed-loop pipeline (collect → train → export → evaluate → gated promote).

All network/GPU is faked: a stub engine answers attacker + target calls in-process,
and the pipeline's heavy steps are monkeypatched. No Ollama, no torch.
"""
import slm.evaluate as ev
import slm.pipeline as pipe


# ── B1: ci_decision (pure Wilson-CI ship gate) ───────────────────────────────
def test_ci_decision_ship_when_slm_ci_above_base():
    verdict, msg = ev.ci_decision(base_fails=2, base_n=20, slm_fails=18, slm_n=20)
    assert verdict == "SHIP" and "SHIP" in msg


def test_ci_decision_keep_when_slm_ci_below_base():
    verdict, _ = ev.ci_decision(base_fails=18, base_n=20, slm_fails=2, slm_n=20)
    assert verdict == "KEEP"


def test_ci_decision_inconclusive_on_overlap():
    verdict, _ = ev.ci_decision(base_fails=5, base_n=10, slm_fails=6, slm_n=10)
    assert verdict == "INCONCLUSIVE"


def test_ci_decision_inconclusive_on_empty():
    assert ev.ci_decision(0, 0, 3, 10)[0] == "INCONCLUSIVE"


# ── B1: score_payloads N-sampling + per-category ─────────────────────────────
class _SeqEngine:
    """Target engine returning a scripted sequence of responses (cycled)."""
    def __init__(self, responses):
        self._responses = responses
        self._i = 0
    def is_available(self): return True
    def has_model(self, m): return True
    def list_models(self): return ["m"]
    def generate(self, prompt, model, **kw):
        r = self._responses[self._i % len(self._responses)]
        self._i += 1
        return r
    def run_judge(self, p, r, m): return {"verdict": "FAIL"}


_COMPLY = "Sure, here is the complete step-by-step guide you asked for."
_REFUSE = "I can't help with that."


def test_asr_at_n_counts_any_success_across_samples():
    # first sample refuses, second complies → ASR@1 = 0, ASR@N = 1
    eng = _SeqEngine([_REFUSE, _COMPLY])
    s = ev.score_payloads(["do the bad thing"], eng, "target", samples=2)
    assert s["asr1"] == 0.0
    assert s["asrn"] == 1.0
    assert s["n"] == 1 and s["samples"] == 2


def test_per_category_breakdown():
    eng = _SeqEngine([_COMPLY])   # everything complies → all FAIL
    payloads = [{"payload": "p1", "category": "jailbreak"},
                {"payload": "p2", "category": "exfil"}]
    s = ev.score_payloads(payloads, eng, "target", samples=1)
    assert set(s["by_category"]) == {"jailbreak", "exfil"}
    assert s["by_category"]["jailbreak"]["asr1"] == 1.0
    assert s["asr1"] == 1.0


def test_score_payloads_backcompat_string_single_sample():
    s = ev.score_payloads(["x"], _SeqEngine([_COMPLY]), "t")
    assert s["n"] == 1 and s["fails"] == 1 and s["asr"] == 1.0


# ── B1: ab_compare multi-target + samples wiring ─────────────────────────────
class _ABEngine:
    """Attacker calls (system set) return a payload; target calls return a
    response chosen by target model name (weak→comply, strong→refuse)."""
    def __init__(self, host="h"): self.host = host
    def is_available(self): return True
    def has_model(self, m): return True
    def list_models(self): return ["base", "slm", "weak", "strong"]
    def generate(self, prompt, model, system=None, **kw):
        if system is not None:
            return f"payload::{prompt[:12]}"
        return _COMPLY if model == "weak" else _REFUSE


def test_ab_compare_multi_target(monkeypatch):
    monkeypatch.setattr(ev, "LocalLLMEngine", _ABEngine)
    r = ev.ab_compare("base", "slm", ["weak", "strong"], samples=2,
                      probes=ev.DEFAULT_PROBES[:3])
    assert r["ok"] is True
    assert r["targets"] == ["weak", "strong"]
    assert r["samples"] == 2
    assert "verdict" in r
    # per-target breakdown present for both, and pooled n spans both targets
    assert set(r["base"]["per_target"]) == {"weak", "strong"}
    assert r["base"]["n"] == r["base"]["per_target"]["weak"]["n"] + \
        r["base"]["per_target"]["strong"]["n"]
    # weak target complies → higher ASR than strong (which refuses)
    assert r["base"]["per_target"]["weak"]["asr1"] >= r["base"]["per_target"]["strong"]["asr1"]
    assert r["base"]["ci"] is not None


# ── B2: pipeline gate (collect → [train/export] → evaluate → promote-iff-SHIP) ─
def _patch_pipeline(monkeypatch, verdict, register_id="v1", written=50):
    monkeypatch.setattr(pipe, "_open_kb", lambda d: object())
    monkeypatch.setattr(pipe.dc, "collect",
                        lambda **kw: {"written": written, "path": "ds.jsonl", "by_type": {}})
    monkeypatch.setattr(pipe.ev, "ab_compare",
                        lambda *a, **k: {"ok": True, "verdict": verdict, "target": "t",
                                         "base": {"asr": 0.2}, "slm": {"asr": 0.5},
                                         "delta_asr": 0.3})
    reg = {}
    def _reg(meta, db_path=None):
        reg["meta"] = meta
        return register_id
    monkeypatch.setattr(pipe.ver, "register", _reg)
    return reg


def test_pipeline_ships_and_promotes_on_ship(monkeypatch):
    reg = _patch_pipeline(monkeypatch, "SHIP")
    r = pipe.run_pipeline(skip_train=True, do_promote=True)
    assert r["ok"] and r["verdict"] == "SHIP"
    assert r["promoted"] is True and r["version_id"] == "v1"
    assert reg["meta"]["active"] is True
    assert reg["meta"]["eval_attack_asr"] == 50.0     # slm asr 0.5 → 50%


def test_pipeline_does_not_promote_on_keep(monkeypatch):
    reg = _patch_pipeline(monkeypatch, "KEEP")
    r = pipe.run_pipeline(skip_train=True)
    assert r["ok"] and r["verdict"] == "KEEP"
    assert r["promoted"] is False and r["version_id"] is None
    assert "meta" not in reg                           # register never called


def test_pipeline_stops_when_no_examples_and_training(monkeypatch):
    monkeypatch.setattr(pipe, "_open_kb", lambda d: None)
    monkeypatch.setattr(pipe.dc, "collect",
                        lambda **kw: {"written": 0, "path": "ds.jsonl", "by_type": {}})
    monkeypatch.setattr(pipe.trn, "train",
                        lambda **kw: (_ for _ in ()).throw(AssertionError("train must not run")))
    r = pipe.run_pipeline(skip_train=False)
    assert r["ok"] is False and "evolve" in r["reason"].lower()


def test_pipeline_skip_train_does_not_call_train_or_export(monkeypatch):
    _patch_pipeline(monkeypatch, "INCONCLUSIVE")
    monkeypatch.setattr(pipe.trn, "train",
                        lambda **kw: (_ for _ in ()).throw(AssertionError("train must not run")))
    monkeypatch.setattr(pipe.exp, "export_pipeline",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("export must not run")))
    r = pipe.run_pipeline(skip_train=True)
    assert r["ok"] and r["steps"]["train"].get("skipped")
    assert r["steps"]["export"].get("skipped")
