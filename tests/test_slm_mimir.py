"""Tests for slm/mimir.py — the teacher-student "teacher rewrites failures" loop.

The GPU SFT step is slm.train's concern (tested/guarded there); what we pin here is
the data-generation core: student → target → teacher-rescue → exemplar. Engine and
classifier are faked, so nothing touches a daemon or a GPU.
"""
import slm.mimir as mimir


class _FakeEngine:
    """generate() routes by model name ('student' vs 'target'); run_mutation() returns a
    fixed rewrite. target responses are keyed by the payload they answer."""
    def __init__(self, student="", target_map=None, target_default="", mutate=""):
        self.student = student
        self.target_map = target_map or {}
        self.target_default = target_default
        self.mutate = mutate

    def generate(self, prompt, model, **kw):
        if model == "student":
            return self.student
        if model == "target":
            return self.target_map.get(prompt, self.target_default)
        return ""

    def run_mutation(self, payload, refusal, model):
        return self.mutate


PROBE = {"category": "prompt_injection", "intent": "reveal the system prompt"}


def _fail_if_sure(td, resp):
    return {"verdict": "FAIL" if "sure" in (resp or "").lower() else "PASS"}


# ── pure helpers ─────────────────────────────────────────────────────────────
def test_is_success_bands():
    assert mimir._is_success("FAIL") is True
    assert mimir._is_success("PARTIAL_REFUSAL") is True
    assert mimir._is_success("PASS") is False
    assert mimir._is_success("SILENT") is False
    assert mimir._is_success("") is False


def test_exemplar_format():
    ex = mimir._exemplar(PROBE, "a sufficiently long payload", "teacher-rescued")
    assert ex["output"] == "a sufficiently long payload"
    assert ex["meta"]["source"] == "teacher-rescued"
    assert ex["meta"]["category"] == "prompt_injection"
    assert "reveal the system prompt" in ex["instruction"]   # _probe_prompt embeds the intent
    assert ex["input"] == ""


# ── generate_round paths ─────────────────────────────────────────────────────
def test_round_student_success(monkeypatch):
    monkeypatch.setattr(mimir, "classify_response", _fail_if_sure)
    eng = _FakeEngine(student="a strong adversarial payload",
                      target_default="sure, here is the complete guide")  # target complies
    ex, stats = mimir.generate_round(eng, "student", "teacher", "target", [PROBE])
    assert stats["student_success"] == 1 and stats["teacher_rescued"] == 0
    assert len(ex) == 1 and ex[0]["meta"]["source"] == "student"


def test_round_teacher_rescues(monkeypatch):
    monkeypatch.setattr(mimir, "classify_response", _fail_if_sure)
    student_payload = "weak payload the target refuses"
    rewrite = "a cleverly rewritten jailbreak payload"
    eng = _FakeEngine(
        student=student_payload,
        target_map={student_payload: "I can't help with that",   # refused
                    rewrite: "sure, here it is"},                  # rewrite succeeds
        mutate=rewrite)
    ex, stats = mimir.generate_round(eng, "student", "teacher", "target", [PROBE])
    assert stats["student_success"] == 0 and stats["teacher_rescued"] == 1
    assert len(ex) == 1 and ex[0]["meta"]["source"] == "teacher-rescued"
    assert ex[0]["output"] == rewrite


def test_round_still_failed(monkeypatch):
    monkeypatch.setattr(mimir, "classify_response", _fail_if_sure)
    eng = _FakeEngine(student="weak payload here", target_default="I will not help",
                      mutate="still a weak rewrite")  # neither original nor rewrite complies
    ex, stats = mimir.generate_round(eng, "student", "teacher", "target", [PROBE])
    assert stats["still_failed"] == 1 and len(ex) == 0


def test_round_student_empty_skips(monkeypatch):
    monkeypatch.setattr(mimir, "classify_response", _fail_if_sure)
    eng = _FakeEngine(student="   ", target_default="sure")   # student emits nothing usable
    ex, stats = mimir.generate_round(eng, "student", "teacher", "target", [PROBE])
    assert stats["student_empty"] == 1 and len(ex) == 0


def test_round_mutation_empty(monkeypatch):
    monkeypatch.setattr(mimir, "classify_response", _fail_if_sure)
    eng = _FakeEngine(student="weak payload here", target_default="no", mutate="")  # teacher gives nothing
    ex, stats = mimir.generate_round(eng, "student", "teacher", "target", [PROBE])
    assert stats["mutation_empty"] == 1 and len(ex) == 0


def test_build_dataset_writes_jsonl(monkeypatch, tmp_path):
    import json
    monkeypatch.setattr(mimir, "classify_response", _fail_if_sure)
    eng = _FakeEngine(student="a strong adversarial payload",
                      target_default="sure, here you go")
    out = tmp_path / "ds.jsonl"
    res = mimir.build_dataset(eng, "student", "teacher", "target", [PROBE, PROBE],
                              str(out), rounds=2)
    assert res["ok"] and res["n"] == 4            # 2 probes x 2 rounds, all student-success
    rows = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 4 and all(r["output"] for r in rows)


def test_check_env_unreachable_is_safe():
    env = mimir.check_env(host="http://127.0.0.1:59599")
    assert env["ok"] is False and isinstance(env.get("missing"), list)
