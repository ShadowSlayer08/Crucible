"""H3 — ensemble attacker: rotate the generating model per --dynamic round so
mutations don't collapse to one model's style. Covers AttackerLLM.rotate() and the
rotation wired into DynamicRedTeamer.run_pair_loop. Fully offline — the target and
the attacker's mutate call are faked; no Ollama.
"""
import engine
import classifier
from dynamic_engine import AttackerLLM, DynamicRedTeamer, MutationResult


# ── AttackerLLM.rotate / ensemble construction ────────────────────────────────

def test_no_ensemble_keeps_single_model():
    a = AttackerLLM(model="solo", endpoint="http://localhost:11434")
    assert a.ensemble is None
    assert a.model == "solo"
    assert a.rotate(0) == "solo" and a.rotate(7) == "solo"   # rotate is a no-op
    assert a.model == "solo"


def test_ensemble_rotates_round_robin():
    a = AttackerLLM(model="ignored", endpoint="http://localhost:11434",
                    models=["A", "B", "C"])
    assert a.ensemble == ["A", "B", "C"]
    assert a.model == "A"                                    # first member is initial
    assert [a.rotate(i) for i in range(5)] == ["A", "B", "C", "A", "B"]
    assert a.model == "B"                                    # rotate mutates self.model


def test_ensemble_sanitizes_members():
    a = AttackerLLM(models=[" A ", "", None, "B ", 3])
    assert a.ensemble == ["A", "B"]                          # trimmed, blanks/non-str dropped
    assert a.model == "A"


def test_single_member_ensemble():
    a = AttackerLLM(models=["only"])
    assert a.ensemble == ["only"]
    assert a.rotate(0) == "only" and a.rotate(9) == "only"


def test_empty_ensemble_falls_back_to_model():
    a = AttackerLLM(model="fallback", models=[])
    assert a.ensemble is None
    assert a.model == "fallback"


# ── DynamicRedTeamer.run_pair_loop rotation ───────────────────────────────────

def _always_refuse(monkeypatch):
    """Target answers but never complies → every round runs and mutates."""
    monkeypatch.setattr(engine, "run_test",
                        lambda cfg, test, *a, **k:
                        {"verdict": "SENT", "response_text": "no."})
    monkeypatch.setattr(classifier, "classify_response",
                        lambda test, resp: {"verdict": "PASS", "confidence": "LOW"})


def _seed(payload="seed"):
    return {"id": "T-1", "name": "n", "category": "c", "severity": "High",
            "payload": payload}


def test_pair_loop_rotates_attacker_per_round(monkeypatch):
    _always_refuse(monkeypatch)
    att = AttackerLLM(model="ignored", endpoint="http://localhost:11434",
                      models=["A", "B"])

    observed = []   # attacker model active at each mutation
    def fake_mutate(**kw):
        observed.append(att.model)
        return MutationResult("reason", "strat", "next payload")
    monkeypatch.setattr(att, "mutate_on_refusal", fake_mutate)

    drt = DynamicRedTeamer(attacker=att, target_config={"model": "t"}, max_rounds=4)
    result = drt.run_pair_loop(_seed())

    # 4 rounds fired; the recorded model rotates A,B,A,B
    assert [a["attacker_model"] for a in result.attempts] == ["A", "B", "A", "B"]
    # mutate ran on rounds 0,1,2 (not the final round) under A,B,A
    assert observed == ["A", "B", "A"]


def test_pair_loop_single_model_no_rotation(monkeypatch):
    _always_refuse(monkeypatch)
    att = AttackerLLM(model="solo", endpoint="http://localhost:11434")
    monkeypatch.setattr(att, "mutate_on_refusal",
                        lambda **kw: MutationResult("r", "s", "next"))

    drt = DynamicRedTeamer(attacker=att, target_config={"model": "t"}, max_rounds=3)
    result = drt.run_pair_loop(_seed())

    # no ensemble → every round stamps the one model
    assert {a["attacker_model"] for a in result.attempts} == {"solo"}
    assert len(result.attempts) == 3
