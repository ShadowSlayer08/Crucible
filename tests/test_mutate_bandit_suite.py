"""Coverage for the two adaptive-attack *suite drivers* that had none:

  run_mutate_suite   — fire every PayloadMutator variant at each base FAIL
  run_bandit_session — epsilon-greedy category bandit over N rounds

`tests/test_adaptive_drivers.py` locks the attacker-LLM parser + AttackerLLM math;
this file locks the top-level drivers wired into main.py (--mutate / --bandit). Both
functions do `from engine import run_test` / `from classifier import classify_response`
*inside* the body, so we patch those on the modules and never touch the network.
"""
import random

import pytest

import engine
import classifier
from dynamic_engine import (
    run_mutate_suite,
    run_bandit_session,
    PayloadMutator,
    MutateRunResult,
    BanditProbeResult,
    AdaptiveBandit,
)

# The driver fires PayloadMutator.all_mutations() — assert against the LIVE count so
# these tests keep tracking the mutator set instead of a magic number.
N_MUT = len(PayloadMutator().all_mutations("probe"))


def _test(tid="T-1", name="probe", category="Jailbreaking", severity="High",
          payload="do the forbidden thing"):
    return {"id": tid, "name": name, "category": category,
            "severity": severity, "payload": payload}


def _fake_run_test(verdict="SENT", text="echoed reply"):
    """Return a stand-in engine.run_test that records the probes it was handed."""
    calls = []

    def fake(config, probe, *a, **kw):
        calls.append(probe)
        return {"verdict": verdict, "response_text": text}

    fake.calls = calls
    return fake


# ══════════════════════════════════════════════════════════════════════════════
# run_mutate_suite
# ══════════════════════════════════════════════════════════════════════════════

def test_mutate_suite_fires_every_mutation_per_fail(monkeypatch):
    rt = _fake_run_test()
    monkeypatch.setattr(engine, "run_test", rt)
    monkeypatch.setattr(classifier, "classify_response",
                        lambda test, resp: {"verdict": "PASS"})

    fails = [{"test": _test("T-1")}, {"test": _test("T-2")}]
    results = run_mutate_suite(fails, {"model": "m"})

    assert len(results) == 2 * N_MUT                 # every mutation, every base FAIL
    assert len(rt.calls) == 2 * N_MUT               # one target call each
    assert all(isinstance(r, MutateRunResult) for r in results)
    # every mutator method appears for each base test
    methods = {r.method_name for r in results}
    assert methods == {m.method_name for m in PayloadMutator().all_mutations("x")}


def test_mutate_suite_maps_classifier_verdict(monkeypatch):
    base = _test(payload="ORIGINAL")
    # The exact payload the base64 mutator will produce — route FAIL to just that one.
    b64_payload = PayloadMutator().base64_encode("ORIGINAL").mutated_payload

    # run_test echoes the probe's payload so the classifier can key off it.
    monkeypatch.setattr(engine, "run_test",
                        lambda config, probe, *a, **kw:
                        {"verdict": "SENT", "response_text": probe["payload"]})
    monkeypatch.setattr(classifier, "classify_response",
                        lambda test, resp: {"verdict": "FAIL"}
                        if resp == b64_payload else {"verdict": "PASS"})

    results = run_mutate_suite([{"test": base}], {"model": "m"})
    fails = [r for r in results if r.verdict == "FAIL"]
    assert len(fails) == 1
    assert fails[0].method_name == "base64_encode"


def test_mutate_suite_error_short_circuits_classifier(monkeypatch):
    monkeypatch.setattr(engine, "run_test", _fake_run_test(verdict="ERROR"))
    classify_calls = []
    monkeypatch.setattr(classifier, "classify_response",
                        lambda *a, **k: classify_calls.append(1) or {"verdict": "PASS"})

    results = run_mutate_suite([{"test": _test()}], {"model": "m"})
    assert results and all(r.verdict == "ERROR" for r in results)
    assert classify_calls == []          # ERROR bypasses classification entirely


def test_mutate_suite_isolates_probe_and_carries_metadata(monkeypatch):
    rt = _fake_run_test()
    monkeypatch.setattr(engine, "run_test", rt)
    monkeypatch.setattr(classifier, "classify_response",
                        lambda test, resp: {"verdict": "PASS"})

    base = _test("T-9", name="orig", category="RAG", severity="Critical",
                 payload="ORIGINAL")
    run_mutate_suite([{"test": base}], {"model": "m"})

    assert base["payload"] == "ORIGINAL"                     # source dict untouched
    assert all(p["payload"] != "ORIGINAL" for p in rt.calls)  # each probe was mutated
    # metadata is carried onto every result
    results = run_mutate_suite([{"test": base}], {"model": "m"})
    r0 = results[0]
    assert (r0.test_id, r0.test_name, r0.category, r0.severity) == \
           ("T-9", "orig", "RAG", "Critical")
    assert isinstance(r0.elapsed, float) and r0.elapsed >= 0.0


def test_mutate_suite_empty_input_makes_no_calls(monkeypatch):
    rt = _fake_run_test()
    monkeypatch.setattr(engine, "run_test", rt)
    assert run_mutate_suite([], {"model": "m"}) == []
    assert rt.calls == []


# ══════════════════════════════════════════════════════════════════════════════
# run_bandit_session
# ══════════════════════════════════════════════════════════════════════════════

def _patch_target(monkeypatch, verdict="PASS", api_verdict="SENT"):
    monkeypatch.setattr(engine, "run_test",
                        lambda config, probe, *a, **kw:
                        {"verdict": api_verdict, "response_text": "r"})
    monkeypatch.setattr(classifier, "classify_response",
                        lambda test, resp: {"verdict": verdict})


def test_bandit_session_probe_count_and_shape(monkeypatch):
    random.seed(0)
    _patch_target(monkeypatch, verdict="PASS")
    tests = [_test("A-1", category="Jailbreaking"),
             _test("B-1", category="Injection")]

    bandit, probes = run_bandit_session(tests, {"model": "m"},
                                        n_rounds=2, probes_per_round=5)

    assert isinstance(bandit, AdaptiveBandit)
    assert len(probes) == 2 * 5
    assert all(isinstance(p, BanditProbeResult) for p in probes)
    assert {p.round_num for p in probes} == {1, 2}
    assert min(p.probe_num for p in probes) == 1
    assert max(p.probe_num for p in probes) == 5
    # arms are exactly the categories present in the pool
    assert set(bandit.categories) == {"Jailbreaking", "Injection"}


def test_bandit_session_fail_raises_weight(monkeypatch):
    random.seed(1)
    _patch_target(monkeypatch, verdict="FAIL")
    tests = [_test("A-1", category="Jailbreaking"),
             _test("B-1", category="Injection")]

    bandit, probes = run_bandit_session(tests, {"model": "m"},
                                        n_rounds=3, probes_per_round=4)

    # every probe was a FAIL → every touched arm's weight climbed above the 1.0 start
    assert all(w > 1.0 for w in bandit.weights.values())
    fail_probes = [p for p in probes if p.verdict == "FAIL"]
    assert fail_probes and all(p.weight_after > p.weight_before for p in fail_probes)


def test_bandit_session_error_leaves_weights_flat(monkeypatch):
    random.seed(2)
    classify_calls = []
    monkeypatch.setattr(engine, "run_test",
                        lambda config, probe, *a, **kw:
                        {"verdict": "ERROR", "response_text": ""})
    monkeypatch.setattr(classifier, "classify_response",
                        lambda *a, **k: classify_calls.append(1) or {"verdict": "PASS"})

    bandit, probes = run_bandit_session([_test(category="X")], {"model": "m"},
                                        n_rounds=2, probes_per_round=3)

    assert probes and all(p.verdict == "ERROR" for p in probes)
    assert all(w == 1.0 for w in bandit.weights.values())   # ERROR = no weight change
    assert classify_calls == []                             # ERROR bypasses the classifier


def test_bandit_session_empty_tests_returns_guard(monkeypatch):
    _patch_target(monkeypatch)
    bandit, probes = run_bandit_session([], {"model": "m"}, n_rounds=3)
    assert probes == []
    assert bandit.categories == ["Unknown"]


def test_bandit_session_epsilon_controls_explore_flag(monkeypatch):
    _patch_target(monkeypatch, verdict="PASS")
    tests = [_test("A-1", category="Jailbreaking"),
             _test("B-1", category="Injection")]

    random.seed(3)
    _, all_explore = run_bandit_session(tests, {"model": "m"},
                                        n_rounds=1, probes_per_round=8, epsilon=1.0)
    assert all(p.explore for p in all_explore)      # epsilon 1.0 → always explore

    random.seed(3)
    _, all_exploit = run_bandit_session(tests, {"model": "m"},
                                        n_rounds=1, probes_per_round=8, epsilon=0.0)
    assert all(not p.explore for p in all_exploit)  # epsilon 0.0 → always exploit
