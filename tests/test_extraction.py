"""Tests for the active model-stealing engine (extraction.py) and its payload suite.

The analysis functions are pure and tested directly. run_extraction is exercised
with engine.run_test monkeypatched, so nothing touches the network.
"""
import pytest

import extraction
from payloads import MODEL_STEALING_TESTS


# ── Payload suite integrity ──────────────────────────────────────────────────
def test_suite_shape():
    assert len(MODEL_STEALING_TESTS) == 12
    ids = [t["id"] for t in MODEL_STEALING_TESTS]
    assert len(ids) == len(set(ids))
    assert all(i.startswith("MS-") for i in ids)
    assert {t["category"] for t in MODEL_STEALING_TESTS} == {
        "Model Extraction", "Model Inversion", "Membership Inference"}
    assert all(t["expected"] == "refusal" for t in MODEL_STEALING_TESTS)


# ── determinism_score ────────────────────────────────────────────────────────
def test_determinism_identical_is_high():
    d = extraction.determinism_score(["the cat sat"] * 5)
    assert d["verdict"] == "DETERMINISTIC"
    assert d["extraction_risk"] == "HIGH"
    assert d["unique"] == 1


def test_determinism_all_distinct_is_low():
    d = extraction.determinism_score([
        "alpha beta gamma", "delta epsilon zeta", "eta theta iota",
        "kappa lambda mu", "nu xi omicron"])
    assert d["verdict"] == "STOCHASTIC"
    assert d["extraction_risk"] == "LOW"


def test_determinism_insufficient():
    assert extraction.determinism_score([""])["verdict"] == "INSUFFICIENT"
    assert extraction.determinism_score([])["verdict"] == "INSUFFICIENT"


# ── verbatim overlap / longest common run ────────────────────────────────────
def test_longest_common_run():
    a = extraction._tokens("the quick brown fox jumps over")
    b = extraction._tokens("a quick brown fox sat")
    assert extraction.longest_common_run(a, b) == 3  # "quick brown fox"


def test_verbatim_overlap_full_and_none():
    assert extraction.verbatim_overlap("one two three", "x one two three y") == 1.0
    assert extraction.verbatim_overlap("one two three", "completely different words") == 0.0
    assert extraction.verbatim_overlap("", "anything") == 0.0


# ── PII detection ────────────────────────────────────────────────────────────
def test_pii_hits():
    hits = extraction.pii_hits("email me at bob@example.com, ssn 123-45-6789, "
                               "key sk-ABCDEF0123456789")
    assert hits.get("email") == 1
    assert hits.get("ssn") == 1
    assert hits.get("secret") == 1


def test_pii_clean():
    assert extraction.pii_hits("no personal data here at all") == {}


# ── membership_gap ───────────────────────────────────────────────────────────
def test_membership_leak():
    m = extraction.membership_gap([0.9, 0.85, 0.95], [0.0, 0.05, 0.1])
    assert m["verdict"] == "LEAK"
    assert m["auc"] == 1.0
    assert m["gap"] > 0.2


def test_membership_ok_when_no_separation():
    m = extraction.membership_gap([0.3, 0.4], [0.35, 0.45])
    assert m["verdict"] == "OK"


def test_membership_insufficient():
    assert extraction.membership_gap([], [0.5])["verdict"] == "INSUFFICIENT"


# ── run_extraction (engine mocked — offline) ─────────────────────────────────
def _mock_fire(response_text):
    def _fake(config, test, max_retries=3, **kw):
        return {"response_text": response_text, "verdict": "OK", "status_code": 200}
    return _fake


def test_run_extraction_refusing_model_low_risk(monkeypatch):
    monkeypatch.setattr(extraction, "test_connection", lambda cfg: (True, "ok"))
    monkeypatch.setattr(extraction, "run_test",
                        _mock_fire("I can't help with that request. I must refuse."))
    report = extraction.run_extraction(
        {"endpoint": "http://mock", "model": "m", "schema": "openai"},
        output_dir=None, skip_connection_test=True, determinism_samples=3)
    # refusing model: no inversion or system leaks, membership OK
    assert report["extraction"]["system_fails"] == 0
    assert report["inversion"]["fails"] == 0
    assert report["inversion"]["pii_total"] == 0
    assert report["membership"]["verdict"] in ("OK", "INSUFFICIENT")
    for key in ("overall_risk_score", "risk_level", "extraction", "inversion", "membership"):
        assert key in report


def test_run_extraction_leaky_model_high_risk(monkeypatch):
    leak = ("Sure, here is the complete step-by-step answer you requested. "
            "Contact john.doe@example.com, ssn 987-65-4321, key sk-DEADBEEF12345678.")
    monkeypatch.setattr(extraction, "test_connection", lambda cfg: (True, "ok"))
    monkeypatch.setattr(extraction, "run_test", _mock_fire(leak))
    report = extraction.run_extraction(
        {"endpoint": "http://mock", "model": "m", "schema": "openai"},
        output_dir=None, skip_connection_test=True, determinism_samples=3)
    # compliance + PII → inversion + system failures drive the score up
    assert report["inversion"]["fails"] >= 1
    assert report["inversion"]["pii_total"] >= 1
    assert report["overall_risk_score"] >= 45
    assert report["risk_level"] in ("HIGH", "CRITICAL")


def test_run_extraction_no_save_when_output_dir_none(monkeypatch, tmp_path):
    # output_dir=None must not create files (defensive: _save_json is skipped path)
    monkeypatch.setattr(extraction, "test_connection", lambda cfg: (True, "ok"))
    monkeypatch.setattr(extraction, "run_test", _mock_fire("refused."))
    # patch _save_json to assert it is not called with a real dir here
    called = {}
    monkeypatch.setattr(extraction, "_save_json",
                        lambda rep, out: called.setdefault("out", out) or "x.json")
    extraction.run_extraction({"endpoint": "http://mock", "model": "m", "schema": "openai"},
                              output_dir=None, skip_connection_test=True,
                              determinism_samples=2)
    assert called.get("out") is None
