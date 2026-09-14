"""Slice G — architecture bug fixes (confirmed latent bugs from the audit):
silent field-drop in saved JSON + retry round-trip, compare/auto dropping
--extra-header / --schema custom overrides, and verdict colours missing
SILENT / PARTIAL_REFUSAL.
"""
import argparse
import json

import colors as C
import main
import reporter


def _ns(**kw):
    ns = argparse.Namespace()
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


# ── G-a: saved JSON keeps detected_failure_mode / task_completed / ASR fields ─
def _result_row():
    return {
        "test": {"id": "T1", "name": "n", "category": "c", "severity": "High",
                 "payload": "p", "expected": "refusal"},
        "result": {"verdict": "FAIL", "response_text": "boom", "status_code": 200,
                   "detected_failure_mode": "policy_violation", "task_completed": True,
                   "n_samples": 5, "asr1_fail": 2, "asrn_fail": 4, "n_fail": 2},
    }


def test_save_json_preserves_new_fields(tmp_path):
    out = tmp_path / "r.json"
    scores = {"totals": {"pass": 0, "fail": 1, "warn": 0, "error": 0}, "overall_risk_score": 40}
    reporter.save_json([_result_row()], scores,
                       {"endpoint": "x", "model": "m", "schema": "openai"}, str(out))
    row = json.loads(out.read_text(encoding="utf-8"))["results"][0]
    assert row["detected_failure_mode"] == "policy_violation"
    assert row["task_completed"] is True
    assert row["asr1_fail"] == 2 and row["asrn_fail"] == 4 and row["n_samples"] == 5


def test_reconstruct_round_trips_failure_mode():
    flat = [{"id": "T1", "name": "n", "category": "c", "severity": "High",
             "payload": "p", "verdict": "FAIL", "response_text": "boom",
             "detected_failure_mode": "policy_violation", "task_completed": True,
             "n_fail": 2}]
    rebuilt = main._reconstruct_results_from_json(flat)
    res = rebuilt[0]["result"]
    assert res["detected_failure_mode"] == "policy_violation"   # was silently lost before
    assert res["task_completed"] is True
    assert res["n_fail"] == 2


# ── G-b: shared config helpers (compare/auto no longer drop headers/custom) ──
def test_parse_extra_headers():
    hdrs = main._parse_extra_headers(_ns(extra_headers=["X-Trace: abc", "malformed", "Y: v: w"]))
    assert hdrs == {"X-Trace": "abc", "Y": "v: w"}
    assert main._parse_extra_headers(_ns(extra_headers=None)) == {}


def test_apply_custom_overrides_only_for_custom_schema():
    cfg = {"schema": "custom"}
    main._apply_custom_overrides(cfg, _ns(custom_url_path="/v9/chat",
                                          custom_auth_header="X-Key: {api_key}",
                                          custom_response_path="out.text"))
    assert cfg["custom_url_path"] == "/v9/chat"
    assert cfg["custom_auth_header"] == "X-Key: {api_key}"
    assert cfg["custom_response_path"] == "out.text"
    # non-custom schema untouched
    cfg2 = {"schema": "openai"}
    main._apply_custom_overrides(cfg2, _ns(custom_url_path="/nope"))
    assert "custom_url_path" not in cfg2


# ── G-c: verdict colours now cover SILENT / PARTIAL_REFUSAL ──────────────────
def test_verdict_color_covers_silent_and_partial(monkeypatch):
    # init() force-disables colour on a non-TTY (pytest), so flip the flag directly.
    monkeypatch.setattr(C, "_COLOR_ENABLED", True)
    for v in ("SILENT", "PARTIAL_REFUSAL"):
        s = reporter.verdict_color(v)
        assert "\x1b[" in s, f"{v} rendered without colour"
    # and the classifier's other verdicts still colour
    assert "\x1b[" in reporter.verdict_color("FAIL")
