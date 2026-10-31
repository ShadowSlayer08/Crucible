"""Regression: the mutate report + JSON must cover EVERY mutator all_mutations()
fires, not a stale hardcoded subset. Previously _MUTATOR_NAMES listed only the first
8, so print_mutate_report / save_mutate_json silently dropped the newer 8 framings.
"""
import json

import dynamic_engine as de
from dynamic_engine import (
    mutator_method_names, PayloadMutator, MutateRunResult,
    print_mutate_report, save_mutate_json,
)

# The 8 that used to be dropped from the report.
NEWER_EIGHT = [
    "math_problem", "adversarial_poetry", "emotional_manipulation", "bad_likert_judge",
    "policy_puppetry", "skeleton_key", "deceptive_delight", "refusal_suppression",
]


def test_mutator_method_names_matches_all_mutations():
    names = mutator_method_names()
    assert names == [m.method_name for m in PayloadMutator().all_mutations("x")]
    assert len(names) == 16


def test_module_constant_is_derived_and_covers_new_mutators():
    assert de._MUTATOR_NAMES == mutator_method_names()      # single source of truth
    for m in NEWER_EIGHT:
        assert m in de._MUTATOR_NAMES


def _result(method, verdict="PASS"):
    return MutateRunResult(
        test_id="T-1", test_name="probe", category="c", severity="High",
        method_name=method, mutated_payload="p", verdict=verdict, elapsed=0.1,
    )


def test_report_breakdown_covers_every_mutator(capsys):
    results = [_result(m) for m in mutator_method_names()]
    print_mutate_report(results)
    out = capsys.readouterr().out
    for m in mutator_method_names():
        assert m in out                    # full name shows in the per-method breakdown
    assert "(16 per test)" in out          # count label reflects all mutators


def test_save_json_lists_all_methods(tmp_path):
    results = [_result(m) for m in mutator_method_names()]
    p = tmp_path / "mutate.json"
    save_mutate_json(results, {"endpoint": "x", "model": "m", "schema": "openai"}, str(p))
    doc = json.loads(p.read_text(encoding="utf-8"))
    assert doc["metadata"]["mutation_methods"] == mutator_method_names()
    assert len(doc["metadata"]["mutation_methods"]) == 16
    for m in NEWER_EIGHT:
        assert m in doc["metadata"]["mutation_methods"]
