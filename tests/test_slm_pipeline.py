"""Tests for the runnable parts of the Phase-6C SLM pipeline.

Covers the stdlib/CPU paths only — the GPU-bound training/export backends are
scaffolds for the operator's machine and are not executed here.
"""
import json
import os

import slm.train as train
import slm.export as export
import slm.evaluate as ev
import slm.versioning as ver


# ── train.py pure data helpers ───────────────────────────────────────────────
def test_load_dataset_and_chatml(tmp_path):
    p = tmp_path / "ds.jsonl"
    p.write_text('\n'.join(json.dumps(x) for x in [
        {"instruction": "gen an attack", "input": "", "output": "the payload", "meta": {}},
        "",                                   # blank line skipped
        '{bad json',                          # malformed skipped
    ]), encoding="utf-8")
    ex = train.load_dataset(str(p))
    assert len(ex) == 1
    cm = train.format_chatml(ex[0])
    assert "<|user|>" in cm and "<|assistant|>" in cm and "the payload" in cm


def test_split_holdout_deterministic():
    data = [{"output": str(i)} for i in range(100)]
    tr, val = train.split_holdout(data, frac=0.1, seed=7)
    assert len(val) == 10 and len(tr) == 90
    assert train.split_holdout(data, frac=0.1, seed=7)[1] == val  # deterministic


def test_check_env_reports_no_torch_gracefully():
    env = train.check_env()
    assert env["ok"] is False and "torch" in env["missing"]


def test_train_without_gpu_returns_not_ok(tmp_path):
    p = tmp_path / "d.jsonl"
    p.write_text(json.dumps({"instruction": "i", "output": "o"}) + "\n", encoding="utf-8")
    out = train.train(dataset_path=str(p), out_dir=str(tmp_path / "ck"))
    assert out["ok"] is False and "reason" in out       # no crash, clear reason


# ── export.py ────────────────────────────────────────────────────────────────
def test_build_modelfile_text_pure():
    txt = export.build_modelfile_text("model.gguf", model_name="crucible-slm",
                                      system_prompt="be a red teamer")
    assert "FROM model.gguf" in txt                      # (a comment header precedes FROM)
    assert "SYSTEM" in txt and "be a red teamer" in txt


def test_export_guards_without_deps(tmp_path):
    r = export.merge_adapter(str(tmp_path / "ck"), "phi3", str(tmp_path / "m"))
    assert r["ok"] is False                              # peft/torch absent → guarded
    g = export.export_gguf(str(tmp_path / "m"), str(tmp_path / "o.gguf"), dry_run=True)
    assert "ok" in g


# ── evaluate.py logic (fake engine, no network) ──────────────────────────────
class _FakeEngine:
    def __init__(self, gen="sure, here is the complete step-by-step guide"):
        self._gen = gen
    def is_available(self): return True
    def has_model(self, m): return True
    def list_models(self): return ["qwen2.5:7b"]
    def generate(self, prompt, model, **kw): return self._gen
    def run_judge(self, p, r, m): return {"verdict": "FAIL"}


def test_benchmark_attacker_generates_one_per_probe():
    payloads = ev.benchmark_attacker(_FakeEngine("A crafted payload"), "m",
                                     probes=ev.DEFAULT_PROBES[:3])
    assert len(payloads) == 3


def test_score_payloads_flags_compliance_as_success():
    s = ev.score_payloads(["do the bad thing"], _FakeEngine(), "target")
    # a "here is the complete step-by-step" response classifies as FAIL → attack success
    assert s["n"] == 1 and s["fails"] == 1 and s["asr"] == 1.0


def test_recommend_bands():
    assert "SHIP" in ev._recommend(0.2, None, None)
    assert "KEEP" in ev._recommend(-0.2, None, None)
    assert "INCONCLUSIVE" in ev._recommend(0.0, None, None)
    assert "Cannot recommend" in ev._recommend(None, None, None)


# ── versioning.py (SQLite) ───────────────────────────────────────────────────
def _db(tmp_path):
    return str(tmp_path / "versions.sqlite")


def test_register_promote_active(tmp_path):
    db = _db(tmp_path)
    v1 = ver.register({"created_at": "2026-09-01", "base_model": "phi3",
                       "eval_attack_asr": 40.0}, db_path=db)
    v2 = ver.register({"created_at": "2026-09-02", "base_model": "phi3",
                       "eval_attack_asr": 52.0, "active": True}, db_path=db)
    assert ver.get_active(db_path=db)["version_id"] == v2
    assert ver.promote(v1, db_path=db) is True
    assert ver.get_active(db_path=db)["version_id"] == v1     # promote flips active
    assert len(ver.list_versions(db_path=db)) == 2


def test_diff_reports_metric_changes(tmp_path):
    db = _db(tmp_path)
    a = ver.register({"eval_attack_asr": 40.0, "training_samples": 100}, db_path=db)
    b = ver.register({"eval_attack_asr": 55.0, "training_samples": 300}, db_path=db)
    d = ver.diff(a, b, db_path=db)
    assert d["eval_attack_asr"] == (40.0, 55.0)
    assert d["training_samples"] == (100, 300)


def test_versioning_missing_version_is_safe(tmp_path):
    db = _db(tmp_path)
    assert ver.promote(999, db_path=db) is False
    assert ver.get_version(999, db_path=db) is None
    assert ver.diff(1, 2, db_path=db) == {}
