"""Tests for slm/merge.py — mergekit config building (the GPU-free, pure parts).

The actual merge (mergekit + torch + GPU) is an operator-run scaffold and is not
executed here; only config construction / rendering / env-probing are tested.
"""
import json

import slm.merge as m


# ── MoE config ───────────────────────────────────────────────────────────────
def test_build_moe_config_from_names_adds_routing():
    cfg = m.build_moe_config(["crucible-slm-inject", "crucible-slm-jailbreak"], "phi3")
    assert cfg["base_model"] == "phi3" and cfg["gate_mode"] == "hidden"
    assert len(cfg["experts"]) == 2
    # family keyword → routing prompts
    inject = cfg["experts"][0]
    assert inject["source_model"] == "crucible-slm-inject"
    assert any("instruction" in p for p in inject["positive_prompts"])


def test_build_moe_config_respects_explicit_prompts():
    cfg = m.build_moe_config(
        [{"source_model": "expA", "positive_prompts": ["custom route"]}], "base")
    assert cfg["experts"][0]["positive_prompts"] == ["custom route"]


# ── weight merge config ──────────────────────────────────────────────────────
def test_build_merge_config_weights_normalise():
    cfg = m.build_merge_config(["a", "b", "c", "d"], "ties", base_model="base")
    assert cfg["merge_method"] == "ties"
    assert len(cfg["models"]) == 4
    assert round(sum(b["parameters"]["weight"] for b in cfg["models"]), 2) == 1.0


def test_slerp_adds_t_parameter():
    cfg = m.build_merge_config(["a", "b"], "slerp")
    assert cfg["parameters"]["t"] == 0.5


def test_unknown_method_raises():
    import pytest
    with pytest.raises(ValueError):
        m.build_merge_config(["a"], "not-a-method")


# ── render / write (JSON is valid YAML for mergekit) ─────────────────────────
def test_render_config_is_valid_json_yaml():
    cfg = m.build_moe_config(["x", "y"], "base")
    loaded = json.loads(m.render_config(cfg))       # JSON parses ⇒ valid YAML
    assert loaded["experts"][0]["source_model"] == "x"


def test_write_config(tmp_path):
    p = str(tmp_path / "cfg.yaml")
    m.write_config(m.build_moe_config(["x"], "base"), p)
    assert json.loads(open(p, encoding="utf-8").read())["base_model"] == "base"


# ── env probe + guarded run ──────────────────────────────────────────────────
def test_check_env_wellformed(monkeypatch):
    # Environment-agnostic: well-formed dict, never raises, ok never True w/o torch.
    env = m.check_env()
    assert isinstance(env["ok"], bool) and isinstance(env["missing"], list)
    assert (not env["ok"]) or env.get("torch") is True
    import importlib
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(m.shutil, "which", lambda name: None)
    env2 = m.check_env()
    assert env2["ok"] is False and "torch" in env2["missing"]


def test_run_merge_dry_run_builds_command():
    r = m.run_merge("cfg.yaml", "out", moe=True, dry_run=True)
    assert r["ok"] is True and "mergekit-moe" in r["cmd"]


def test_run_merge_guarded_without_mergekit(tmp_path):
    r = m.run_merge(str(tmp_path / "c.yaml"), str(tmp_path / "o"), moe=False)
    assert r["ok"] is False and "cmd" in r          # no mergekit/torch → not run, no crash


def test_merge_experts_dry_run_writes_config(tmp_path):
    r = m.merge_experts(["crucible-slm-inject", "crucible-slm-jb"], "phi3",
                        out_dir=str(tmp_path / "merged"), method="moe", dry_run=True)
    assert r["ok"] is True and r["method"] == "moe"
    assert json.loads(open(r["config_path"], encoding="utf-8").read())["gate_mode"] == "hidden"
