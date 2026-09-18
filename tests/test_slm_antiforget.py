"""Slice I — anti-forgetting training recipe (the critical SLM root-cause fix).

Tests the pure/stdlib parts: LoRA target resolution, the built-in replay set, replay
loading, and replay mixing. The actual fine-tune is GPU-operator (unchanged here).
"""
import json

import slm.train as train


# ── LoRA target resolution ───────────────────────────────────────────────────
def test_resolve_lora_targets_all_linear_default():
    assert train.resolve_lora_targets() == "all-linear"
    assert train.resolve_lora_targets("all-linear") == "all-linear"


def test_resolve_lora_targets_mlp_includes_mlp_layers():
    mlp = train.resolve_lora_targets("mlp")
    assert "gate_proj" in mlp and "up_proj" in mlp and "down_proj" in mlp
    assert "q_proj" in mlp                       # attention retained too


def test_resolve_lora_targets_attention_and_custom():
    assert train.resolve_lora_targets("attention") == ["q_proj", "k_proj", "v_proj", "o_proj"]
    assert train.resolve_lora_targets("q_proj, v_proj") == ["q_proj", "v_proj"]
    assert train.resolve_lora_targets("") == ["q_proj", "k_proj", "v_proj", "o_proj"]


# ── replay set + loading ─────────────────────────────────────────────────────
def test_default_replay_set_well_formed():
    rs = train.default_replay_set()
    assert len(rs) >= 20
    for e in rs:
        assert e["instruction"] and e["output"]
        assert e["meta"]["type"] == "replay"


def test_load_replay(tmp_path):
    p = tmp_path / "replay.jsonl"
    p.write_text("\n".join([
        json.dumps({"instruction": "hi", "output": "hello"}),
        "",                                      # blank skipped
        "{bad json",                             # malformed skipped
        json.dumps({"instruction": "no output"}),  # missing output skipped
    ]), encoding="utf-8")
    got = train.load_replay(str(p))
    assert len(got) == 1 and got[0]["instruction"] == "hi"
    assert train.load_replay(str(tmp_path / "missing.jsonl")) == []


# ── replay mixing (the anti-forgetting mechanism) ────────────────────────────
def _attacks(n):
    return [{"instruction": f"attack {i}", "input": "", "output": "payload",
             "meta": {"type": "attack"}} for i in range(n)]


def test_mix_replay_hits_target_ratio():
    mixed = train.mix_replay(_attacks(70), train.default_replay_set(), ratio=0.3)
    replay = [e for e in mixed if e["meta"]["type"] == "replay"]
    assert len(mixed) == 100
    assert len(replay) == 30                      # 30/100 == 0.30
    # attack examples come first and are preserved
    assert mixed[0]["meta"]["type"] == "attack"


def test_mix_replay_cycles_small_pool():
    # pool of 5 must be cycled to reach the required replay count
    mixed = train.mix_replay(_attacks(90), _attacks(5), ratio=0.5)  # need 90 replay
    replay = [e for e in mixed if e["meta"]["type"] == "replay"]
    assert len(replay) == 90 and len(mixed) == 180


def test_mix_replay_zero_ratio_is_noop():
    a = _attacks(10)
    assert train.mix_replay(a, train.default_replay_set(), ratio=0.0) == a
    assert train.mix_replay(a, [], ratio=0.3) == a          # no replay pool


def test_mix_replay_deterministic():
    r = train.default_replay_set()
    assert train.mix_replay(_attacks(40), r, 0.3, seed=7) == \
        train.mix_replay(_attacks(40), r, 0.3, seed=7)


def test_mix_replay_ratio_clamped():
    # ratio >0.9 clamps so attack examples are never fully drowned out
    mixed = train.mix_replay(_attacks(10), train.default_replay_set(), ratio=0.99)
    attack = [e for e in mixed if e["meta"]["type"] == "attack"]
    assert len(attack) == 10
    replay = len(mixed) - 10
    assert replay / len(mixed) <= 0.91
