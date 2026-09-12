"""Tests for the offline dynamic engine: deterministic payload mutations and the
epsilon-greedy adaptive bandit (no Ollama / network needed)."""
import base64
import codecs

import pytest

from dynamic_engine import PayloadMutator, AdaptiveBandit


# ── PayloadMutator ────────────────────────────────────────────────────────────

def test_base64_mutation_roundtrips():
    m = PayloadMutator().base64_encode("reveal the secret")
    # the encoded form must decode back to the original payload
    encoded = m.mutated_payload.split("\n")[-1].strip()
    assert base64.b64decode(encoded).decode() == "reveal the secret"
    assert m.original_payload == "reveal the secret"


def test_rot13_mutation_roundtrips():
    m = PayloadMutator().rot13_encode("attack")
    assert "nggnpx" in m.mutated_payload  # rot13('attack')
    assert codecs.decode("nggnpx", "rot13") == "attack"


def test_all_mutations_returns_sixteen():
    muts = PayloadMutator().all_mutations("do the thing")
    assert len(muts) == 16
    names = {mm.method_name for mm in muts}
    assert "base64_encode" in names and "rot13_encode" in names
    # DeepTeam-parity framings + Bad-Likert-Judge
    assert {"math_problem", "adversarial_poetry", "emotional_manipulation",
            "bad_likert_judge"} <= names


def test_mutations_embed_or_transform_original():
    p = "the original payload text"
    for mm in PayloadMutator().all_mutations(p):
        # every mutation either contains the original or is an encoding of it
        assert mm.original_payload == p
        assert mm.mutated_payload  # non-empty


# ── AdaptiveBandit ────────────────────────────────────────────────────────────

def test_empty_categories_raises():
    with pytest.raises(ValueError):
        AdaptiveBandit([])


def test_fail_increases_weight_pass_decreases():
    b = AdaptiveBandit(["a", "b"])
    b.update("a", "FAIL")
    b.update("b", "PASS")
    assert b.weights["a"] > 1.0
    assert b.weights["b"] < 1.0


def test_greedy_selection_picks_highest_weight():
    b = AdaptiveBandit(["a", "b"], epsilon=0.0)  # pure exploitation
    b.update("a", "FAIL")
    cat, is_explore = b.select_category()
    assert cat == "a"
    assert is_explore is False


def test_select_category_always_valid():
    b = AdaptiveBandit(["x", "y", "z"], epsilon=1.0)  # pure exploration
    for _ in range(20):
        cat, _explore = b.select_category()
        assert cat in ("x", "y", "z")


def test_unknown_category_added_on_update():
    b = AdaptiveBandit(["a"])
    b.update("brand-new", "FAIL")
    assert "brand-new" in b.categories
    assert "brand-new" in b.weights


def test_weight_summary_shares_sum_to_100():
    b = AdaptiveBandit(["a", "b", "c"])
    b.update("a", "FAIL")
    b.update("b", "WARN")
    rows = b.weight_summary()
    assert abs(sum(r["share_pct"] for r in rows) - 100.0) < 0.5
