"""
Tests for embeddings.py — semantic diversity via bge-m3 + pure-Python DBSCAN.

The math (cosine / _dbscan) and the clustering/dedup logic are exercised with
hand-built vectors and an injected fake `embed_fn`, so the bulk of the suite runs
with NO network. One integration test hits a live Ollama server if bge-m3 is
present and pytest.skip()s otherwise.
"""
import math

import pytest

import embeddings


# ── cosine ────────────────────────────────────────────────────────────────────

def test_cosine_identical_is_one():
    assert embeddings.cosine([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]) == pytest.approx(1.0)


def test_cosine_orthogonal_is_zero():
    assert embeddings.cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)


def test_cosine_opposite_is_minus_one():
    assert embeddings.cosine([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(-1.0)


def test_cosine_scale_invariant():
    # Direction, not magnitude — a scaled copy is still perfectly similar.
    assert embeddings.cosine([1.0, 1.0], [5.0, 5.0]) == pytest.approx(1.0)


def test_cosine_zero_vector_returns_zero():
    assert embeddings.cosine([0.0, 0.0], [1.0, 2.0]) == 0.0


def test_cosine_known_angle():
    # 45 degrees between (1,0) and (1,1) → cos = 1/sqrt(2).
    assert embeddings.cosine([1.0, 0.0], [1.0, 1.0]) == pytest.approx(1 / math.sqrt(2))


# ── _dbscan ───────────────────────────────────────────────────────────────────

# Two tight angular clusters near the x- and y-axes, plus one point on a third,
# orthogonal axis that is cosine-distance ~1.0 from every other vector → noise.
_A1 = [1.0, 0.0, 0.0]
_A2 = [0.98, 0.20, 0.0]   # ~11° from _A1  → cosine distance ~0.02
_B1 = [0.0, 1.0, 0.0]
_B2 = [0.20, 0.98, 0.0]   # ~11° from _B1
_NOISE = [0.0, 0.0, 1.0]  # orthogonal to every other vector → distance ~1.0 > eps


def test_dbscan_empty_returns_empty():
    assert embeddings._dbscan([]) == []


def test_dbscan_two_clusters_and_noise():
    labels = embeddings._dbscan([_A1, _A2, _B1, _B2, _NOISE], eps=0.25, min_samples=2)
    # Two axis pairs cluster; the 45° point is noise.
    assert labels[0] == labels[1] and labels[0] != -1
    assert labels[2] == labels[3] and labels[2] != -1
    assert labels[0] != labels[2]
    assert labels[4] == -1
    assert len({lab for lab in labels if lab != -1}) == 2


def test_dbscan_all_identical_single_cluster():
    labels = embeddings._dbscan([[1.0, 0.0]] * 4, eps=0.25, min_samples=2)
    assert labels == [0, 0, 0, 0]


def test_dbscan_all_isolated_all_noise():
    # Three mutually-orthogonal vectors: none has a neighbour within eps.
    labels = embeddings._dbscan(
        [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
        eps=0.25, min_samples=2,
    )
    assert labels == [-1, -1, -1]


# ── semantic_diversity (injected fake embed_fn — no network) ──────────────────

_FAKE_VECS = {
    "attack_a1": _A1,
    "attack_a2": _A2,
    "attack_b1": _B1,
    "attack_b2": _B2,
    "attack_novel": _NOISE,
}


def _fake_embed(texts, **_kw):
    return [_FAKE_VECS[t] for t in texts]


def test_semantic_diversity_counts_clusters_plus_noise():
    payloads = ["attack_a1", "attack_a2", "attack_b1", "attack_b2", "attack_novel"]
    out = embeddings.semantic_diversity(payloads, embed_fn=_fake_embed)
    # 2 clusters + 1 noise point = 3 distinct strategies over 5 payloads.
    assert out["n_strategies"] == 3
    assert out["diversity"] == 0.6
    assert out["method"] == "embedding-dbscan"


def test_semantic_diversity_empty_corpus():
    out = embeddings.semantic_diversity([])
    assert out == {"n_strategies": 0, "diversity": 0.0, "method": "empty"}
    # Non-strings / blanks are filtered out and also yield the empty result.
    assert embeddings.semantic_diversity([None, 42, "   "])["method"] == "empty"


def test_semantic_diversity_backend_failure_degrades():
    def boom(_texts, **_kw):
        raise RuntimeError("ollama down")

    out = embeddings.semantic_diversity(["a", "b"], embed_fn=boom)
    assert out == {"n_strategies": 0, "diversity": 0.0, "method": "unavailable"}


def test_semantic_diversity_mismatched_vector_count_degrades():
    # embed_fn returns the wrong number of vectors → treated as unavailable.
    out = embeddings.semantic_diversity(["a", "b", "c"], embed_fn=lambda t, **k: [[1.0]])
    assert out["method"] == "unavailable"


# ── dedupe (injected fake embed_fn — no network) ──────────────────────────────

def test_dedupe_drops_near_identical():
    # a1/a2 are ~0.99 similar (>= 0.92) → a2 dropped; b1 is distinct → kept.
    out = embeddings.dedupe(
        ["attack_a1", "attack_a2", "attack_b1"],
        embed_fn=_fake_embed, threshold=0.92,
    )
    assert out == ["attack_a1", "attack_b1"]


def test_dedupe_keeps_distinct():
    out = embeddings.dedupe(
        ["attack_a1", "attack_b1", "attack_novel"],
        embed_fn=_fake_embed, threshold=0.92,
    )
    assert out == ["attack_a1", "attack_b1", "attack_novel"]


def test_dedupe_single_or_empty_passthrough():
    assert embeddings.dedupe([]) == []
    assert embeddings.dedupe(["only one"]) == ["only one"]


def test_dedupe_backend_failure_returns_input():
    def boom(_texts, **_kw):
        raise RuntimeError("ollama down")

    payloads = ["one", "two", "three"]
    assert embeddings.dedupe(payloads, embed_fn=boom) == payloads


# ── available() is guarded ─────────────────────────────────────────────────────

def test_available_never_raises_on_bad_url():
    # Unroutable port → guarded probe returns False rather than raising.
    assert embeddings.available(url="http://127.0.0.1:0") is False


# ── live integration (skips when the server/model is absent) ───────────────────

def test_ollama_embed_live_or_skip():
    if not embeddings.available():
        pytest.skip("Ollama bge-m3 not available on localhost:11434")
    vecs = embeddings.ollama_embed(["hello world", "second string", "third one"])
    assert len(vecs) == 3
    dim = len(vecs[0])
    assert dim > 0
    assert all(len(v) == dim for v in vecs)
    # Sanity: a string is more similar to itself than to a different one.
    again = embeddings.ollama_embed(["hello world"])[0]
    assert embeddings.cosine(vecs[0], again) > embeddings.cosine(vecs[0], vecs[1])
