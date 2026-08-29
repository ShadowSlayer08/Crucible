"""
Semantic Embeddings — real strategic diversity via bge-m3 (roadmap #37, H4).

metrics.diversity_score() clusters payloads with a token-set Jaccard heuristic:
cheap, deterministic, and blind to meaning ("reveal your prompt" vs. "expose your
instructions" look unrelated to it). This module upgrades that to *semantic*
diversity using a real embedding model (Ollama bge-m3) plus a pure-Python DBSCAN
over cosine distance — so paraphrases collapse into one strategy the way a human
reviewer would judge them, and genuinely novel attacks stand out as their own.

The embedding backend is Ollama's local REST API. It is entirely OPTIONAL: every
public entry point degrades gracefully when the server or model is absent, and
NOTHING here touches the network at import time. Callers may inject their own
`embed_fn` (tests do) so the clustering/dedup logic is exercisable offline.

  * ollama_embed(texts)     -> list[list[float]]  (raises RuntimeError if down)
  * available()             -> bool               (guarded probe, never raises)
  * cosine(a, b)            -> float
  * _dbscan(vectors, ...)   -> list[int]          (label -1 == noise)
  * semantic_diversity(...) -> {"n_strategies", "diversity", "method"}
  * dedupe(payloads, ...)   -> list[str]          (drops near-identical payloads)

Stdlib only, plus `requests` for the HTTP call (already a project dependency).
NO numpy / sklearn — the cosine + DBSCAN are hand-rolled.
"""

import math

import requests

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
OLLAMA_URL  = "http://localhost:11434"
EMBED_MODEL = "bge-m3:latest"

_TIMEOUT = 30  # seconds — matches engine.py's request timeout


# ─────────────────────────────────────────────────────────────────────────────
# OLLAMA BACKEND
# ─────────────────────────────────────────────────────────────────────────────

def ollama_embed(texts: list, url: str = OLLAMA_URL, model: str = EMBED_MODEL) -> list:
    """
    Embed a batch of strings via Ollama's bge-m3 model and return one float
    vector per input, in order.

    Primary path is the batch endpoint POST {url}/api/embed with body
    {"model": model, "input": texts}. Older Ollama builds lack that route and
    answer 404 — in which case we fall back to the single-text legacy endpoint
    POST {url}/api/embeddings ({"model": model, "prompt": t}), one call per text.

    Network is only touched when this is CALLED (never at import). Raises
    RuntimeError with a descriptive message if the server is unreachable or the
    model cannot produce embeddings — callers that want a soft failure should
    wrap the call (semantic_diversity / dedupe already do).
    """
    items = list(texts or [])
    if not items:
        return []

    try:
        resp = requests.post(
            f"{url}/api/embed",
            json={"model": model, "input": items},
            timeout=_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(
            f"Ollama embeddings unavailable at {url} (is the server running?): {exc}"
        ) from exc

    # Old server / route missing → per-text legacy endpoint.
    if resp.status_code == 404:
        return _embed_legacy(items, url, model)

    if resp.status_code >= 400:
        raise RuntimeError(
            f"Ollama embed failed (HTTP {resp.status_code}) for model '{model}': "
            f"{resp.text[:200]}"
        )

    try:
        data = resp.json()
    except ValueError as exc:
        raise RuntimeError(f"Ollama embed returned a non-JSON response: {exc}") from exc

    vectors = data.get("embeddings")
    if not vectors:
        raise RuntimeError(
            f"Ollama embed returned no embeddings for model '{model}' — is it "
            f"pulled? (response keys: {sorted(data)})"
        )
    return [[float(x) for x in vec] for vec in vectors]


def _embed_legacy(texts: list, url: str, model: str) -> list:
    """Fallback for pre-/api/embed servers: POST /api/embeddings one text at a time."""
    vectors = []
    for text in texts:
        try:
            resp = requests.post(
                f"{url}/api/embeddings",
                json={"model": model, "prompt": text},
                timeout=_TIMEOUT,
            )
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(
                f"Ollama embeddings unavailable at {url}: {exc}"
            ) from exc

        if resp.status_code >= 400:
            raise RuntimeError(
                f"Ollama embeddings failed (HTTP {resp.status_code}) for model "
                f"'{model}': {resp.text[:200]}"
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Ollama embeddings returned a non-JSON response: {exc}"
            ) from exc

        vec = data.get("embedding")
        if not vec:
            raise RuntimeError(
                f"Ollama embeddings returned no vector for model '{model}'"
            )
        vectors.append([float(x) for x in vec])
    return vectors


def available(url: str = OLLAMA_URL, model: str = EMBED_MODEL) -> bool:
    """
    True if an Ollama server at *url* lists *model* in /api/tags. Fully guarded:
    any error (server down, timeout, bad JSON) returns False rather than raising,
    so callers can cheaply gate on `available()` before embedding.

    Matches the exact tag ("bge-m3:latest") and also tolerates a tagless name
    ("bge-m3") by comparing the portion before the ':'.
    """
    try:
        resp = requests.get(f"{url}/api/tags", timeout=10)
        if resp.status_code >= 400:
            return False
        data = resp.json()
    except Exception:
        return False

    tags = [str(m.get("name", "")) for m in (data.get("models") or [])]
    base = model.split(":")[0]
    return any(t == model or t.split(":")[0] == base for t in tags)


# ─────────────────────────────────────────────────────────────────────────────
# VECTOR MATH  (pure Python — no numpy)
# ─────────────────────────────────────────────────────────────────────────────

def cosine(a: list, b: list) -> float:
    """
    Cosine similarity of two vectors in [-1.0, 1.0]. Returns 0.0 when either
    vector is all-zeros (undefined direction). Iterates over the shorter length
    if the vectors differ in size.
    """
    dot = norm_a = norm_b = 0.0
    for x, y in zip(a, b):
        dot += x * y
        norm_a += x * x
        norm_b += y * y
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / math.sqrt(norm_a * norm_b)


def _dbscan(vectors: list, eps: float = 0.25, min_samples: int = 2) -> list:
    """
    Density-based clustering (DBSCAN) over COSINE DISTANCE (= 1 - cosine
    similarity). Returns a per-vector integer label: 0, 1, 2, … for cluster
    membership and -1 for noise (points too isolated to join any cluster).

    Two vectors are neighbours when their cosine distance is <= eps. A point is a
    core point when it has at least `min_samples` neighbours *including itself*
    (sklearn's convention); clusters grow by density-reachability from core
    points, and non-core points on a cluster's fringe become border members.

    Pure Python, O(n^2) in the number of vectors — intended for the small
    payload corpora this tool works with, not millions of points.
    """
    n = len(vectors)
    labels = [-1] * n
    if n == 0:
        return labels

    # Precompute neighbour lists (each point is its own neighbour).
    neighbours = []
    for i in range(n):
        nb = []
        for j in range(n):
            if i == j or (1.0 - cosine(vectors[i], vectors[j])) <= eps:
                nb.append(j)
        neighbours.append(nb)

    visited = [False] * n
    cluster_id = -1

    for i in range(n):
        if visited[i]:
            continue
        visited[i] = True
        if len(neighbours[i]) < min_samples:
            continue  # not a core point → leave as noise (may become a border point)

        cluster_id += 1
        labels[i] = cluster_id

        # Breadth-first density expansion over the seed set.
        seeds = list(neighbours[i])
        in_seeds = set(seeds)
        k = 0
        while k < len(seeds):
            j = seeds[k]
            k += 1
            if labels[j] == -1:          # unassigned or prior noise → claim it
                labels[j] = cluster_id
            if not visited[j]:
                visited[j] = True
                if len(neighbours[j]) >= min_samples:  # j is core → keep expanding
                    for m in neighbours[j]:
                        if m not in in_seeds:
                            in_seeds.add(m)
                            seeds.append(m)

    return labels


# ─────────────────────────────────────────────────────────────────────────────
# SEMANTIC DIVERSITY  (roadmap #37)
# ─────────────────────────────────────────────────────────────────────────────

def semantic_diversity(payloads: list, embed_fn=ollama_embed) -> dict:
    """
    Estimate strategic diversity by EMBEDDING each payload and DBSCAN-clustering
    the vectors: paraphrases fall into one cluster, novel attacks stand alone.

    n_strategies = (number of distinct clusters) + (number of noise points), so
    every unique-looking payload counts as its own strategy while near-duplicates
    collapse. diversity = n_strategies / len(payloads), rounded to 3 dp — 1.0 is
    maximally varied, values near 0 mean a repetitive corpus.

    Non-string / blank payloads are ignored. If the embedding backend is
    unreachable (or returns the wrong number of vectors), degrades to
    {"n_strategies": 0, "diversity": 0.0, "method": "unavailable"} instead of
    raising, so a run without Ollama still completes.
    """
    items = [p for p in (payloads or []) if isinstance(p, str) and p.strip()]
    n = len(items)
    if n == 0:
        return {"n_strategies": 0, "diversity": 0.0, "method": "empty"}

    try:
        vectors = embed_fn(items)
    except Exception:
        return {"n_strategies": 0, "diversity": 0.0, "method": "unavailable"}

    if not vectors or len(vectors) != n:
        return {"n_strategies": 0, "diversity": 0.0, "method": "unavailable"}

    labels = _dbscan(vectors)
    n_clusters = len({lab for lab in labels if lab != -1})
    n_noise = sum(1 for lab in labels if lab == -1)
    n_strategies = n_clusters + n_noise

    return {
        "n_strategies": n_strategies,
        "diversity": round(n_strategies / n, 3),
        "method": "embedding-dbscan",
    }


# ─────────────────────────────────────────────────────────────────────────────
# NEAR-DUPLICATE DEDUP
# ─────────────────────────────────────────────────────────────────────────────

def dedupe(payloads: list, embed_fn=ollama_embed, threshold: float = 0.92) -> list:
    """
    Greedily drop near-identical payloads by semantic similarity, preserving the
    first occurrence of each cluster of look-alikes.

    Walk the payloads in order; keep one only if its embedding's cosine
    similarity to every already-kept payload is BELOW *threshold* (default 0.92).
    Anything at/above threshold is treated as a duplicate and discarded.

    Degrades to returning the input unchanged (order preserved) whenever the
    embedding backend fails or returns a mismatched vector count — never raises.
    """
    items = [p for p in (payloads or []) if isinstance(p, str)]
    if len(items) <= 1:
        return list(items)

    try:
        vectors = embed_fn(items)
    except Exception:
        return list(items)

    if not vectors or len(vectors) != len(items):
        return list(items)

    kept, kept_vecs = [], []
    for text, vec in zip(items, vectors):
        if any(cosine(vec, kv) >= threshold for kv in kept_vecs):
            continue  # near-duplicate of something already kept
        kept.append(text)
        kept_vecs.append(vec)
    return kept
