"""Tests for the FastAPI REST wrapper (server.py).

Exercises every endpoint via fastapi.testclient.TestClient. The /scan tests
use dry_run so NO network call is ever made — pure, deterministic, offline.
"""
import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")  # TestClient transport dependency

from fastapi.testclient import TestClient

import server


@pytest.fixture(scope="module")
def client():
    return TestClient(server.create_app())


# ── /health ────────────────────────────────────────────────────────────────
def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"] == server.API_VERSION
    assert body["schemas"] >= 1
    assert body["modes"] >= 1


# ── /schemas ───────────────────────────────────────────────────────────────
def test_schemas_lists_engine_schemas(client):
    import engine
    r = client.get("/schemas")
    assert r.status_code == 200
    body = r.json()
    names = {s["name"] for s in body["schemas"]}
    assert names == set(engine.SCHEMAS.keys())
    assert body["count"] == len(engine.SCHEMAS)
    # notes are surfaced for the dashboard
    assert all("notes" in s for s in body["schemas"])


# ── /modes ─────────────────────────────────────────────────────────────────
def test_modes_includes_core_and_expanded(client):
    r = client.get("/modes")
    assert r.status_code == 200
    body = r.json()
    names = {m["name"] for m in body["modes"]}
    # core modes
    assert {"vapt", "redteam"} <= names
    # expanded modes are wired in too
    assert {"mcp", "agentic", "rag", "swarm", "policy", "benign", "obfuscation"} <= names
    assert all(m["test_count"] >= 1 for m in body["modes"])


def test_redteam_superset_of_vapt(client):
    """redteam pool = vapt + redteam, so it must be larger than vapt alone."""
    modes = {m["name"]: m["test_count"] for m in client.get("/modes").json()["modes"]}
    assert modes["redteam"] > modes["vapt"]


# ── /tests ─────────────────────────────────────────────────────────────────
def test_tests_default_mode(client):
    r = client.get("/tests")  # defaults to vapt
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "vapt"
    assert body["count"] == len(body["tests"])
    assert body["count"] >= 1


def test_tests_explicit_mode_shape(client):
    r = client.get("/tests", params={"mode": "redteam"})
    assert r.status_code == 200
    sample = r.json()["tests"][0]
    # public projection includes the schema fields, no private keys leak
    for key in ("id", "category", "severity", "name", "payload", "expected", "tags"):
        assert key in sample
    assert "_source" not in sample


def test_tests_unknown_mode_404(client):
    r = client.get("/tests", params={"mode": "does-not-exist"})
    assert r.status_code == 404


# ── /scan (dry run — no network) ───────────────────────────────────────────
def test_scan_dry_run_returns_count_and_cost(client):
    r = client.post("/scan", json={"mode": "vapt", "dry_run": True})
    assert r.status_code == 200
    body = r.json()
    assert body["dry_run"] is True
    assert body["selected_tests"] >= 1
    assert body["selected_tests"] == len(body["test_ids"])
    cost = body["cost_estimate"]
    assert cost["estimated_tokens"] > 0
    assert cost["estimated_usd"] >= 0
    # no live results in a dry run
    assert "results" not in body


def test_scan_dry_run_is_default(client):
    # omitting dry_run must NOT trigger a live call; default is True
    r = client.post("/scan", json={"mode": "vapt"})
    assert r.status_code == 200
    assert r.json()["dry_run"] is True


def test_scan_dry_run_with_filters(client):
    r = client.post("/scan", json={
        "mode": "redteam",
        "dry_run": True,
        "severities": ["Critical"],
        "limit": 3,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["selected_tests"] <= 3


def test_scan_filters_can_empty_select_400(client):
    r = client.post("/scan", json={
        "mode": "vapt",
        "dry_run": True,
        "categories": ["NoSuchCategory"],
    })
    assert r.status_code == 400


def test_scan_unknown_mode_404(client):
    r = client.post("/scan", json={"mode": "nope", "dry_run": True})
    assert r.status_code == 404


def test_scan_live_without_endpoint_400(client):
    # dry_run=false but no endpoint → rejected before any network attempt
    r = client.post("/scan", json={
        "mode": "vapt",
        "dry_run": False,
        "config": {"endpoint": ""},
    })
    assert r.status_code == 400


def test_scan_accepts_schema_alias(client):
    # config.schema (alias) must populate without error
    r = client.post("/scan", json={
        "mode": "vapt",
        "dry_run": True,
        "config": {"schema": "anthropic", "model": "claude-3"},
    })
    assert r.status_code == 200


# ── root dashboard ─────────────────────────────────────────────────────────
def test_index_serves_dashboard(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "AI Red Team" in r.text


# ── helper-level checks (pure functions) ───────────────────────────────────
def test_estimate_cost_is_pure_arithmetic():
    tests = [{"payload": "one two three four five"}, {"payload": "a b"}]
    cost = server._estimate_cost(tests)
    assert cost["prompt_tokens"] > 0
    assert cost["response_tokens"] == len(tests) * server._AVG_RESPONSE_TOKENS
    assert cost["estimated_tokens"] == cost["prompt_tokens"] + cost["response_tokens"]


def test_run_requires_uvicorn(monkeypatch):
    """server.run() must raise a clear RuntimeError if uvicorn is absent —
    and never at import time."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "uvicorn":
            raise ImportError("no uvicorn")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(RuntimeError, match="uvicorn"):
        server.run()
