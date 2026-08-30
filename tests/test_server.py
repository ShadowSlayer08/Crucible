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


# ── CORS ───────────────────────────────────────────────────────────────────
def test_cors_headers_present(client):
    """The dashboard / React dev server call cross-origin, so CORS must be on."""
    r = client.get("/health", headers={"Origin": "http://localhost:5173"})
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "*"


# ── live /scan (engine mocked → no network) ────────────────────────────────
def _fake_refusal(config, test):
    """Stand-in for engine.run_test: always returns a clean refusal."""
    return {"verdict": "OK", "response_text": "I can't help with that request.",
            "status_code": 200, "latency_ms": 1}


def test_scan_live_returns_enriched_summary(client, monkeypatch):
    monkeypatch.setattr(server.engine, "run_test", _fake_refusal)
    r = client.post("/scan", json={
        "mode": "policy", "dry_run": False, "limit": 3,
        "config": {"endpoint": "http://mock.local", "schema": "openai", "model": "m"},
    })
    assert r.status_code == 200
    body = r.json()
    assert body["dry_run"] is False
    assert body["selected_tests"] == 3
    # enriched summary blocks are all present
    for key in ("scores", "asr", "coverage", "owasp", "guardrails", "results"):
        assert key in body
    assert body["scores"]["totals"]["pass"] == 3          # all refusals → PASS
    assert body["asr"]["n"] == 3 and body["asr"]["asr"] == 0.0
    assert body["coverage"]["total"] == 14                # Llama-Guard S1..S14
    assert len(body["results"]) == 3


# ── /scan/stream (SSE) ─────────────────────────────────────────────────────
def test_scan_stream_requires_live_config(client):
    # dry_run True → streaming is rejected (nothing to stream)
    r = client.post("/scan/stream", json={"mode": "vapt", "dry_run": True})
    assert r.status_code == 400
    # dry_run False but no endpoint → also rejected
    r2 = client.post("/scan/stream", json={
        "mode": "vapt", "dry_run": False, "config": {"endpoint": ""}})
    assert r2.status_code == 400


def test_scan_stream_emits_test_and_done_events(client, monkeypatch):
    monkeypatch.setattr(server.engine, "run_test", _fake_refusal)
    r = client.post("/scan/stream", json={
        "mode": "policy", "dry_run": False, "limit": 2,
        "config": {"endpoint": "http://mock.local", "schema": "openai", "model": "m"},
    })
    assert r.status_code == 200
    assert "text/event-stream" in r.headers["content-type"]
    body = r.text
    assert body.count("event: test") == 2      # one per test
    assert body.count("event: done") == 1       # single final summary
    # the done payload carries the full summary
    done_blob = body.split("event: done", 1)[1]
    assert '"scores"' in done_blob and '"asr"' in done_blob and '"guardrails"' in done_blob


# ── helper units ───────────────────────────────────────────────────────────
def test_enrich_populates_framework_tags():
    enriched = server._enrich([{"id": "X-1", "category": "Test", "severity": "High",
                                "name": "n", "payload": "p", "expected": "refusal", "tags": []}])
    assert "atlas_tactic" in enriched[0]      # ATLAS enrichment ran


def test_summary_excludes_errors_from_asr_denominator():
    results = [
        {"test": {"category": "c", "severity": "High"},
         "result": {"verdict": "FAIL", "response_text": ""}},
        {"test": {"category": "c", "severity": "High"},
         "result": {"verdict": "ERROR", "response_text": ""}},
    ]
    s = server._summary(results)
    # 1 FAIL + 1 ERROR → denominator excludes the ERROR ⇒ n == 1, ASR == 100%
    assert s["asr"]["n"] == 1
    assert s["asr"]["asr"] == 100.0


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
