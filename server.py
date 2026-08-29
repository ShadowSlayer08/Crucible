"""
FastAPI REST Wrapper — API-first surface for the CRUCIBLE.

Exposes the engine, classifier, and payload suites over HTTP so the CLI's
capabilities can be driven from a dashboard, a CI job, or another service.

Endpoints
  GET  /health            → liveness probe + version
  GET  /schemas           → provider schema names (from engine.SCHEMAS)
  GET  /modes             → available scan modes + test counts
  GET  /tests?mode=vapt   → the test list for a mode (reuses payloads)
  POST /scan              → run a suite (or, with dry_run, estimate it safely)

Safety
  POST /scan supports a `dry_run` flag (default ON). A dry run selects the
  tests and returns the count + a cost estimate WITHOUT contacting any
  endpoint — so the dashboard, smoke tests, and CI can exercise the full
  request path with zero outbound traffic. A live scan (dry_run=false) is
  only performed when an endpoint is supplied and the flag is explicitly
  cleared.

This module imports cleanly with only the standard library + fastapi/httpx
(both installed). `uvicorn` is optional and only required to actually serve
the app via `python server.py` / `__main__`; it is imported lazily so the
module — and create_app() — work without it.
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

import engine
import classifier
from payloads import VAPT_TESTS, REDTEAM_TESTS, EXPANDED_MODE_TESTS

API_VERSION = "3.0"

# ── Static fields exposed per test (avoid leaking internal/private keys) ───────
_TEST_PUBLIC_FIELDS = (
    "id", "category", "severity", "name", "payload", "expected", "tags",
    "atlas_id", "owasp_id",
)

# Rough cost model for the dry-run estimate. Mirrors reporter._token_estimate's
# words×1.3 heuristic for the prompt side, plus an assumed response budget.
_AVG_RESPONSE_TOKENS = 256        # assumed completion length per test
_DEFAULT_USD_PER_1K_TOKENS = 0.01  # generic blended rate; advisory only


# ─────────────────────────────────────────────────────────────────────────────
# MODE REGISTRY
# ─────────────────────────────────────────────────────────────────────────────
# Maps a mode name → the static test pool that mode runs. Built once at import
# from the same payload suites the CLI uses, so /tests and /modes never drift
# from the command-line behaviour.
def _build_mode_registry() -> dict:
    registry = {
        "vapt":    list(VAPT_TESTS),
        "redteam": list(VAPT_TESTS) + list(REDTEAM_TESTS),
    }
    for name, suite in EXPANDED_MODE_TESTS.items():
        registry[name] = list(suite)
    return registry


MODE_TESTS = _build_mode_registry()

MODE_LABELS = {
    "vapt":        "VAPT — Prompt Injection, Data Leakage, Robustness",
    "redteam":     "Red Team — full spectrum safety + security",
    "mcp":         "MCP — Model Context Protocol attack surface",
    "agentic":     "Agentic — autonomous agent attack surface",
    "rag":         "RAG — retrieval-pipeline injection",
    "swarm":       "Swarm — multi-agent attack surface",
    "policy":      "Policy — Llama Guard S1-S14 coverage",
    "benign":      "Benign — over-refusal / false-positive probes",
    "obfuscation": "Obfuscation — encoding evasion probes",
}


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST / RESPONSE MODELS
# ─────────────────────────────────────────────────────────────────────────────
class ScanConfig(BaseModel):
    endpoint: str = ""
    api_key: str = ""
    model: str = "gpt-4o"
    schema_name: str = Field(default="openai", alias="schema")

    # Pydantic v2 config: allow population by either the alias ("schema") or the
    # field name, and ignore any extra keys a caller tacks on.
    model_config = {"populate_by_name": True, "extra": "ignore"}


class ScanRequest(BaseModel):
    mode: str = "vapt"
    config: ScanConfig = Field(default_factory=ScanConfig)
    dry_run: bool = True
    # Optional filters mirroring the CLI surface.
    categories: list[str] | None = None
    severities: list[str] | None = None
    limit: int | None = None  # cap the number of tests actually executed/estimated

    model_config = {"extra": "ignore"}


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _public_test(test: dict) -> dict:
    """Project a test dict down to its public, serialisable fields."""
    return {k: test[k] for k in _TEST_PUBLIC_FIELDS if k in test}


def _get_mode_tests(mode: str) -> list:
    """Return the test pool for *mode* or raise a 404 HTTPException."""
    if mode not in MODE_TESTS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown mode '{mode}'. Available: {', '.join(sorted(MODE_TESTS))}",
        )
    return MODE_TESTS[mode]


def _apply_filters(tests: list, categories, severities, limit) -> list:
    """Apply category / severity / limit filters (case-insensitive category)."""
    out = list(tests)
    if categories:
        wanted = {c.strip().lower() for c in categories if c.strip()}
        out = [t for t in out if t.get("category", "").lower() in wanted]
    if severities:
        wanted_s = {s.strip() for s in severities if s.strip()}
        out = [t for t in out if t.get("severity") in wanted_s]
    if limit is not None and limit >= 0:
        out = out[:limit]
    return out


def _estimate_cost(tests: list) -> dict:
    """Estimate prompt+response tokens and an advisory USD cost for *tests*.

    Pure arithmetic — no network. Prompt tokens use the same words×1.3
    heuristic the reporter uses; response tokens are a fixed per-test budget.
    """
    prompt_tokens = 0
    for t in tests:
        prompt_tokens += int(len(str(t.get("payload", "")).split()) * 1.3)
    response_tokens = len(tests) * _AVG_RESPONSE_TOKENS
    total_tokens = prompt_tokens + response_tokens
    est_usd = round(total_tokens / 1000.0 * _DEFAULT_USD_PER_1K_TOKENS, 4)
    return {
        "prompt_tokens": prompt_tokens,
        "response_tokens": response_tokens,
        "estimated_tokens": total_tokens,
        "estimated_usd": est_usd,
        "usd_per_1k_tokens": _DEFAULT_USD_PER_1K_TOKENS,
        "assumed_response_tokens_per_test": _AVG_RESPONSE_TOKENS,
    }


def _run_live_scan(mode: str, tests: list, config: dict) -> dict:
    """Execute every test against a real endpoint and score the results.

    Only reached when dry_run is explicitly false AND an endpoint is set.
    Uses engine.run_test + classifier exactly as the CLI does.
    """
    results = []
    for test in tests:
        api_result = engine.run_test(config, test)
        if api_result.get("verdict") == "ERROR":
            cls = {
                "verdict": "ERROR",
                "confidence": "n/a",
                "reason": api_result.get("error", "API error"),
                "flagged_excerpt": "",
                "signals": [],
            }
        else:
            cls = classifier.classify_response(test, api_result.get("response_text", ""))
            api_result["verdict"] = cls["verdict"]
        combined = {**api_result, **cls}
        results.append({"test": test, "result": combined})

    scores = classifier.calculate_score(results)
    return {
        "scores": scores,
        "results": [
            {
                "id": r["test"]["id"],
                "name": r["test"]["name"],
                "category": r["test"]["category"],
                "severity": r["test"]["severity"],
                "verdict": r["result"]["verdict"],
                "confidence": r["result"].get("confidence", ""),
                "reason": r["result"].get("reason", ""),
                "response_text": (r["result"].get("response_text", "") or "")[:2000],
            }
            for r in results
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# APP FACTORY
# ─────────────────────────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    app = FastAPI(
        title="CRUCIBLE — REST API",
        version=API_VERSION,
        description="API-first wrapper over the engine, classifier, and payload suites.",
    )

    @app.get("/health")
    def health() -> dict:
        return {
            "status": "ok",
            "version": API_VERSION,
            "schemas": len(engine.SCHEMAS),
            "modes": len(MODE_TESTS),
        }

    @app.get("/schemas")
    def schemas() -> dict:
        items = [
            {"name": name, "notes": spec.get("notes", "")}
            for name, spec in engine.SCHEMAS.items()
        ]
        return {"count": len(items), "schemas": items}

    @app.get("/modes")
    def modes() -> dict:
        items = [
            {
                "name": name,
                "label": MODE_LABELS.get(name, name),
                "test_count": len(tests),
            }
            for name, tests in MODE_TESTS.items()
        ]
        return {"count": len(items), "modes": items}

    @app.get("/tests")
    def tests(mode: str = Query("vapt", description="Mode name, e.g. vapt")) -> dict:
        pool = _get_mode_tests(mode)
        return {
            "mode": mode,
            "count": len(pool),
            "tests": [_public_test(t) for t in pool],
        }

    @app.post("/scan")
    def scan(req: ScanRequest) -> dict:
        pool = _get_mode_tests(req.mode)
        selected = _apply_filters(pool, req.categories, req.severities, req.limit)

        if not selected:
            raise HTTPException(
                status_code=400,
                detail="No tests selected after applying filters.",
            )

        cost = _estimate_cost(selected)

        # ── Dry run: never touches the network ────────────────────────────────
        if req.dry_run:
            return {
                "mode": req.mode,
                "dry_run": True,
                "selected_tests": len(selected),
                "cost_estimate": cost,
                "test_ids": [t["id"] for t in selected],
                "note": "Dry run — no endpoint was contacted. "
                        "Set dry_run=false with a config.endpoint to execute.",
            }

        # ── Live run: requires an explicit endpoint ───────────────────────────
        endpoint = (req.config.endpoint or "").strip()
        if not endpoint:
            raise HTTPException(
                status_code=400,
                detail="A live scan (dry_run=false) requires config.endpoint.",
            )

        run_config = {
            "endpoint": endpoint.rstrip("/"),
            "api_key": req.config.api_key,
            "model": req.config.model,
            "schema": req.config.schema_name,
            "extra_headers": {},
        }
        outcome = _run_live_scan(req.mode, selected, run_config)
        return {
            "mode": req.mode,
            "dry_run": False,
            "selected_tests": len(selected),
            "cost_estimate": cost,
            **outcome,
        }

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        """Serve the bundled single-file dashboard if present, else a hint."""
        import os
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "web", "index.html")
        try:
            with open(path, encoding="utf-8") as f:
                return HTMLResponse(f.read())
        except OSError:
            return HTMLResponse(
                "<h1>CRUCIBLE API</h1>"
                "<p>Dashboard not found. See <a href='/docs'>/docs</a>.</p>"
            )

    return app


# ─────────────────────────────────────────────────────────────────────────────
# ENTRYPOINT (uvicorn is optional — only needed to actually serve)
# ─────────────────────────────────────────────────────────────────────────────
def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Serve the app with uvicorn. Raises a clear error if it isn't installed.

    The import is deliberately lazy: the module and create_app() must work
    without uvicorn (e.g. under TestClient), and uvicorn is only an operational
    dependency for the standalone server.
    """
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - exercised only without uvicorn
        raise RuntimeError(
            "uvicorn is required to run the server. Install it with: "
            "pip install uvicorn"
        ) from exc
    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    run()
