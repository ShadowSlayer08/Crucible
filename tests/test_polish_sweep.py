"""Polish sweep — G3 OWASP-Agentic map, E4 export-history."""
import csv

import owasp_agentic as oa
import trend


# ── G3: OWASP Agentic threat map ──────────────────────────────────────────────

def test_fifteen_threats_defined():
    assert set(oa.AGENTIC_THREATS) == {f"T{i}" for i in range(1, 16)}


def test_privilege_maps_to_t3():
    t = oa.enrich_agentic({"category": "RBAC", "name": "Self role escalation", "tags": ["rbac"]})
    assert t["agentic_id"] == "T3"


def test_memory_maps_to_t1():
    t = oa.enrich_agentic({"category": "Agent Memory Manipulation",
                           "name": "false fact injection", "tags": ["memory-poison"]})
    assert t["agentic_id"] == "T1"


def test_non_agentic_test_unmapped():
    t = oa.enrich_agentic({"category": "Prompt Injection", "name": "Direct Override", "tags": []})
    assert "agentic_id" not in t


def test_agentic_coverage_counts():
    results = [
        {"test": oa.enrich_agentic({"category": "RBAC", "name": "escalate", "tags": ["rbac"]}),
         "result": {"verdict": "FAIL"}},
        {"test": oa.enrich_agentic({"category": "Tool Hijacking", "name": "tool call", "tags": ["tool"]}),
         "result": {"verdict": "PASS"}},
    ]
    cov = oa.agentic_coverage(results)
    assert cov["T3"]["fail"] == 1
    assert "T2" in cov


# ── E4: run-history CSV export ────────────────────────────────────────────────

def _scores(score):
    return {"overall_risk_score": score, "risk_level": "LOW",
            "totals": {"pass": 1, "fail": 0, "warn": 0, "error": 0}}


def test_export_history_csv(tmp_path):
    db = str(tmp_path / "h.db")
    cfg = {"schema": "openai", "model": "m", "endpoint": "https://x"}
    trend.save_run(cfg, "vapt", _scores(10), db_path=db, timestamp="2026-01-01T10:00:00")
    trend.save_run(cfg, "vapt", _scores(40), db_path=db, timestamp="2026-01-02T10:00:00")
    out = tmp_path / "hist.csv"
    n = trend.export_history_csv(str(out), db_path=db)
    assert n == 2
    rows = list(csv.reader(out.open(encoding="utf-8")))
    assert rows[0][0] == "id"          # header
    assert len(rows) == 3              # header + 2
    assert "framework" in rows[0] and "duration" in rows[0]
