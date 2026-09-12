"""Slice D — finish the full-stack merge: behavioural sweep of discovered endpoints,
unified infra+behaviour report, layer correlation, attack-path rendering, and the
SARIF fold-in of infra findings.

The subprocess sweep is exercised via an injected fake invoker (no live targets);
everything else is pure.
"""
import json

import agenthound
import fullstack
import reporter
import targets as targets_mod


SAMPLE = {
    "services": [
        {"type": "ollama", "url": "http://10.0.0.5:11434", "auth": "none", "models": ["llama3"]},
        {"type": "litellm", "url": "http://10.0.0.6:4000", "auth": "key"},
    ],
    "findings": [
        {"id": "AH-001", "severity": "critical", "title": "Unauth Ollama",
         "service": "ollama", "url": "http://10.0.0.5:11434", "detail": "anon pull"},
    ],
    "attack_paths": [
        {"from": "anon", "to": "ollama", "via": "unauth", "impact": "model exfiltration"},
    ],
}


def _parsed():
    return agenthound.parse(SAMPLE)


# ── D2: sweep_targets with an injected invoker ───────────────────────────────
def test_sweep_targets_uses_injected_invoker():
    parsed = _parsed()
    discovered = agenthound.to_targets(parsed)

    def fake_invoker(t):
        # ollama endpoint "breaks", litellm "holds"
        if t["service"] == "ollama":
            return {"ok": True, "summary": {"total": 10, "fails": 4, "warns": 1,
                                            "errors": 0, "asr_percent": 40.0, "risk_score": 65}}
        return {"ok": True, "summary": {"total": 10, "fails": 0, "warns": 0,
                                        "errors": 0, "asr_percent": 0.0, "risk_score": 5}}

    rows = fullstack.sweep_targets(discovered, invoker=fake_invoker)
    assert len(rows) == 2
    ollama_row = next(r for r in rows if r["service"] == "ollama")
    assert ollama_row["ok"] and ollama_row["summary"]["fails"] == 4


# ── D4: correlation (reachable AND exploitable) ──────────────────────────────
def test_correlate_escalates_unauth_and_exploitable():
    parsed = _parsed()
    rows = [
        {"target_name": "ah-ollama-1", "endpoint": "http://10.0.0.5:11434",
         "service": "ollama", "mode": "vapt", "auth": "unauthenticated", "ok": True,
         "summary": {"fails": 4}},
        {"target_name": "ah-litellm-2", "endpoint": "http://10.0.0.6:4000",
         "service": "litellm", "mode": "vapt", "auth": "key", "ok": True,
         "summary": {"fails": 0}},
    ]
    chained = fullstack.correlate(parsed, rows)
    assert len(chained) == 1                         # only the one with fails>0
    c = chained[0]
    assert c["endpoint"] == "http://10.0.0.5:11434"
    assert c["severity"] == "CRITICAL"              # unauth + exploitable
    assert "AH-001" in c["infra_findings"]          # linked back to the infra finding


def test_correlate_high_when_authenticated():
    parsed = _parsed()
    rows = [{"endpoint": "http://10.0.0.6:4000", "service": "litellm", "auth": "key",
             "ok": True, "summary": {"fails": 2}}]
    chained = fullstack.correlate(parsed, rows)
    assert chained and chained[0]["severity"] == "HIGH"   # authed → not escalated to CRITICAL


# ── D4: attack-path rendering ────────────────────────────────────────────────
def test_render_attack_paths_ascii_and_mermaid():
    g = fullstack.render_attack_paths(_parsed())
    assert g["count"] == 1
    assert "anon" in g["ascii"] and "unauth" in g["ascii"]
    assert g["mermaid"].startswith("graph LR")
    assert "-->" in g["mermaid"]


# ── D3: unified report + combined posture ────────────────────────────────────
def test_build_unified_report_posture():
    parsed = _parsed()
    rows = [{"endpoint": "http://10.0.0.5:11434", "service": "ollama",
             "auth": "unauthenticated", "ok": True, "summary": {"fails": 3}}]
    rep = fullstack.build_unified_report(parsed, rows, meta={"scope": "10.0.0.0/24"})
    assert rep["posture"]["infra_findings"] == 1
    assert rep["posture"]["behaviour_total_fails"] == 3
    assert rep["posture"]["chained_findings"] == 1
    assert rep["posture"]["combined_risk"] == "CRITICAL"   # crit infra + crit chain
    assert rep["infra"]["stats"]["services"] == 2
    assert rep["attack_path_graph"]["count"] == 1
    # no 'raw' leaks into the unified endpoints
    assert all("raw" not in e for e in rep["infra"]["endpoints"])


# ── D1: SARIF fold-in of infra findings ──────────────────────────────────────
def test_sarif_folds_infra_findings(tmp_path):
    parsed = _parsed()
    out = tmp_path / "fs.sarif"
    reporter.save_sarif([], {"endpoint": "10.0.0.0/24"}, str(out),
                        infra_findings=parsed["findings"])
    doc = json.loads(out.read_text(encoding="utf-8"))
    run = doc["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "AH-001" in rule_ids
    res = run["results"][0]
    assert res["ruleId"] == "AH-001"
    assert res["level"] == "error"                  # critical → error
    assert res["properties"]["layer"] == "infra"
    assert res["properties"]["atlas_id"].startswith("AML.T")


# ── D4: target book persists infra context ───────────────────────────────────
def test_save_target_persists_extra_context(tmp_path):
    path = str(tmp_path / "targets.yaml")
    targets_mod.save_target("ah-ollama-1", "http://10.0.0.5:11434", "llama3", "ollama",
                            path=path, extra={"service": "ollama",
                                              "suggested_mode": "vapt", "auth": "unauthenticated"})
    data = targets_mod.load_targets(path)
    rec = data["ah-ollama-1"]
    assert rec["service"] == "ollama" and rec["suggested_mode"] == "vapt"
    assert rec["auth"] == "unauthenticated"
    # core fields still intact and apply_target still works off them
    assert rec["endpoint"] == "http://10.0.0.5:11434"
