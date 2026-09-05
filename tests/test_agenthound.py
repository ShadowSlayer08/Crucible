"""Tests for agenthound.py — the AgentHound infra-recon bridge.

The Go binary is never run here (offensive + needs authorized infra); we exercise
the pure parsing + endpoint-mapping + report against representative scan JSON, and
verify the guards when the binary is absent.
"""
import json

import agenthound


# A representative `agenthound scan --json` document (canonical key names).
SAMPLE = {
    "services": [
        {"type": "ollama", "url": "http://10.0.0.5:11434", "auth": "none",
         "models": ["llama3", "mistral"]},
        {"type": "litellm", "url": "http://10.0.0.6:4000/", "auth": "key"},
        {"type": "mcp", "url": "http://10.0.0.7:8080", "auth": "none"},
        {"type": "vllm", "url": "http://10.0.0.9:8000", "auth": "none",
         "models": ["Qwen2.5-7B"]},
        {"type": "qdrant", "url": "http://10.0.0.8:6333", "auth": "none"},
        {"type": "mlflow", "url": "http://10.0.0.10:5000", "auth": "none"},
    ],
    "findings": [
        {"id": "AH-001", "severity": "high", "title": "Unauthenticated Ollama server",
         "service": "ollama", "url": "http://10.0.0.5:11434",
         "detail": "Anonymous inference + model pull permitted"},
        {"id": "AH-002", "severity": "critical", "title": "LiteLLM master key in env",
         "service": "litellm", "detail": "credential recoverable via /health"},
        {"id": "AH-003", "severity": "medium", "title": "Qdrant collection exfil",
         "service": "qdrant", "detail": "vector store exfil without auth"},
    ],
    "attack_paths": [
        {"from": "anon", "to": "ollama", "via": "unauth", "impact": "model exfiltration"},
        {"from": "litellm", "to": "openai", "via": "credential", "impact": "billed abuse"},
    ],
}


def test_parse_counts():
    p = agenthound.parse(SAMPLE)
    assert p["stats"]["services"] == 6
    assert p["stats"]["findings"] == 3
    assert p["stats"]["attack_paths"] == 2
    # ollama, litellm, mcp, vllm are LLM/agent surfaces; qdrant + mlflow are not
    assert p["stats"]["llm_endpoints"] == 4


def test_parse_findings_are_tagged():
    p = agenthound.parse(SAMPLE)
    by_id = {f["id"]: f for f in p["findings"]}
    assert by_id["AH-001"]["severity"] == "HIGH"
    assert by_id["AH-002"]["severity"] == "CRITICAL"
    # every finding carries ATLAS + OWASP tags
    for f in p["findings"]:
        assert f["atlas_id"].startswith("AML.T")
        assert f["owasp_id"].startswith("LLM")
    # credential finding maps to the credential ATLAS technique
    assert by_id["AH-002"]["atlas_id"] == "AML.T0055"


def test_to_targets_maps_schemas_and_excludes_infra():
    tgts = agenthound.to_targets(agenthound.parse(SAMPLE))
    by_svc = {t["service"]: t for t in tgts}
    # infra-only stores excluded
    assert "qdrant" not in by_svc and "mlflow" not in by_svc
    # schema mapping
    assert by_svc["ollama"]["schema"] == "ollama"
    assert by_svc["litellm"]["schema"] == "openai"
    assert by_svc["vllm"]["schema"] == "openai"
    assert by_svc["mcp"]["schema"] == "openai"
    # suggested mode per surface
    assert by_svc["mcp"]["suggested_mode"] == "mcp"
    assert by_svc["ollama"]["suggested_mode"] == "vapt"
    # trailing slash stripped, model surfaced
    assert by_svc["litellm"]["endpoint"] == "http://10.0.0.6:4000"
    assert by_svc["ollama"]["model"] == "llama3"
    # auth surfaced
    assert by_svc["ollama"]["auth"] == "unauthenticated"
    assert by_svc["litellm"]["auth"] == "key"


def test_to_targets_dedupes_urls():
    dup = {"services": [
        {"type": "ollama", "url": "http://x:11434"},
        {"type": "ollama", "url": "http://x:11434/"},
    ]}
    assert len(agenthound.to_targets(agenthound.parse(dup))) == 1


def test_parse_tolerates_variant_keys():
    variant = {
        "nodes": [{"kind": "vllm", "endpoint": "http://a:8000", "authn": "none"}],
        "issues": [{"name": "exposed", "risk": "low", "description": "x"}],
        "paths": [{"a": 1}],
    }
    p = agenthound.parse(variant)
    assert p["stats"]["services"] == 1
    assert p["endpoints"][0]["type"] == "vllm"
    assert p["endpoints"][0]["url"] == "http://a:8000"
    assert p["findings"][0]["title"] == "exposed"
    assert p["stats"]["attack_paths"] == 1


def test_parse_from_path(tmp_path):
    fp = tmp_path / "scan.json"
    fp.write_text(json.dumps(SAMPLE), encoding="utf-8")
    p = agenthound.parse(str(fp))
    assert p["stats"]["llm_endpoints"] == 4


def test_parse_empty_and_junk():
    assert agenthound.parse({})["stats"]["services"] == 0
    assert agenthound.parse(None)["stats"]["services"] == 0
    # non-dict entries are skipped, not fatal
    p = agenthound.parse({"services": ["nope", 3, {"type": "ollama", "url": "http://y:1"}]})
    assert p["stats"]["services"] == 1


def test_run_scan_guarded_without_binary():
    # A binary name that certainly isn't installed → graceful failure, no raise.
    res = agenthound.run_scan("10.0.0.0/24", binary="agenthound-does-not-exist-xyz")
    assert res["ok"] is False
    assert "not on PATH" in res["reason"]


def test_print_recon_report_smoke(capsys):
    agenthound.print_recon_report(agenthound.parse(SAMPLE))
    out = capsys.readouterr().out
    assert "INFRASTRUCTURE RECON" in out
    assert "behavioural targets" in out
    assert "10.0.0.5:11434" in out          # discovered endpoint listed
    assert "Unauthenticated Ollama server" in out
