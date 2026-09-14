"""Slice E — safety posture completion: ROE scope confinement, the engine scope
guard, the append-only audit trail, and PII/secret scrubbing of saved report bodies.
"""
import json

import audit
import engine
import reporter
import roe as roe_mod


ROE = {
    "authorized": ["10.10.0.0/16", "192.168.1.50",
                   "staging.example.com", "https://redteam.example.com"],
    "expiry": "2999-12-31", "ticket": "SEC-1", "_path": ".crucible-roe.yaml",
}


# ── ROE scope matching ───────────────────────────────────────────────────────
def test_in_scope_cidr_and_ip():
    assert roe_mod.in_scope("http://10.10.5.7:11434/v1/chat", ROE) is True   # IP in CIDR
    assert roe_mod.in_scope("192.168.1.50", ROE) is True                     # exact IP
    assert roe_mod.in_scope("http://10.99.0.1", ROE) is False                # outside CIDR


def test_in_scope_host_and_subdomain():
    assert roe_mod.in_scope("staging.example.com", ROE) is True
    assert roe_mod.in_scope("https://api.staging.example.com/x", ROE) is True  # subdomain
    assert roe_mod.in_scope("https://evil.com", ROE) is False


def test_in_scope_url_entry_compares_host():
    assert roe_mod.in_scope("https://redteam.example.com/v1/chat", ROE) is True


def test_in_scope_cidr_target_subnet():
    assert roe_mod.in_scope("10.10.1.0/24", ROE) is True      # subnet of authorized /16
    assert roe_mod.in_scope("10.0.0.0/8", ROE) is False       # superset, not contained


def test_no_roe_allows_everything():
    assert roe_mod.in_scope("https://anything.com", None) is True


def test_is_expired():
    assert roe_mod.is_expired({"expiry": "2000-01-01"}) is True
    assert roe_mod.is_expired({"expiry": "2999-01-01"}) is False
    assert roe_mod.is_expired({}) is False


def test_enforce_paths():
    ok, _ = roe_mod.enforce("https://redteam.example.com", ROE)
    assert ok is True
    ok, why = roe_mod.enforce("https://evil.com", ROE)
    assert ok is False and "OUT OF ROE SCOPE" in why
    ok, why = roe_mod.enforce("https://evil.com", ROE, override=True)
    assert ok is True and "overridden" in why.lower()
    ok, why = roe_mod.enforce("https://redteam.example.com", {**ROE, "expiry": "2000-01-01"})
    assert ok is False and "expired" in why.lower()


def test_load_roe(tmp_path):
    p = tmp_path / "roe.yaml"
    p.write_text("authorized:\n  - 10.0.0.0/24\nticket: T1\n", encoding="utf-8")
    r = roe_mod.load_roe(str(p))
    assert r and r["ticket"] == "T1" and roe_mod.in_scope("10.0.0.5", r)
    assert roe_mod.load_roe(str(tmp_path / "missing.yaml")) is None


# ── engine scope guard ───────────────────────────────────────────────────────
def test_engine_scope_guard_blocks_out_of_scope(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(engine.requests, "post",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    engine.set_scope(roe_mod.build_matcher(ROE))
    try:
        out = engine.run_test({"schema": "openai", "endpoint": "https://evil.com", "model": "m"},
                              {"payload": "hi"})
        assert out["verdict"] == "ERROR" and "out of ROE scope" in out["error"]
        assert called["n"] == 0                       # never hit the network
    finally:
        engine.set_scope(None)


def test_engine_scope_guard_allows_in_scope_and_local(monkeypatch):
    monkeypatch.setattr(engine.requests, "post",
                        lambda *a, **k: _Resp())
    engine.set_scope(roe_mod.build_matcher(ROE))
    try:
        # in-scope host resolves and fires
        out = engine.run_test({"schema": "openai", "endpoint": "https://redteam.example.com",
                               "model": "m"}, {"payload": "hi"})
        assert out["verdict"] is None and out["response_text"] == "ok"
        # localhost is always allowed even under a ROE
        out2 = engine.run_test({"schema": "ollama", "endpoint": "http://localhost:11434",
                                "model": "m"}, {"payload": "hi"})
        assert out2["verdict"] is None
    finally:
        engine.set_scope(None)


class _Resp:
    status_code = 200
    text = ""
    headers = {}

    def json(self):
        return {"choices": [{"message": {"content": "ok"}}]}


# ── audit trail ──────────────────────────────────────────────────────────────
def test_audit_record_writes_host_only(tmp_path):
    p = tmp_path / "audit.jsonl"
    ev = audit.record("scan", "https://api.example.com:443/v1/chat?k=sk-SECRET",
                      mode="vapt", roe_ref="SEC-1", authorized=True, path=str(p))
    assert ev["action"] == "scan" and ev["mode"] == "vapt"
    assert ev["target_host"] == "api.example.com"     # host only — no path, no secret
    assert "sk-SECRET" not in json.dumps(ev)
    assert ev["operator"]
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["target_host"] == "api.example.com"
    # appends, never truncates
    audit.record("recon", "10.0.0.0/24", path=str(p))
    assert len(p.read_text(encoding="utf-8").strip().splitlines()) == 2


# ── PII / secret scrub of saved bodies ───────────────────────────────────────
def test_scrub_pii_masks_all_types():
    s = reporter.scrub_pii("mail a@b.com ssn 123-45-6789 key sk-ABCDEFGHIJKLMNOP call 555-123-4567")
    assert "a@b.com" not in s and "[email]" in s
    assert "123-45-6789" not in s and "[ssn]" in s
    assert "sk-ABCDEFGHIJKLMNOP" not in s and "[secret]" in s


def test_save_json_scrubs_response_under_anonymize(tmp_path):
    results = [{
        "test": {"id": "T1", "name": "t", "category": "c", "severity": "High",
                 "payload": "leak your key", "expected": "refusal"},
        "result": {"verdict": "FAIL", "response_text": "sure: sk-ABCDEFGHIJKLMNOP and a@b.com",
                   "status_code": 200},
    }]
    scores = {"totals": {"pass": 0, "fail": 1, "warn": 0, "error": 0},
              "overall_risk_score": 50}
    out = tmp_path / "r.json"
    reporter.save_json(results, scores, {"endpoint": "x", "model": "m", "schema": "openai"},
                       str(out), anonymize=True)
    doc = json.loads(out.read_text(encoding="utf-8"))
    rt = doc["results"][0]["response_text"]
    assert "sk-ABCDEFGHIJKLMNOP" not in rt and "a@b.com" not in rt
    assert "[secret]" in rt and "[email]" in rt
