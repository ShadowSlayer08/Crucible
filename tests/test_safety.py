"""Slice A — safety hardening of the offensive paths.

Covers: the shared authorization gate (require_authorization), AgentHound raw-blob
redaction, the hardened --offline air-gap host check, and client-side rate limiting.
The offensive binaries/live infra are never touched; gate + redaction are exercised
end-to-end via --recon-input (offline) and unit-level.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

import pytest

import agenthound
import engine
import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "main.py")


def _args(**kw):
    ns = argparse.Namespace()
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def _run(*args, stdin=""):
    env = dict(os.environ)
    env.pop("AI_RT_AUTHORIZED", None)
    env.pop("PYTHONUTF8", None)
    env.pop("PYTHONIOENCODING", None)
    env["AI_RT_HISTORY_DB"] = os.path.join(tempfile.gettempdir(), "redai_safety_hist.db")
    return subprocess.run(
        [sys.executable, MAIN, *args, "--no-config"],
        cwd=ROOT, env=env, input=stdin, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
    )


def _latest_json(out_dir, prefix="recon_"):
    files = [f for f in os.listdir(out_dir) if f.startswith(prefix) and f.endswith(".json")]
    assert files, f"no {prefix}*.json in {out_dir}"
    newest = max(files, key=lambda f: os.path.getmtime(os.path.join(out_dir, f)))
    with open(os.path.join(out_dir, newest), encoding="utf-8") as fh:
        return json.load(fh)


# ── A1: require_authorization ────────────────────────────────────────────────
def test_auth_flag_opt_in_skips_prompt(monkeypatch):
    monkeypatch.delenv("AI_RT_AUTHORIZED", raising=False)
    monkeypatch.setattr(main, "prompt_authorization",
                        lambda: pytest.fail("flag should short-circuit the prompt"))
    assert main.require_authorization(_args(i_am_authorized=True), "x") is True


def test_auth_env_opt_in_skips_prompt(monkeypatch):
    monkeypatch.setenv("AI_RT_AUTHORIZED", "1")
    monkeypatch.setattr(main, "prompt_authorization",
                        lambda: pytest.fail("env should short-circuit the prompt"))
    assert main.require_authorization(_args(i_am_authorized=False), "x") is True


def test_auth_prompt_yes(monkeypatch):
    monkeypatch.delenv("AI_RT_AUTHORIZED", raising=False)
    monkeypatch.setattr(main, "prompt_authorization", lambda: True)
    assert main.require_authorization(_args(i_am_authorized=False), "x") is True


def test_auth_prompt_no_fails_closed(monkeypatch):
    monkeypatch.delenv("AI_RT_AUTHORIZED", raising=False)
    monkeypatch.setattr(main, "prompt_authorization", lambda: False)
    assert main.require_authorization(_args(i_am_authorized=False), "x") is False


def test_extract_aborts_without_authorization():
    # empty stdin → the prompt sees EOF → fails closed → aborts before any probe
    r = _run("--extract")
    blob = r.stdout + r.stderr
    assert "AUTHORIZATION" in blob or "uthoriz" in blob
    assert "Aborted" in blob


def test_recon_gate_opens_with_flag():
    # gate passes with --i-am-authorized, then hits the missing binary (exit 3)
    r = _run("--recon", "--recon-scope", "10.0.0.0/24", "--i-am-authorized")
    assert "not on PATH" in (r.stdout + r.stderr)
    assert r.returncode == 3


# ── A2: redact_secrets ───────────────────────────────────────────────────────
def test_redact_masks_credentials_recursively():
    blob = {
        "api_key": "sk-123", "password": "hunter2", "authorization": "Bearer xyz",
        "nested": {"session_token": "abc", "models": ["a"]},
        "loot": [{"secret": "s"}, {"ok": "keep"}],
        "auth": "none", "url": "http://x", "count": 5,
    }
    red = agenthound.redact_secrets(blob)
    assert red["api_key"] == "«redacted»"
    assert red["password"] == "«redacted»"
    assert red["authorization"] == "«redacted»"
    assert red["nested"]["session_token"] == "«redacted»"
    assert red["loot"][0]["secret"] == "«redacted»"
    # non-secret data preserved — including the bare "auth" STATUS field
    assert red["auth"] == "none"
    assert red["url"] == "http://x"
    assert red["count"] == 5
    assert red["nested"]["models"] == ["a"]
    assert red["loot"][1]["ok"] == "keep"


def test_redact_does_not_mutate_input():
    blob = {"token": "t", "n": [{"password": "p"}]}
    agenthound.redact_secrets(blob)
    assert blob["token"] == "t" and blob["n"][0]["password"] == "p"


def test_redact_scalars_passthrough():
    assert agenthound.redact_secrets("plain") == "plain"
    assert agenthound.redact_secrets(7) == 7
    assert agenthound.redact_secrets(None) is None


def test_recon_input_omits_raw_by_default_and_redacts_when_saved(tmp_path):
    sample = {
        "services": [{"type": "ollama", "url": "http://x:11434", "auth": "none"}],
        "findings": [{"id": "AH-1", "severity": "high", "title": "unauth"}],
        "loot": {"password": "hunter2", "api_key": "sk-SECRET"},
    }
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps(sample), encoding="utf-8")
    out_dir = tmp_path / "reports"

    r = _run("--recon-input", str(scan), "--i-am-authorized", "--output-dir", str(out_dir))
    assert r.returncode == 0, r.stdout + r.stderr
    doc = _latest_json(str(out_dir))
    assert "raw" not in doc                      # opt-in only

    r2 = _run("--recon-input", str(scan), "--i-am-authorized", "--recon-save-raw",
              "--output-dir", str(out_dir))
    assert r2.returncode == 0, r2.stdout + r2.stderr
    doc2 = _latest_json(str(out_dir))
    assert "raw" in doc2                          # now present…
    assert doc2["raw"]["loot"]["password"] == "«redacted»"   # …but redacted
    assert doc2["raw"]["loot"]["api_key"] == "«redacted»"


# ── A3: hardened air-gap host check ──────────────────────────────────────────
@pytest.mark.parametrize("url", [
    "http://localhost:11434", "http://127.0.0.1:11434/v1/chat", "https://[::1]:8080",
    "http://0.0.0.0:11434", "http://host.docker.internal:11434", "localhost", "127.0.0.1",
])
def test_is_local_true(url):
    assert engine._is_local_url(url) is True


@pytest.mark.parametrize("url", [
    "http://localhost.evil.com/",                      # substring bypass (old bug)
    "http://127.0.0.1.evil.com/",                      # substring bypass (old bug)
    "https://api.openai.com/v1/chat?x=127.0.0.1",      # loopback in query (old bug)
    "https://api.openai.com",
    "http://169.254.169.254/latest/meta-data/",        # link-local metadata — NOT local
    "http://10.0.0.5:11434", "", "not a url",
])
def test_is_local_false(url):
    assert engine._is_local_url(url) is False


# ── A4: client-side rate limiting ────────────────────────────────────────────
def test_throttle_spaces_requests():
    engine.set_rate(rps=100)          # 0.01s min interval
    try:
        t0 = time.monotonic()
        engine._throttle()            # first is immediate
        engine._throttle()
        engine._throttle()
        elapsed = time.monotonic() - t0
        assert elapsed >= 0.015       # ~2 intervals of enforced spacing
    finally:
        engine.set_rate(0)


def test_throttle_noop_when_unlimited():
    engine.set_rate(0)
    t0 = time.monotonic()
    for _ in range(5):
        engine._throttle()
    assert time.monotonic() - t0 < 0.01


def test_set_rate_delay_wins_when_larger():
    engine.set_rate(rps=1000, delay=0.02)   # delay (0.02) > rps interval (0.001)
    try:
        assert engine._MIN_INTERVAL == pytest.approx(0.02)
    finally:
        engine.set_rate(0)
