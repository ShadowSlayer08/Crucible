"""End-to-end CLI smoke tests via subprocess.

Output is captured through a pipe (not a TTY), which on Windows defaults to cp1252
— so these also guard the stdout/stderr UTF-8 fix and the judge_config ordering fix
(both crashed every one of these invocations before the fixes).
"""
import os
import subprocess
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "main.py")


def _run(*args):
    env = dict(os.environ)
    # Genuinely exercise the in-code UTF-8 reconfigure, not an env override.
    env.pop("PYTHONUTF8", None)
    env.pop("PYTHONIOENCODING", None)
    # Isolate trend history so smoke tests never touch the project DB.
    env["AI_RT_HISTORY_DB"] = os.path.join(tempfile.gettempdir(), "redai_smoke_history.db")
    return subprocess.run(
        [sys.executable, MAIN, *args, "--no-config"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
        # The CLI emits UTF-8 (its stdout is reconfigured); decode it as such on
        # the parent side rather than the Windows default cp1252.
        encoding="utf-8", errors="replace",
    )


@pytest.mark.parametrize("args", [
    ["--help"],
    ["--list-schemas"],
    ["--list-tests", "--mode", "vapt"],
    ["--list-tests", "--mode", "redteam", "--framework", "atlas", "--owasp"],
    ["--list-tests", "--mode", "payload"],
    ["--mode", "payload", "--schema", "anthropic", "--show-payloads"],
    ["--search", "injection", "--mode", "vapt"],
    # v3.0 expanded attack modes
    ["--list-tests", "--mode", "mcp"],
    ["--list-tests", "--mode", "agentic"],
    ["--list-tests", "--mode", "rag"],
    ["--list-tests", "--mode", "swarm"],
    ["--list-tests", "--mode", "policy"],
    ["--list-tests", "--mode", "benign"],
    ["--list-tests", "--mode", "obfuscation"],
    ["--mode", "mcp", "--dry-run", "--api-key", "x", "--endpoint", "http://x", "--nist"],
    ["--trend"],
])
def test_offline_command_exits_zero(args):
    r = _run(*args)
    assert r.returncode == 0, f"{args} failed:\n{r.stderr[-500:]}"
    assert "Traceback" not in r.stderr


def test_dry_run_makes_no_calls_and_exits_zero():
    r = _run("--mode", "vapt", "--dry-run", "--api-key", "x", "--endpoint", "http://x")
    assert r.returncode == 0
    assert "DRY RUN" in r.stdout
    assert "Traceback" not in r.stderr


def test_list_tests_shows_test_ids():
    r = _run("--list-tests", "--mode", "vapt")
    assert "PI-001" in r.stdout  # a known VAPT test id


def test_help_mentions_modes():
    r = _run("--help")
    assert "--mode" in r.stdout
