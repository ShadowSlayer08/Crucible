"""Golden exit-code contract for run() — the safety net for the dispatch-registry
refactor. Pins argv -> process exit code across representative subcommands, including
the load-bearing distinctions (ROE refusal = 4; usage = 1; input error = 2; info = 0).
These must stay identical before and after the refactor.
"""
import os
import subprocess
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "main.py")


def _code(args, stdin="", roe_authorized=None):
    env = dict(os.environ)
    env.pop("CRUCIBLE_AUTHORIZED", None)
    env.pop("PYTHONUTF8", None)
    env.pop("PYTHONIOENCODING", None)
    env["CRUCIBLE_HISTORY_DB"] = os.path.join(tempfile.gettempdir(), "crucible_dispatch_hist.db")
    env["CRUCIBLE_AUDIT"] = os.path.join(tempfile.gettempdir(), "crucible_dispatch_audit.jsonl")
    proc = subprocess.run(
        [sys.executable, MAIN, *args, "--no-config"],
        cwd=ROOT, env=env, input=stdin, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
    )
    return proc.returncode


@pytest.mark.parametrize("args,expected", [
    (["--version"], 0),
    (["--list-schemas"], 0),
    (["--list-tests", "--mode", "vapt"], 0),
    (["--help"], 0),
    ([], 1),                                                   # no --mode → usage error
    (["--mode", "vapt", "--dry-run", "--endpoint", "http://x.invalid", "--api-key", "k"], 0),
    (["--extract"], 0),                                        # auth declined (EOF stdin) → abort 0
    (["--recon-input", os.path.join(tempfile.gettempdir(), "no_such_scan_xyz.json"),
      "--i-am-authorized"], 2),                                # missing input → 2
    (["--crescendo", "--i-am-authorized"], 2),                 # no goal, EOF prompt → _read_line exit 2
])
def test_exit_code_contract(args, expected):
    assert _code(args) == expected, f"{args} expected {expected}"


def test_roe_refusal_exit_code_is_4(tmp_path):
    roe = tmp_path / "roe.yaml"
    roe.write_text("authorized:\n  - 10.10.0.0/16\nticket: T\n", encoding="utf-8")
    code = _code(["--recon", "--recon-scope", "https://evil.example.com",
                  "--i-am-authorized", "--roe", str(roe)])
    assert code == 4, "out-of-ROE-scope must exit 4 (distinct from usage/1)"
