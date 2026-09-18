"""
audit.py — append-only audit trail of side-effectful runs.

An offensive-capable tool needs a defensible record of exactly what was fired at
which system, when, by whom, and under what authorization — for accountability and
compliance evidence (SOC2 / ISO 42001, which compliance.py already targets). This is
deliberately separate from the trend DB (which hashes the endpoint and holds no
operator identity) and from the redactable reports.

Writes newline-delimited JSON to .crucible-audit.jsonl (path via $CRUCIBLE_AUDIT).
Records the endpoint HOST only (never the full URL, api key, or any credential).
Never raises: a failed write degrades to a no-op, it never blocks a run.

    audit.record("scan", endpoint, mode="vapt", roe_ref="SEC-123")
"""

import datetime
import getpass
import json
import os
from urllib.parse import urlparse

DEFAULT_AUDIT_FILE = os.environ.get("CRUCIBLE_AUDIT", ".crucible-audit.jsonl")


def _operator() -> str:
    for k in ("CRUCIBLE_OPERATOR", "USER", "USERNAME"):
        v = os.environ.get(k)
        if v:
            return v
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _host(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        return urlparse(t).hostname or t
    # host[:port] or CIDR — keep as-is (no scheme, no path, no creds)
    return t.split("/")[0]


def record(action: str, target: str = "", *, mode: str = None, roe_ref: str = None,
           authorized=None, extra: dict = None, path: str = None) -> dict:
    """Append one audit event and return it. `target` is reduced to its host."""
    ev = {
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "operator": _operator(),
        "action": action,
        "target_host": _host(target),
        "mode": mode,
        "roe_ref": roe_ref or "",
        "authorized": authorized,
        "pid": os.getpid(),
    }
    if extra:
        ev.update(extra)
    p = path or DEFAULT_AUDIT_FILE
    try:
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    except Exception:
        pass
    return ev
