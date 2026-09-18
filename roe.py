"""
roe.py — Rules-of-Engagement / scope confinement.

Scope confinement is the single control that most reliably stops an authorized tool
from being aimed at unauthorized infrastructure (fat-finger, wrong CIDR) — and with
credential-looting recon and an active model-stealing engine now bundled, an
unconstrained scope is the gap between an engagement and a CFAA violation.

If a `.crucible-roe.yaml` exists (or is passed via --roe / $CRUCIBLE_ROE), CRUCIBLE
refuses any live target or recon scope not inside the authorized list, and stamps
the ROE reference into reports/audit. No ROE file → not enforced (opt-in), so
existing workflows are unaffected until an operator adds one.

ROE file shape (all fields optional except `authorized`):
    authorized:
      - "10.0.0.0/24"
      - "api.internal.example.com"        # host (also matches sub.host)
      - "https://staging.example.com"     # URL (host compared)
    expiry: "2026-12-31"                    # ISO date; refuse after
    authorizer: "Jane Doe / Ticket SEC-123"
    ticket: "SEC-123"

Public API:
    load_roe(path=None)       -> dict | None
    in_scope(target, roe)     -> bool
    is_expired(roe)           -> bool
    enforce(target, roe, override=False) -> (ok: bool, reason: str)
    build_matcher(roe)        -> function(url_or_host) -> bool
    roe_ref(roe)              -> str        (short reference for stamping)
"""

import datetime
import ipaddress
import os
from urllib.parse import urlparse

DEFAULT_ROE_FILE = os.environ.get("CRUCIBLE_ROE", ".crucible-roe.yaml")


def load_roe(path: str = None):
    """Load the ROE file. Returns the dict, or None if the file is absent/empty/bad
    (absent = not enforced). Never raises."""
    path = path or DEFAULT_ROE_FILE
    if not path or not os.path.exists(path):
        return None
    try:
        import yaml
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict) and (data.get("authorized") or data.get("scope")):
            data["_path"] = path
            return data
    except Exception:
        return None
    return None


def _authorized_list(roe: dict) -> list:
    return list(roe.get("authorized") or roe.get("scope") or []) if roe else []


def _classify(s: str):
    """Return ('net', network) | ('ip', addr) | ('host', name) for a target/entry."""
    s = (s or "").strip()
    if not s:
        return (None, None)
    if "://" in s:
        host = (urlparse(s).hostname or "").lower()
        s = host
    # CIDR?
    if "/" in s:
        try:
            return ("net", ipaddress.ip_network(s, strict=False))
        except ValueError:
            s = s.split("/")[0]
    # strip a :port
    if s.count(":") == 1 and not s.replace(":", "").replace(".", "").isalpha():
        s = s.split(":")[0]
    try:
        return ("ip", ipaddress.ip_address(s))
    except ValueError:
        return ("host", s.lower())


def _matches(target, entry) -> bool:
    tk, tv = _classify(target)
    ek, ev = _classify(entry)
    if tk is None or ek is None:
        return False
    if ek == "net":
        if tk == "ip":
            return tv in ev
        if tk == "net":
            return tv.subnet_of(ev)
        return False
    if ek == "ip":
        return tk == "ip" and tv == ev
    # ek == "host"
    if tk == "host":
        return tv == ev or tv.endswith("." + ev)
    return False


def in_scope(target: str, roe: dict) -> bool:
    """True if *target* (URL / host / IP / CIDR) is inside the ROE's authorized list."""
    if not roe:
        return True  # no ROE → not enforced
    return any(_matches(target, e) for e in _authorized_list(roe))


def is_expired(roe: dict) -> bool:
    if not roe or not roe.get("expiry"):
        return False
    try:
        exp = datetime.date.fromisoformat(str(roe["expiry"])[:10])
    except ValueError:
        return False
    return datetime.date.today() > exp


def roe_ref(roe: dict) -> str:
    if not roe:
        return ""
    bits = []
    if roe.get("ticket"):
        bits.append(str(roe["ticket"]))
    if roe.get("authorizer"):
        bits.append(str(roe["authorizer"]))
    if roe.get("expiry"):
        bits.append(f"exp={roe['expiry']}")
    return " / ".join(bits) or (roe.get("_path") or "roe")


def enforce(target: str, roe: dict, override: bool = False) -> tuple:
    """Return (ok, reason). No ROE → allowed (opt-in). Expired → refused. Out of
    scope → refused unless override. Override is recorded by the caller (audit)."""
    if not roe:
        return (True, "no ROE file — scope not enforced")
    if is_expired(roe):
        if override:
            return (True, f"ROE EXPIRED ({roe.get('expiry')}) — overridden")
        return (False, f"ROE expired ({roe.get('expiry')}). Update the ROE file to proceed.")
    if in_scope(target, roe):
        return (True, f"in scope [{roe_ref(roe)}]")
    if override:
        return (True, f"OUT OF SCOPE — overridden ({target})")
    allowed = ", ".join(_authorized_list(roe)) or "(none)"
    return (False, f"'{target}' is OUT OF ROE SCOPE. Authorized: {allowed}. "
                   f"Add it to {roe.get('_path', DEFAULT_ROE_FILE)} or pass --roe-override.")


def build_matcher(roe: dict):
    """Return a fast predicate(url_or_host)->bool for the hot path (engine guard)."""
    if not roe:
        return None
    entries = _authorized_list(roe)

    def _match(url):
        return any(_matches(url, e) for e in entries)
    return _match
