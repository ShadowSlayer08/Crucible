"""
fullstack.py — orchestrate the infra → behaviour full-stack merge.

`--full-stack` previously only PRINTED a sweep plan. This module makes the merge
real:

  • sweep_targets()        — actually fire CRUCIBLE's behavioural red-team at each
                             AgentHound-discovered endpoint (subprocess self-invocation;
                             the invoker is injectable so it is unit-testable).
  • build_unified_report() — merge infra findings/endpoints/paths + the behavioural
                             results into ONE document under shared ATLAS/OWASP/NIST
                             with a combined risk posture.
  • correlate()            — chain the two layers: an endpoint that is REACHABLE
                             (infra: unauth/exposed) AND EXPLOITABLE (behaviour:
                             jailbreak-compliant) escalates to a CRITICAL finding.
  • render_attack_paths()  — ASCII chain + Mermaid export of the recon attack paths.

Pure/orchestration only (no heavy deps); authorized-use only.
"""

import glob
import json
import os
import subprocess
import sys
from datetime import datetime

_MAIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "": 0}


# ─────────────────────────────────────────────────────────────────────────────
# D2 — run the behavioural sweep over discovered endpoints
# ─────────────────────────────────────────────────────────────────────────────
def _summarize_report(report: dict) -> dict:
    """Compact summary from a behavioural report JSON (reporter.save_json shape)."""
    scores = (report or {}).get("scores", {}) or {}
    totals = scores.get("totals", {}) or {}
    return {
        "total": sum(totals.get(k, 0) for k in ("pass", "fail", "warn", "error")),
        "fails": totals.get("fail", 0),
        "warns": totals.get("warn", 0),
        "errors": totals.get("error", 0),
        "asr_percent": scores.get("asr_percent", 0.0),
        "risk_score": scores.get("overall_risk_score", 0),
    }


def _subprocess_invoker(report_dir: str, extra_argv=None, timeout: int = 900):
    """Default invoker: run `main.py --target <name> --mode <mode>` as a subprocess
    and read back the behavioural report it writes. Contained — no run() refactor."""
    extra_argv = extra_argv or []

    def _invoke(target: dict) -> dict:
        td = os.path.join(report_dir, target["name"])
        os.makedirs(td, exist_ok=True)
        cmd = [sys.executable, _MAIN, "--target", target["name"],
               "--mode", target.get("suggested_mode", "vapt"),
               "--output-dir", td, "--i-am-authorized", "--no-config", "--no-color"]
        cmd += extra_argv
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except Exception as exc:  # pragma: no cover - subprocess env
            return {"ok": False, "error": str(exc)[:200]}
        files = sorted(glob.glob(os.path.join(td, "*.json")), key=os.path.getmtime)
        if not files:
            return {"ok": False, "returncode": proc.returncode,
                    "error": (proc.stderr or "no report produced")[:200]}
        try:
            with open(files[-1], encoding="utf-8") as f:
                report = json.load(f)
        except Exception as exc:  # pragma: no cover
            return {"ok": False, "error": f"unreadable report: {exc}"}
        return {"ok": True, "report_path": files[-1], "returncode": proc.returncode,
                "summary": _summarize_report(report)}
    return _invoke


def sweep_targets(discovered: list, invoker=None, report_dir: str = None,
                  extra_argv=None) -> list:
    """Behaviourally red-team each discovered endpoint. `invoker(target)->dict` is
    injectable (default = subprocess self-invocation). Returns one row per target:
    {target_name, endpoint, service, mode, ok, summary|error}."""
    if invoker is None:
        report_dir = report_dir or os.path.join(".", "reports", "fullstack")
        os.makedirs(report_dir, exist_ok=True)
        invoker = _subprocess_invoker(report_dir, extra_argv=extra_argv)
    rows = []
    for t in (discovered or []):
        res = invoker(t) or {}
        rows.append({
            "target_name": t.get("name"), "endpoint": t.get("endpoint"),
            "service": t.get("service"), "mode": t.get("suggested_mode"),
            "auth": t.get("auth"),
            "ok": bool(res.get("ok")),
            "summary": res.get("summary"),
            "error": res.get("error"),
            "report_path": res.get("report_path"),
        })
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# D4 — correlate infra reachability with behavioural exploitability
# ─────────────────────────────────────────────────────────────────────────────
def correlate(parsed: dict, sweep_rows: list) -> list:
    """Chain the two layers. An endpoint that infra recon found EXPOSED and that the
    behavioural sweep then BROKE is a chained finding whose severity is escalated —
    unauthenticated + jailbreak-compliant = CRITICAL."""
    endpoints = {(_norm(e.get("url"))): e for e in parsed.get("endpoints", [])}
    findings_by_url = {}
    for f in parsed.get("findings", []):
        findings_by_url.setdefault(_norm(f.get("url")), []).append(f)

    chained = []
    for row in sweep_rows or []:
        summ = row.get("summary") or {}
        fails = summ.get("fails", 0)
        if not row.get("ok") or fails <= 0:
            continue
        url = _norm(row.get("endpoint"))
        infra_ep = endpoints.get(url, {})
        auth = (row.get("auth") or infra_ep.get("auth") or "").lower()
        unauth = auth in ("unauthenticated", "none", "", "anonymous")
        severity = "CRITICAL" if unauth else "HIGH"
        infra_ids = [f.get("id") for f in findings_by_url.get(url, []) if f.get("id")]
        chained.append({
            "endpoint": row.get("endpoint"), "service": row.get("service"),
            "reachable": True, "auth": auth or "unknown", "unauthenticated": unauth,
            "behaviour_fails": fails, "behaviour_mode": row.get("mode"),
            "infra_findings": infra_ids, "severity": severity,
            "atlas_id": "AML.T0040", "owasp_id": "LLM06",
            "note": (f"{row.get('service')} endpoint is "
                     f"{'unauthenticated' if unauth else auth} AND its model failed "
                     f"{fails} behavioural probe(s) — reachable and exploitable."),
        })
    chained.sort(key=lambda c: _SEV_RANK.get(c["severity"], 0), reverse=True)
    return chained


def _norm(url: str) -> str:
    return (url or "").rstrip("/").lower()


# ─────────────────────────────────────────────────────────────────────────────
# D4 — attack-path rendering
# ─────────────────────────────────────────────────────────────────────────────
def render_attack_paths(parsed: dict) -> dict:
    """Render recon attack paths as an ASCII chain + a Mermaid graph. The path edges
    were parsed but previously only counted — this surfaces them."""
    paths = parsed.get("paths", []) or []
    ascii_lines, mermaid = [], ["graph LR"]
    seen_nodes = set()

    def _node(v):
        nid = "n" + str(abs(hash(str(v))) % 100000)
        if nid not in seen_nodes:
            seen_nodes.add(nid)
            mermaid.append(f'  {nid}["{str(v)[:40]}"]')
        return nid

    for p in paths:
        if not isinstance(p, dict):
            continue
        frm = p.get("from", "?")
        to = p.get("to", "?")
        via = p.get("via", "")
        impact = p.get("impact", "")
        arrow = f"--[{via}]-->" if via else "-->"
        ascii_lines.append(f"  {frm} {arrow} {to}" + (f"   ({impact})" if impact else ""))
        a, b = _node(frm), _node(to)
        label = (via + (": " + impact if impact else "")).strip(": ")
        mermaid.append(f'  {a} -->|{label[:40]}| {b}' if label else f"  {a} --> {b}")

    return {"ascii": "\n".join(ascii_lines), "mermaid": "\n".join(mermaid),
            "count": len(ascii_lines)}


# ─────────────────────────────────────────────────────────────────────────────
# D3 — unified report
# ─────────────────────────────────────────────────────────────────────────────
def _infra_by_severity(findings: list) -> dict:
    out = {}
    for f in findings or []:
        s = str(f.get("severity", "")).upper()
        out[s] = out.get(s, 0) + 1
    return out


def build_unified_report(parsed: dict, sweep_rows: list, meta: dict = None) -> dict:
    """Merge infra recon + behavioural sweep into ONE report with a combined posture."""
    findings = parsed.get("findings", [])
    correlations = correlate(parsed, sweep_rows)
    infra_sev = _infra_by_severity(findings)
    behaviour_fails = sum((r.get("summary") or {}).get("fails", 0)
                          for r in sweep_rows or [])

    # Combined risk: worst of infra severities, escalated by any chained CRITICAL.
    risk_rank = max([_SEV_RANK.get(s, 0) for s in infra_sev] or [0])
    if correlations:
        risk_rank = max(risk_rank, _SEV_RANK.get(correlations[0]["severity"], 0))
    combined_risk = next((k for k, v in _SEV_RANK.items() if v == risk_rank and k), "LOW")

    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "meta": meta or {},
        "infra": {
            "stats": parsed.get("stats", {}),
            "findings": findings,
            "endpoints": [{k: v for k, v in e.items() if k != "raw"}
                          for e in parsed.get("endpoints", [])],
            "attack_paths": parsed.get("paths", []),
        },
        "attack_path_graph": render_attack_paths(parsed),
        "behaviour": sweep_rows,
        "correlations": correlations,
        "posture": {
            "infra_findings": len(findings),
            "infra_by_severity": infra_sev,
            "behaviour_targets": len(sweep_rows or []),
            "behaviour_total_fails": behaviour_fails,
            "chained_findings": len(correlations),
            "combined_risk": combined_risk,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────────────────────────────────────────
def print_unified_report(report: dict, colors=None) -> None:
    C = colors
    if C is None:
        class _N:
            def __getattr__(self, _):
                return lambda t="": t
        C = _N()
    p = report.get("posture", {})
    print()
    print(C.BOLD("═" * 74))
    print(C.BOLD("  FULL-STACK REPORT  —  infrastructure + behaviour"))
    print(C.BOLD("═" * 74))
    print(f"  infra findings : {p.get('infra_findings', 0)}   "
          f"behavioural targets : {p.get('behaviour_targets', 0)}   "
          f"behavioural fails : {p.get('behaviour_total_fails', 0)}")
    rc = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW}.get(p.get("combined_risk"), C.DIM)
    print(rc(C.BOLD(f"  COMBINED RISK  : {p.get('combined_risk', 'LOW')}")))

    cors = report.get("correlations", [])
    if cors:
        print()
        print(C.BOLD("  CHAINED FINDINGS  (reachable AND exploitable)"))
        for c in cors:
            col = C.RED if c["severity"] == "CRITICAL" else C.YELLOW
            print(f"    {col('[' + c['severity'] + ']')} {c['endpoint']} "
                  f"{C.DIM('(' + str(c['service']) + ')')} — {c['behaviour_fails']} fails")

    graph = report.get("attack_path_graph", {})
    if graph.get("ascii"):
        print()
        print(C.BOLD("  ATTACK PATHS"))
        print(C.DIM(graph["ascii"]))
    print(C.BOLD("═" * 74))
