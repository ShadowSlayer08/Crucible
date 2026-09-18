"""
agenthound.py — bridge to AgentHound (infra-layer AI attack-surface recon).

CRUCIBLE red-teams model/agent *behaviour*; AgentHound
(github.com/adithyan-ak/AgentHound, Apache-2.0, Go) maps the AI *infrastructure* —
exposed MCP / LiteLLM / Ollama / vLLM / Qdrant / MLflow / Jupyter / Open-WebUI
services, credential chains, and BloodHound-style attack paths. This adapter runs
AgentHound (or ingests a JSON scan it already produced) and folds its findings into
CRUCIBLE's model: it surfaces the infra findings AND hands the discovered model/agent
endpoints to CRUCIBLE's behavioural red-team. One tool, full stack.

AgentHound stays its own upstream project (credited, Apache-2.0) — we wrap its JSON
output, never fuse code. Offensive / authorized-use only. Running the Go binary and
a live scan are operator-run and guarded; the parsing + endpoint mapping here are
pure stdlib and unit-tested.

Public API:
    available()                       -> bool          (agenthound on PATH?)
    run_scan(scope, out_json, ...)    -> {ok, reason, data|path}
    parse(data_or_path)               -> {findings, endpoints, paths, stats}
    to_targets(parsed)                -> [ {name, endpoint, schema, model, service, note} ]
    print_recon_report(parsed)        -> None
"""

import json
import os
import re
import shutil
import subprocess

import colors as C

# Field names whose values are credentials/secrets and must be masked before an
# AgentHound blob is persisted. Deliberately does NOT match the bare "auth" status
# field (endpoints carry auth="none"/"key"/"unauthenticated" — useful, not secret).
_SECRET_KEY_RE = re.compile(
    r"pass(word|wd)?|secret|token|api[-_ ]?key|credential|bearer|"
    r"private[-_ ]?key|access[-_ ]?key|cookie|authoriz|"
    r"auth[-_ ](token|header|key)|session[-_ ]?id",
    re.I,
)
_REDACTED = "«redacted»"


def redact_secrets(obj, mask: str = _REDACTED):
    """Recursively mask credential-like values in an AgentHound blob before it is
    written to disk (recon reports can otherwise become a cleartext loot cache).
    A dict key matching _SECRET_KEY_RE has its scalar value masked; lists and
    nested dicts are walked. Returns a NEW structure — never mutates the input,
    never raises."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and _SECRET_KEY_RE.search(k) and isinstance(v, (str, int, float, bool)):
                out[k] = mask
            else:
                out[k] = redact_secrets(v, mask)
        return out
    if isinstance(obj, list):
        return [redact_secrets(x, mask) for x in obj]
    return obj

# Service type -> (CRUCIBLE schema, suggested --mode). Types that expose an LLM/agent
# chat surface become behavioural targets; pure-infra stores (qdrant/mlflow/…) do not.
_LLM_SERVICE_SCHEMA = {
    "ollama":     ("ollama", "vapt"),
    "vllm":       ("openai", "vapt"),
    "litellm":    ("openai", "vapt"),
    "openai":     ("openai", "vapt"),
    "open-webui": ("openai", "vapt"),
    "openwebui":  ("openai", "vapt"),
    "localai":    ("openai", "vapt"),
    "tgi":        ("openai", "vapt"),
    "mcp":        ("openai", "mcp"),
    "a2a":        ("openai", "agentic"),
}
# Infra-only services AgentHound reports but CRUCIBLE doesn't behaviourally test.
_INFRA_ONLY = {"qdrant", "mlflow", "jupyter", "neo4j", "chroma", "weaviate", "pinecone"}

# Rough infra-finding -> framework tags (best-effort).
_FINDING_TAGS = {
    "unauth":      ("AML.T0040", "LLM06"),   # ML service access / excessive agency
    "credential":  ("AML.T0055", "LLM06"),
    "exfil":       ("AML.T0024", "LLM10"),
    "model":       ("AML.T0010", "LLM10"),   # supply chain / model theft
    "poison":      ("AML.T0020", "LLM08"),
    "impersonat":  ("AML.T0055", "LLM06"),
    "tool":        ("AML.T0055", "LLM06"),
}


def available(binary: str = "agenthound") -> bool:
    return shutil.which(binary) is not None


def run_scan(scope: str, out_json: str = None, binary: str = "agenthound",
             mode: str = "stealth", extra: list = None) -> dict:
    """Run `agenthound scan` and return its parsed JSON. Guarded: if the binary is
    absent this returns {ok: False, reason: ...} with an install hint (never raises).
    `mode` = stealth (read-only) or active. Operator/authorized-use only."""
    if not available(binary):
        return {"ok": False, "reason": (
            f"'{binary}' not on PATH. Install AgentHound "
            "(github.com/adithyan-ak/AgentHound, Apache-2.0) and re-run, or pass "
            "--recon-input with a JSON scan it produced.")}
    out_json = out_json or "agenthound_scan.json"
    cmd = [binary, "scan", "--scope", scope, "--json", "--output", out_json]
    if mode == "stealth":
        cmd.append("--stealth")
    if extra:
        cmd += list(extra)
    try:  # pragma: no cover - requires the binary + authorized infra to scan
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            return {"ok": False, "reason": (proc.stderr or "agenthound failed")[:400],
                    "cmd": " ".join(cmd)}
        data = json.load(open(out_json, encoding="utf-8"))
        return {"ok": True, "data": data, "path": out_json, "cmd": " ".join(cmd)}
    except Exception as exc:  # pragma: no cover
        return {"ok": False, "reason": str(exc), "cmd": " ".join(cmd)}


# ─────────────────────────────────────────────────────────────────────────────
# PARSING  (pure, tolerant of key variance — unit-tested)
# ─────────────────────────────────────────────────────────────────────────────
def _as_list(obj, *keys):
    """First list found under any of *keys* in dict *obj* (else [])."""
    if not isinstance(obj, dict):
        return obj if isinstance(obj, list) else []
    for k in keys:
        v = obj.get(k)
        if isinstance(v, list):
            return v
    return []


def parse(data_or_path) -> dict:
    """Parse an AgentHound JSON scan (dict or path) into a normalized shape.

    Tolerant of schema variance: services under services/nodes/hosts, findings under
    findings/issues/vulnerabilities, attack paths under attack_paths/paths/edges.
    Returns {findings, endpoints, paths, stats}.
    """
    if isinstance(data_or_path, str):
        with open(data_or_path, encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = data_or_path or {}

    services = _as_list(data, "services", "nodes", "hosts", "assets")
    raw_findings = _as_list(data, "findings", "issues", "vulnerabilities", "vulns")
    raw_paths = _as_list(data, "attack_paths", "paths", "edges", "attackPaths")

    endpoints = []
    for s in services:
        if not isinstance(s, dict):
            continue
        stype = str(s.get("type") or s.get("service") or s.get("kind") or "").lower()
        url = s.get("url") or s.get("endpoint") or s.get("address") or s.get("uri") or ""
        models = s.get("models") or s.get("model") or []
        if isinstance(models, str):
            models = [models]
        endpoints.append({
            "type": stype, "url": url, "auth": str(s.get("auth") or s.get("authn") or "").lower(),
            "models": models, "raw": s,
        })

    findings = []
    for fdg in raw_findings:
        if not isinstance(fdg, dict):
            continue
        title = fdg.get("title") or fdg.get("name") or fdg.get("id") or "finding"
        sev = str(fdg.get("severity") or fdg.get("risk") or "medium").upper()
        atlas, owasp = _tag_finding(f"{title} {fdg.get('detail','')}")
        findings.append({
            "id": fdg.get("id") or "", "title": title, "severity": sev,
            "service": str(fdg.get("service") or fdg.get("type") or "").lower(),
            "url": fdg.get("url") or fdg.get("endpoint") or "",
            "detail": fdg.get("detail") or fdg.get("description") or "",
            "atlas_id": atlas, "owasp_id": owasp,
        })

    stats = {"services": len(endpoints), "findings": len(findings),
             "attack_paths": len(raw_paths),
             "llm_endpoints": sum(1 for e in endpoints
                                  if e["type"] in _LLM_SERVICE_SCHEMA)}
    return {"findings": findings, "endpoints": endpoints, "paths": raw_paths, "stats": stats}


def _tag_finding(text: str):
    low = (text or "").lower()
    for key, (atlas, owasp) in _FINDING_TAGS.items():
        if key in low:
            return atlas, owasp
    return "AML.T0040", "LLM06"


# ─────────────────────────────────────────────────────────────────────────────
# BRIDGE TO BEHAVIOURAL TESTING
# ─────────────────────────────────────────────────────────────────────────────
def to_targets(parsed: dict) -> list:
    """Map AgentHound-discovered LLM/agent endpoints to CRUCIBLE target dicts, so the
    behavioural red-team can sweep everything recon found. Infra-only stores
    (Qdrant/MLflow/…) are excluded — AgentHound tests those, not CRUCIBLE's behaviour."""
    targets = []
    seen = set()
    for i, e in enumerate(parsed.get("endpoints", []), 1):
        stype = e["type"]
        if stype in _INFRA_ONLY or stype not in _LLM_SERVICE_SCHEMA:
            continue
        url = (e.get("url") or "").rstrip("/")
        if not url or url in seen:
            continue
        seen.add(url)
        schema, mode = _LLM_SERVICE_SCHEMA[stype]
        model = e["models"][0] if e.get("models") else ("" if schema != "ollama" else "llama3")
        note = "unauthenticated" if e.get("auth") in ("none", "", "anonymous") else e.get("auth")
        targets.append({
            "name": f"ah-{stype}-{i}", "endpoint": url, "schema": schema,
            "model": model, "service": stype, "suggested_mode": mode, "auth": note,
        })
    return targets


# ─────────────────────────────────────────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────────────────────────────────────────
_SEV_COL = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.DIM, "INFO": C.DIM}


def print_recon_report(parsed: dict) -> None:
    st = parsed.get("stats", {})
    width = 78
    print(f"\n{'═' * width}")
    print(C.BOLD("  INFRASTRUCTURE RECON  —  AgentHound (AI infra attack surface)"))
    print(f"{'═' * width}")
    print(f"  services: {st.get('services', 0)}   findings: {st.get('findings', 0)}   "
          f"attack-paths: {st.get('attack_paths', 0)}   "
          f"behavioural targets: {C.BOLD(str(st.get('llm_endpoints', 0)))}\n")

    findings = sorted(parsed.get("findings", []),
                      key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f["severity"], 4))
    if findings:
        print(C.BOLD("  Findings"))
        for f in findings[:20]:
            col = _SEV_COL.get(f["severity"], C.DIM)
            tag = C.DIM(f"[{f['atlas_id']}/{f['owasp_id']}]")
            svc = C.DIM(f"({f['service']})") if f["service"] else ""
            print(f"    {col('[' + f['severity'] + ']')} {f['title']} {svc} {tag}")
        print()

    tgts = to_targets(parsed)
    if tgts:
        print(C.BOLD("  Discovered model/agent endpoints (→ behavioural targets)"))
        for t in tgts:
            print(f"    {C.CYAN(t['endpoint'])}  {C.DIM(t['service'] + '/' + t['schema'])}"
                  f"  {C.YELLOW(t['auth']) if t['auth'] == 'unauthenticated' else ''}"
                  f"  {C.DIM('→ --mode ' + t['suggested_mode'])}")
        print()
