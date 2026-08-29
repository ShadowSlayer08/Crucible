"""
OWASP Agentic AI — Threats & Mitigations mapping  (roadmap G3)

Tags each test with the OWASP Agentic AI threat (AAI-T01 .. T15) it exercises and
prints a coverage table — the agentic counterpart to owasp.py's LLM Top 10 report.
Ref: OWASP Agentic Security Initiative, "Agentic AI — Threats and Mitigations" v1.0.
"""
import colors as C

AGENTIC_THREATS = {
    "T1":  "Memory Poisoning",
    "T2":  "Tool Misuse",
    "T3":  "Privilege Compromise",
    "T4":  "Resource Overload",
    "T5":  "Cascading Hallucination",
    "T6":  "Intent Breaking & Goal Manipulation",
    "T7":  "Misaligned & Deceptive Behaviours",
    "T8":  "Repudiation & Untraceability",
    "T9":  "Identity Spoofing & Impersonation",
    "T10": "Overwhelming Human-in-the-Loop",
    "T11": "Unexpected Code Execution (RCE)",
    "T12": "Agent Communication Poisoning",
    "T13": "Rogue Agents in Multi-Agent Systems",
    "T14": "Human Attacks on Multi-Agent Systems",
    "T15": "Human Manipulation",
}

# keyword → threat (first match wins); scanned over category + name + tags.
_KEYWORD_THREAT = [
    (("memory", "false fact", "persistence", "delayed trigger", "poison memory"), "T1"),
    (("tool hijack", "tool output", "tool call", "unauthorized api", "tool misuse", "action injection"), "T2"),
    (("privilege", "rbac", "escalat", "scope bypass", "bfla", "bola", "admin"), "T3"),
    (("resource", "exhaustion", "loop", "dos", "spam", "flooding", "overload"), "T4"),
    (("cascad", "hallucinat", "propagat"), "T5"),
    (("goal", "objective", "plan injection", "intent", "goal hijack"), "T6"),
    (("deceptive", "misalign", "reward"), "T7"),
    (("repudiation", "untraceab", "logging", "audit"), "T8"),
    (("impersonat", "spoof", "identity", "forgery", "false consent"), "T9"),
    (("human-in-the-loop", "approval", "consent", "auto-approve"), "T10"),
    (("code exec", "rce", "shell", "sql", "command injection", "sandbox"), "T11"),
    (("message-bus", "communication", "cross-agent", "shared context", "blackboard"), "T12"),
    (("rogue", "orchestrator", "swarm", "consensus", "sybil"), "T13"),
    (("cross-server", "cross-context", "tenant", "bleed"), "T14"),
    (("phish", "social", "manipulat", "trust"), "T15"),
]


def _threat_for(test: dict) -> str:
    hay = " ".join([
        str(test.get("category", "")), str(test.get("name", "")),
        " ".join(str(x) for x in test.get("tags", []) or []),
    ]).lower()
    for keywords, threat in _KEYWORD_THREAT:
        if any(k in hay for k in keywords):
            return threat
    return ""  # not an agentic test


def enrich_agentic(test: dict) -> dict:
    t = dict(test)
    tid = _threat_for(t)
    if tid:
        t["agentic_id"] = tid
        t["agentic_name"] = AGENTIC_THREATS[tid]
    return t


def agentic_coverage(results: list) -> dict:
    cov = {}
    for r in results:
        tid = r["test"].get("agentic_id") or _threat_for(r["test"])
        if not tid:
            continue
        b = cov.setdefault(tid, {"name": AGENTIC_THREATS[tid],
                                 "pass": 0, "fail": 0, "warn": 0, "error": 0, "total": 0})
        v = r["result"]["verdict"].lower()
        if v in b:
            b[v] += 1
        b["total"] += 1
    return cov


def print_agentic_report(results: list) -> None:
    cov = agentic_coverage(results)
    width = 78
    print(f"\n{'═' * width}")
    print(C.BOLD("  OWASP AGENTIC AI — THREATS & MITIGATIONS COVERAGE"))
    print(f"{'═' * width}\n")
    print(f"  {'ID':<5} {'Threat':<38} {'Tests':>5} {'FAIL':>5} {'Status'}")
    print(f"  {'─' * (width - 4)}")
    covered = 0
    for tid, name in AGENTIC_THREATS.items():
        d = cov.get(tid)
        if d:
            covered += 1
            status = C.RED("HIT") if d["fail"] else C.GREEN("tested")
            print(f"  {C.CYAN(tid):<5} {name[:38]:<38} {d['total']:>5} "
                  f"{(C.RED(str(d['fail'])) if d['fail'] else C.DIM('0')):>5} {status}")
        else:
            print(f"  {C.DIM(tid):<5} {C.DIM(name[:38]):<38} {C.DIM('   —'):>5} "
                  f"{C.DIM('  —'):>5} {C.DIM('not tested')}")
    print(f"\n  Agentic coverage : {covered}/{len(AGENTIC_THREATS)} threats exercised")
    print(f"\n{'═' * width}\n")
