"""
ATLAS Reporter
Prints a MITRE ATLAS tactic/technique coverage report after a test run.
"""

from payloads.atlas import ATLAS_TACTICS, ATLAS_TECHNIQUES, tactic_summary
import colors as C


TACTIC_ORDER = [
    "AML.TA0002",  # Reconnaissance
    "AML.TA0003",  # Resource Development
    "AML.TA0004",  # Initial Access
    "AML.TA0005",  # ML Attack Staging
    "AML.TA0006",  # Execution
    "AML.TA0007",  # Persistence
    "AML.TA0009",  # Collection
    "AML.TA0010",  # Exfiltration
    "AML.TA0011",  # Command and Control
    "AML.TA0012",  # Impact
]


def print_atlas_report(results: list, coverage: dict):
    """
    Prints the full MITRE ATLAS coverage report.
    Called after print_final_report() in reporter.py when --framework atlas is set.
    """
    width = 72
    tac_sum = tactic_summary(coverage)

    print("\n" + "═" * width)
    print(C.BOLD(C.CYAN("  MITRE ATLAS COVERAGE REPORT")))
    print(C.DIM("  Adversarial Threat Landscape for Artificial-Intelligence Systems"))
    print("═" * width)

    # ── technique summary ─────────────────────────────────────────────────────
    total_techs  = len(coverage)
    failed_techs = sum(1 for v in coverage.values() if v["fail"] > 0)
    warned_techs = sum(1 for v in coverage.values() if v["warn"] > 0 and v["fail"] == 0)

    print(f"\n  Techniques tested : {C.CYAN(str(total_techs))}")
    print(f"  Techniques FAILED : {C.RED(str(failed_techs))}  (model complied with harmful prompt)")
    print(f"  Techniques WARNED : {C.YELLOW(str(warned_techs))}  (partial/ambiguous response)")

    # ── tactic-by-tactic breakdown ────────────────────────────────────────────
    print(f"\n{'─' * width}")
    print(C.BOLD("  TACTIC BREAKDOWN"))
    print(f"{'─' * width}\n")

    for tac_id in TACTIC_ORDER:
        if tac_id not in tac_sum:
            continue

        tac_data = tac_sum[tac_id]
        tac_name = tac_data["tactic_name"]
        n_pass   = tac_data["pass"]
        n_fail   = tac_data["fail"]
        n_warn   = tac_data["warn"]
        n_techs  = len(tac_data["techniques"])

        status_icon = C.RED("✗") if n_fail > 0 else (C.YELLOW("⚠") if n_warn > 0 else C.GREEN("✓"))

        print(f"  {status_icon}  {C.BOLD(tac_id)}  {C.CYAN(tac_name)}")
        print(f"     Techniques tested: {n_techs}  |  "
              f"{C.GREEN('PASS')}: {n_pass}  "
              f"{C.RED('FAIL')}: {n_fail}  "
              f"{C.YELLOW('WARN')}: {n_warn}")

        # list techniques under this tactic
        for tech_id, tech_data in coverage.items():
            if tech_data["tactic_id"] != tac_id:
                continue
            t_name  = tech_data["technique_name"]
            t_fail  = tech_data["fail"]
            t_warn  = tech_data["warn"]
            t_pass  = tech_data["pass"]
            t_icon  = C.RED("✗") if t_fail > 0 else (C.YELLOW("⚠") if t_warn > 0 else C.GREEN("✓"))
            verdict_str = (
                f"{C.GREEN('P')}:{t_pass} "
                f"{C.RED('F')}:{t_fail} "
                f"{C.YELLOW('W')}:{t_warn}"
            )
            print(f"       {t_icon}  {C.DIM(tech_id):<16}  {t_name:<40}  {verdict_str}")

        print()

    # ── failed techniques detail ──────────────────────────────────────────────
    failed_tests = [r for r in results if r["result"]["verdict"] == "FAIL"]
    if failed_tests:
        print(f"{'─' * width}")
        print(C.BOLD(C.RED(f"  ATLAS FAILURES — {len(failed_tests)} test(s) where model complied")))
        print(f"{'─' * width}\n")

        for r in failed_tests:
            t   = r["test"]
            res = r["result"]
            atlas_id   = t.get("atlas_id", "N/A")
            atlas_name = t.get("atlas_technique_name", "")
            tactic_name = t.get("atlas_tactic_name", "")

            print(f"  {C.RED('✗')} [{t['id']}] {C.BOLD(t['name'])}")
            print(f"     ATLAS    : {C.CYAN(atlas_id)} — {atlas_name}  ({C.DIM(tactic_name)})")
            print(f"     Severity : {t.get('severity','?')}")
            print(f"     Reason   : {res.get('reason','')}")
            excerpt = res.get("flagged_excerpt", "")[:120].replace("\n", " ")
            if excerpt:
                print(f"     Excerpt  : {C.DIM(excerpt)}")
            print()

    # ── untested techniques ───────────────────────────────────────────────────
    tested_ids = set(coverage.keys())
    all_ids    = set(ATLAS_TECHNIQUES.keys())
    untested   = all_ids - tested_ids

    if untested:
        print(f"{'─' * width}")
        print(C.BOLD(C.YELLOW(f"  UNTESTED ATLAS TECHNIQUES ({len(untested)})")))
        print(C.DIM("  These techniques exist in ATLAS but were not covered by this run."))
        print(C.DIM("  Consider adding --mode redteam or running with provider-specific payloads.\n"))
        for tid in sorted(untested):
            tech = ATLAS_TECHNIQUES.get(tid, {})
            tac  = ATLAS_TACTICS.get(tech.get("tactic", ""), {})
            print(f"  {C.DIM(tid):<16}  {tech.get('name',''):<38}  [{C.DIM(tac.get('name',''))}]")
        print()

    # ── ATLAS risk summary ────────────────────────────────────────────────────
    print(f"{'─' * width}")
    _print_atlas_risk_summary(tac_sum)
    print("═" * width + "\n")


def _print_atlas_risk_summary(tac_sum: dict):
    """Print a one-line risk statement per failing tactic."""
    TACTIC_REMEDIATIONS = {
        "AML.TA0002": "Restrict model capability disclosure; audit verbose error messages.",
        "AML.TA0003": "Monitor for adversarial dataset submissions in ML supply chain.",
        "AML.TA0004": "Enforce API authentication, rate limiting, and access logging.",
        "AML.TA0005": "Implement input sanitisation, encoding normalisation, and indirect injection defenses.",
        "AML.TA0006": "Strengthen system prompt boundary enforcement; test adversarial personas.",
        "AML.TA0007": "Audit and restrict persistent memory and plugin tool permissions.",
        "AML.TA0009": "Limit in-context data exposure; scope tool access to minimum required.",
        "AML.TA0010": "Implement output filtering; block system prompt and PII repetition.",
        "AML.TA0011": "Monitor for agent-to-agent communication patterns and exfiltration channels.",
        "AML.TA0012": "Add output classifiers; implement cost alerts and DoS rate controls.",
    }

    failing_tactics = [
        (tid, data) for tid, data in tac_sum.items() if data["fail"] > 0
    ]

    if not failing_tactics:
        print(C.BOLD(C.GREEN("  ✓ No ATLAS tactic failures detected in this run.")))
        return

    print(C.BOLD("  ATLAS REMEDIATION GUIDANCE"))
    print()
    for tac_id, data in failing_tactics:
        tip = TACTIC_REMEDIATIONS.get(tac_id, "Review and harden model behavior for this tactic.")
        print(f"  {C.CYAN('→')} {C.BOLD(tac_id + ' ' + data['tactic_name'])}")
        print(f"    {tip}\n")
