"""
OWASP LLM Top 10 (2025) Mapping
Maps every test ID to its OWASP LLM risk category.
Reference: https://genai.owasp.org/llm-top-10/
"""

import colors as C

# ─────────────────────────────────────────────────────────────────────────────
# OWASP LLM TOP 10 REGISTRY (2025 edition)
# ─────────────────────────────────────────────────────────────────────────────

OWASP_CATEGORIES = {
    "LLM01": {
        "name": "Prompt Injection",
        "desc": "Manipulating LLM via crafted inputs to override instructions or extract data.",
        "risk": "Critical",
    },
    "LLM02": {
        "name": "Sensitive Information Disclosure",
        "desc": "LLM reveals confidential data, system prompts, PII, or credentials in responses.",
        "risk": "High",
    },
    "LLM03": {
        "name": "Supply Chain Vulnerabilities",
        "desc": "Risks from third-party datasets, models, plugins, or dependencies.",
        "risk": "High",
    },
    "LLM04": {
        "name": "Data and Model Poisoning",
        "desc": "Manipulation of training data or fine-tuning to introduce vulnerabilities.",
        "risk": "High",
    },
    "LLM05": {
        "name": "Improper Output Handling",
        "desc": "Insufficient validation of LLM output before passing to downstream systems.",
        "risk": "High",
    },
    "LLM06": {
        "name": "Excessive Agency",
        "desc": "LLM granted too much autonomy or permissions, enabling unintended actions.",
        "risk": "Critical",
    },
    "LLM07": {
        "name": "System Prompt Leakage",
        "desc": "Exposure of system prompt contents through model responses.",
        "risk": "Medium",
    },
    "LLM08": {
        "name": "Vector and Embedding Weaknesses",
        "desc": "Attacks targeting embedding models, vector stores, and RAG pipelines.",
        "risk": "High",
    },
    "LLM09": {
        "name": "Misinformation",
        "desc": "LLM generates false, misleading, or harmful content presented as fact.",
        "risk": "Medium",
    },
    "LLM10": {
        "name": "Unbounded Consumption",
        "desc": "Excessive resource consumption via token flooding, DoS, or cost harvesting.",
        "risk": "Medium",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# TEST ID → OWASP CATEGORY MAPPING
# ─────────────────────────────────────────────────────────────────────────────

TEST_TO_OWASP = {
    # VAPT — Prompt Injection → LLM01
    "PI-001": "LLM01",
    "PI-002": "LLM01",
    "PI-003": "LLM01",
    "PI-004": "LLM01",
    "PI-005": "LLM07",
    "PI-006": "LLM01",
    "PI-007": "LLM01",
    "PI-008": "LLM01",
    "PI-009": "LLM01",
    "PI-010": "LLM01",

    # VAPT — Data Leakage → LLM02 / LLM07
    "DL-001": "LLM07",
    "DL-002": "LLM07",
    "DL-003": "LLM02",
    "DL-004": "LLM02",
    "DL-005": "LLM07",
    "DL-006": "LLM02",
    "DL-007": "LLM07",
    "DL-008": "LLM02",

    # VAPT — Robustness → LLM01 / LLM10
    "RB-001": "LLM01",
    "RB-002": "LLM01",
    "RB-003": "LLM10",
    "RB-004": "LLM10",
    "RB-005": "LLM01",
    "RB-006": "LLM10",
    "RB-007": "LLM01",
    "RB-008": "LLM01",
    "RB-009": "LLM01",
    "RB-010": "LLM10",

    # Red Team — Jailbreaking → LLM01
    "JB-001": "LLM01",
    "JB-002": "LLM01",
    "JB-003": "LLM01",
    "JB-004": "LLM01",
    "JB-005": "LLM01",
    "JB-006": "LLM01",
    "JB-007": "LLM01",
    "JB-008": "LLM01",
    "JB-009": "LLM01",
    "JB-010": "LLM01",
    "JB-011": "LLM01",
    "JB-012": "LLM01",
    "JB-013": "LLM01",
    "JB-014": "LLM01",
    "JB-015": "LLM01",

    # Red Team — Harmful Content → LLM05
    "HC-001": "LLM05",
    "HC-002": "LLM05",
    "HC-003": "LLM05",
    "HC-004": "LLM05",
    "HC-005": "LLM05",
    "HC-006": "LLM05",
    "HC-007": "LLM09",
    "HC-008": "LLM05",
    "HC-009": "LLM05",
    "HC-010": "LLM05",
    "HC-011": "LLM06",
    "HC-012": "LLM05",

    # Provider-specific — OpenAI
    "OAI-001": "LLM07",
    "OAI-002": "LLM01",
    "OAI-003": "LLM01",
    "OAI-004": "LLM02",
    "OAI-005": "LLM01",
    "OAI-006": "LLM01",
    "OAI-007": "LLM07",
    "OAI-008": "LLM01",

    # Provider-specific — Anthropic
    "ANT-001": "LLM01",
    "ANT-002": "LLM01",
    "ANT-003": "LLM01",
    "ANT-004": "LLM01",
    "ANT-005": "LLM01",
    "ANT-006": "LLM01",
    "ANT-007": "LLM07",
    "ANT-008": "LLM01",

    # Provider-specific — Google
    "GEM-001": "LLM01",
    "GEM-002": "LLM01",
    "GEM-003": "LLM08",
    "GEM-004": "LLM01",
    "GEM-005": "LLM08",
    "GEM-006": "LLM02",

    # Provider-specific — Mistral
    "MST-001": "LLM01",
    "MST-002": "LLM01",
    "MST-003": "LLM05",
    "MST-004": "LLM07",
    "MST-005": "LLM01",

    # Provider-specific — Cohere
    "COH-001": "LLM08",
    "COH-002": "LLM06",
    "COH-003": "LLM08",
    "COH-004": "LLM07",

    # Provider-specific — Ollama
    "OLL-001": "LLM01",
    "OLL-002": "LLM01",
    "OLL-003": "LLM01",
    "OLL-004": "LLM02",
    "OLL-005": "LLM01",

    # Provider-specific — Azure
    "AZR-001": "LLM01",
    "AZR-002": "LLM02",
    "AZR-003": "LLM08",
    "AZR-004": "LLM07",

    # Provider-specific — Bedrock
    "BDR-001": "LLM01",
    "BDR-002": "LLM02",
    "BDR-003": "LLM08",

    # Provider-specific — Custom
    "CST-001": "LLM01",
    "CST-002": "LLM07",
    "CST-003": "LLM01",
    "CST-004": "LLM01",
    "CST-005": "LLM01",

    # ATLAS new tests
    "AT-REC-001": "LLM02",
    "AT-REC-002": "LLM02",
    "AT-REC-003": "LLM06",
    "AT-ACC-001": "LLM10",
    "AT-ACC-002": "LLM10",
    "AT-POI-001": "LLM04",
    "AT-POI-002": "LLM04",
    "AT-POI-003": "LLM04",
    "AT-CST-001": "LLM10",
    "AT-CST-002": "LLM10",
    "AT-INV-001": "LLM02",
    "AT-INV-002": "LLM02",
    "AT-DOS-001": "LLM10",
    "AT-DOS-002": "LLM10",
    "AT-PLG-001": "LLM06",
    "AT-PLG-002": "LLM06",
    "AT-PLG-003": "LLM06",
    "AT-ERI-001": "LLM09",
    "AT-ERI-002": "LLM01",
    "AT-HRM-001": "LLM05",
    "AT-HRM-002": "LLM05",
    "AT-HRM-003": "LLM05",
}


def enrich_owasp(test: dict) -> dict:
    """Add OWASP fields to a test dict."""
    t = dict(test)
    owasp_id  = TEST_TO_OWASP.get(t.get("id", ""), "N/A")
    owasp_cat = OWASP_CATEGORIES.get(owasp_id, {})
    t["owasp_id"]   = owasp_id
    t["owasp_name"] = owasp_cat.get("name", "Unknown")
    return t


def owasp_coverage(results: list) -> dict:
    """Compute per-OWASP-category pass/fail/warn counts."""
    coverage = {}
    for r in results:
        oid = r["test"].get("owasp_id", "N/A")
        if oid not in coverage:
            cat = OWASP_CATEGORIES.get(oid, {})
            coverage[oid] = {
                "name":  cat.get("name", "Unknown"),
                "risk":  cat.get("risk", "?"),
                "pass": 0, "fail": 0, "warn": 0, "error": 0,
            }
        v = r["result"]["verdict"].lower()
        if v in coverage[oid]:
            coverage[oid][v] += 1
    return coverage


def print_owasp_report(results: list):
    """Print OWASP LLM Top 10 coverage table."""
    coverage = owasp_coverage(results)
    width    = 72

    print("\n" + "═" * width)
    print(C.BOLD(C.CYAN("  OWASP LLM TOP 10 (2025) — COVERAGE REPORT")))
    print("═" * width + "\n")
    print(f"  {'ID':<8} {'Category':<35} {'PASS':>5} {'FAIL':>5} {'WARN':>5}")
    print(f"  {'─'*7} {'─'*34} {'─'*5} {'─'*5} {'─'*5}")

    untested = []
    for oid, cat in OWASP_CATEGORIES.items():
        if oid not in coverage:
            untested.append(oid)
            print(f"  {C.DIM(oid):<8} {C.DIM(cat['name']):<35} {C.DIM('—'):>5} {C.DIM('—'):>5} {C.DIM('—'):>5}  {C.DIM('not tested')}")
            continue

        data    = coverage[oid]
        n_fail  = data["fail"]
        n_warn  = data["warn"]
        n_pass  = data["pass"]
        icon    = C.RED("✗") if n_fail > 0 else (C.YELLOW("⚠") if n_warn > 0 else C.GREEN("✓"))
        id_str  = C.RED(oid) if n_fail > 0 else (C.YELLOW(oid) if n_warn > 0 else C.CYAN(oid))

        print(f"  {icon} {id_str:<15} {cat['name']:<35} "
              f"{C.GREEN(str(n_pass)):>5} {C.RED(str(n_fail)):>5} {C.YELLOW(str(n_warn)):>5}")

    if untested:
        print(f"\n  {C.DIM(f'{len(untested)} categories not tested in this run: ' + ', '.join(untested))}")

    # highlight worst categories
    failures = [(oid, d) for oid, d in coverage.items() if d["fail"] > 0]
    if failures:
        print(f"\n  {C.BOLD(C.RED('Failing OWASP categories:'))}")
        for oid, d in sorted(failures, key=lambda x: -x[1]["fail"]):
            cat = OWASP_CATEGORIES.get(oid, {})
            print(f"  {C.RED('→')} {C.BOLD(oid + ' ' + cat.get('name',''))}: "
                  f"{d['fail']} failure(s) — {cat.get('desc','')}")

    print("\n" + "═" * width + "\n")
