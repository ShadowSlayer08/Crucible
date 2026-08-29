"""
Compliance Evidence Mapping — SOC 2 / ISO 42001 / EU AI Act
Roadmap milestone: "Compliance evidence report SOC2/ISO42001/EU AI Act".

Maps red-team findings to the control families of three governance frameworks so a
red-team run doubles as audit evidence. The mapping is deliberately conservative and
keyed off the data already attached to each test dict (category, tags, and the
optional atlas_id / owasp_id enrichment fields) — no network calls, pure stdlib.

Frameworks covered:
    SOC2      → Trust Services Criteria (AICPA TSC 2017, common + processing-integrity)
    ISO42001  → ISO/IEC 42001:2023 AI Management System Annex A controls
    EU_AI_ACT → EU AI Act (Reg. 2024/1689) obligations for high-risk / GPAI systems

Public API:
    COMPLIANCE_FRAMEWORKS         -> framework -> {control_id: control_name}
    map_finding(test)             -> {framework: [control_ids]}
    compliance_summary(results)   -> per-framework coverage (#touched, #with failures)
    print_compliance_report(results)
    export_compliance_json(results, path)
"""

import json
from datetime import datetime

import colors as C


# ─────────────────────────────────────────────────────────────────────────────
# CONTROL FAMILY REGISTRY
# Each framework -> ordered dict of {control_id: human-readable control name}.
# ─────────────────────────────────────────────────────────────────────────────

COMPLIANCE_FRAMEWORKS = {

    # ── SOC 2 — AICPA Trust Services Criteria ────────────────────────────────
    "SOC2": {
        "CC6.1": "Logical access — restrict system access to authorized users",
        "CC6.6": "Logical access — protect against external threats / boundary controls",
        "CC6.7": "Logical access — restrict transmission and disclosure of information",
        "CC7.1": "System operations — detect and monitor anomalous activity",
        "CC7.2": "System operations — monitor for security events and incidents",
        "CC8.1": "Change management — control changes to infrastructure and software",
        "PI1.1": "Processing integrity — outputs are complete, valid, and accurate",
        "PI1.4": "Processing integrity — outputs are delivered only to authorized parties",
        "A1.1":  "Availability — capacity and resource consumption are managed",
    },

    # ── ISO/IEC 42001:2023 — AI Management System (Annex A) ──────────────────
    "ISO42001": {
        "A.5.2":  "AI policy — establish acceptable-use and responsible-AI policy",
        "A.6.2":  "AI system lifecycle — risk assessment and impact evaluation",
        "A.7.4":  "Data for AI — quality, provenance, and poisoning resistance",
        "A.8.2":  "Information for interested parties — system documentation",
        "A.8.3":  "AI system operation — controls over use and misuse",
        "A.9.2":  "Use of AI — guardrails against unintended or prohibited use",
        "A.9.3":  "Use of AI — human oversight and intervention controls",
        "A.10.2": "Third-party / supply chain — controls over external components",
    },

    # ── EU AI Act (Regulation 2024/1689) — high-risk + GPAI obligations ──────
    "EU_AI_ACT": {
        "ART9":  "Article 9 — risk management system for high-risk AI",
        "ART10": "Article 10 — data and data governance (quality, bias, poisoning)",
        "ART13": "Article 13 — transparency and provision of information to users",
        "ART14": "Article 14 — human oversight",
        "ART15": "Article 15 — accuracy, robustness, and cybersecurity",
        "ART5":  "Article 5 — prohibited AI practices (manipulation, exploitation)",
        "ART50": "Article 50 — transparency obligations for certain AI systems",
        "ART55": "Article 55 — obligations for GPAI models with systemic risk",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# MAPPING RULES
# A finding is described by its category + tags (+ optional atlas_id / owasp_id).
# We resolve each signal to a set of control ids per framework. The matcher is a
# keyword scan so it survives the many category spellings across the payload pools.
# ─────────────────────────────────────────────────────────────────────────────

# (keyword tuple) -> {framework: [control_ids]}.  First-to-last; ALL matches union.
_KEYWORD_CONTROLS = [
    # Prompt injection / jailbreaking / persona bypass → access boundary + robustness
    (("injection", "jailbreak", "persona", "override", "bypass", "obfuscat",
      "encoding", "smuggl", "leetspeak", "base64", "rot13"),
     {"SOC2": ["CC6.6", "CC6.1"],
      "ISO42001": ["A.9.2", "A.8.3"],
      "EU_AI_ACT": ["ART15", "ART5"]}),

    # Data leakage / system-prompt / credential disclosure → confidentiality
    (("leakage", "leak", "disclosure", "exfil", "credential", "system prompt",
      "system-prompt", "pii", "privacy", "inversion", "membership"),
     {"SOC2": ["CC6.7", "PI1.4"],
      "ISO42001": ["A.7.4", "A.8.2"],
      "EU_AI_ACT": ["ART10", "ART13"]}),

    # Harmful content / safety / prohibited use → acceptable-use governance
    (("harmful", "harm", "weapon", "cbrn", "explosive", "self-harm", "suicide",
      "hate", "extremis", "radicaliz", "csam", "minor", "drug", "violen", "bias"),
     {"SOC2": ["PI1.1"],
      "ISO42001": ["A.5.2", "A.9.2"],
      "EU_AI_ACT": ["ART5", "ART9"]}),

    # Robustness / adversarial perturbation → accuracy & robustness
    (("robustness", "adversarial", "perturbation", "evasion", "noise"),
     {"SOC2": ["PI1.1"],
      "ISO42001": ["A.6.2"],
      "EU_AI_ACT": ["ART15"]}),

    # Resource / DoS / unbounded consumption → availability
    (("dos", "denial", "consumption", "token flood", "flood", "rate limit",
      "rate-limit", "cost", "unbounded", "exhaust"),
     {"SOC2": ["A1.1", "CC7.1"],
      "ISO42001": ["A.6.2"],
      "EU_AI_ACT": ["ART15"]}),

    # Tool / plugin / agent / orchestration → excessive agency & oversight
    (("tool", "plugin", "agent", "orchestrat", "permission", "escalation",
      "excessive agency", "autonomy", "mcp", "swarm", "consensus"),
     {"SOC2": ["CC6.1", "CC8.1"],
      "ISO42001": ["A.9.3", "A.8.3"],
      "EU_AI_ACT": ["ART14", "ART9"]}),

    # RAG / vector / embedding / memory / poisoning / supply chain → data governance
    (("rag", "vector", "embedding", "memory", "poison", "supply chain",
      "supply-chain", "document", "retrieval", "context integrity"),
     {"SOC2": ["CC8.1", "CC7.2"],
      "ISO42001": ["A.7.4", "A.10.2"],
      "EU_AI_ACT": ["ART10", "ART55"]}),

    # Reconnaissance / discovery / model recon → monitoring & transparency
    (("reconnaissance", "recon", "discovery", "enumeration", "fingerprint"),
     {"SOC2": ["CC7.1"],
      "ISO42001": ["A.8.2"],
      "EU_AI_ACT": ["ART13"]}),

    # Misinformation / hallucination → processing integrity & transparency
    (("misinformation", "hallucinat", "fabricat", "false", "defamation"),
     {"SOC2": ["PI1.1"],
      "ISO42001": ["A.8.2"],
      "EU_AI_ACT": ["ART13", "ART50"]}),
]

# Baseline controls every finding contributes to: red-teaming itself is evidence of
# an operating risk-management process, so the run touches these regardless of topic.
_BASELINE_CONTROLS = {
    "SOC2": ["CC7.2"],
    "ISO42001": ["A.6.2"],
    "EU_AI_ACT": ["ART9"],
}

# OWASP LLM Top-10 id → supplemental control hints (only ids present in COMPLIANCE_FRAMEWORKS).
_OWASP_CONTROLS = {
    "LLM01": {"SOC2": ["CC6.6"], "ISO42001": ["A.9.2"], "EU_AI_ACT": ["ART15"]},
    "LLM02": {"SOC2": ["CC6.7"], "ISO42001": ["A.8.2"], "EU_AI_ACT": ["ART10"]},
    "LLM03": {"SOC2": ["CC8.1"], "ISO42001": ["A.10.2"], "EU_AI_ACT": ["ART55"]},
    "LLM04": {"SOC2": ["CC8.1"], "ISO42001": ["A.7.4"], "EU_AI_ACT": ["ART10"]},
    "LLM05": {"SOC2": ["PI1.1"], "ISO42001": ["A.8.3"], "EU_AI_ACT": ["ART15"]},
    "LLM06": {"SOC2": ["CC6.1"], "ISO42001": ["A.9.3"], "EU_AI_ACT": ["ART14"]},
    "LLM07": {"SOC2": ["CC6.7"], "ISO42001": ["A.8.2"], "EU_AI_ACT": ["ART13"]},
    "LLM08": {"SOC2": ["CC7.2"], "ISO42001": ["A.7.4"], "EU_AI_ACT": ["ART10"]},
    "LLM09": {"SOC2": ["PI1.1"], "ISO42001": ["A.8.2"], "EU_AI_ACT": ["ART50"]},
    "LLM10": {"SOC2": ["A1.1"], "ISO42001": ["A.6.2"], "EU_AI_ACT": ["ART15"]},
}


def _haystack(test: dict) -> str:
    """Lower-cased blob of the matchable text fields on a test/finding."""
    return " ".join([
        str(test.get("category", "")),
        str(test.get("name", "")),
        " ".join(test.get("tags", []) or []),
    ]).lower()


def _merge(into: dict, frameworks: dict) -> None:
    """Union the per-framework control-id lists from *frameworks* into *into*."""
    for fw, ids in frameworks.items():
        valid = COMPLIANCE_FRAMEWORKS.get(fw, {})
        bucket = into.setdefault(fw, [])
        for cid in ids:
            if cid in valid and cid not in bucket:
                bucket.append(cid)


def map_finding(test: dict) -> dict:
    """
    Map a single test/finding to the control families it provides evidence for.

    Returns {framework: [control_ids]} containing only known control ids, with the
    baseline risk-management controls always included. Every framework key is present
    (possibly with just the baseline control) so downstream code never KeyErrors.
    """
    mapping: dict = {fw: [] for fw in COMPLIANCE_FRAMEWORKS}

    # Baseline first so it always appears even for an unmatched finding.
    _merge(mapping, _BASELINE_CONTROLS)

    haystack = _haystack(test)
    for keywords, frameworks in _KEYWORD_CONTROLS:
        if any(k in haystack for k in keywords):
            _merge(mapping, frameworks)

    owasp_id = test.get("owasp_id", "") or ""
    if owasp_id in _OWASP_CONTROLS:
        _merge(mapping, _OWASP_CONTROLS[owasp_id])

    # Stable, predictable ordering (registry order) for deterministic evidence packs.
    for fw, ids in mapping.items():
        order = list(COMPLIANCE_FRAMEWORKS[fw].keys())
        ids.sort(key=lambda c: order.index(c) if c in order else len(order))

    return mapping


def _is_failure(verdict: str) -> bool:
    """A finding counts as a control gap when the model failed or partially complied."""
    return verdict in ("FAIL", "WARN", "PARTIAL_REFUSAL")


def compliance_summary(results: list) -> dict:
    """
    Per-framework coverage across a results list.

    Each results row is the standard {"test": {...}, "result": {"verdict": ...}} shape.

    Returns, per framework:
        total_controls    : number of controls defined in the framework
        controls_touched  : count of distinct controls any finding mapped to
        controls_failed   : count of distinct controls with >=1 failing finding
        coverage_percent  : controls_touched / total_controls * 100 (rounded 1dp)
        controls          : {control_id: {name, tested, failed}} detail
    """
    summary = {}
    for fw, controls in COMPLIANCE_FRAMEWORKS.items():
        summary[fw] = {
            "total_controls": len(controls),
            "controls_touched": 0,
            "controls_failed": 0,
            "coverage_percent": 0.0,
            "controls": {cid: {"name": name, "tested": 0, "failed": 0}
                         for cid, name in controls.items()},
        }

    for r in results:
        verdict = r.get("result", {}).get("verdict", "")
        failed = _is_failure(verdict)
        mapping = map_finding(r.get("test", {}))
        for fw, ids in mapping.items():
            fw_controls = summary[fw]["controls"]
            for cid in ids:
                if cid not in fw_controls:
                    continue
                fw_controls[cid]["tested"] += 1
                if failed:
                    fw_controls[cid]["failed"] += 1

    for fw, data in summary.items():
        touched = sum(1 for c in data["controls"].values() if c["tested"] > 0)
        failed = sum(1 for c in data["controls"].values() if c["failed"] > 0)
        data["controls_touched"] = touched
        data["controls_failed"] = failed
        data["coverage_percent"] = (
            round(touched / data["total_controls"] * 100, 1)
            if data["total_controls"] else 0.0
        )
    return summary


_FRAMEWORK_LABEL = {
    "SOC2":      "SOC 2 (AICPA Trust Services Criteria)",
    "ISO42001":  "ISO/IEC 42001:2023 (AI Management System)",
    "EU_AI_ACT": "EU AI Act (Regulation 2024/1689)",
}


def print_compliance_report(results: list) -> None:
    """Print a per-framework control-coverage compliance evidence summary."""
    summary = compliance_summary(results)
    width = 78

    print("\n" + "═" * width)
    print(C.BOLD(C.CYAN("  COMPLIANCE EVIDENCE — SOC 2 / ISO 42001 / EU AI ACT")))
    print("═" * width)

    for fw in ("SOC2", "ISO42001", "EU_AI_ACT"):
        data = summary[fw]
        label = _FRAMEWORK_LABEL.get(fw, fw)
        touched = data["controls_touched"]
        total = data["total_controls"]
        failed = data["controls_failed"]
        cov = data["coverage_percent"]
        cov_col = C.GREEN if cov >= 60 else (C.YELLOW if cov >= 30 else C.DIM)
        fail_col = C.RED if failed else C.DIM

        print(f"\n  {C.BOLD(label)}")
        print(f"  {'─' * (width - 4)}")
        print(f"  Controls touched : {cov_col(f'{touched}/{total}')}  "
              f"({cov_col(f'{cov:.1f}%')} coverage)   "
              f"with findings: {fail_col(str(failed))}")
        print(f"  {'Control':<10} {'Tested':>7} {'Gaps':>6}   Name")
        print(f"  {'─' * 9} {'─' * 7} {'─' * 6}   {'─' * (width - 30)}")
        for cid, c in data["controls"].items():
            tested = c["tested"]
            gaps = c["failed"]
            if tested == 0:
                id_disp = C.DIM(cid)
                tested_disp = C.DIM("—")
                gaps_disp = C.DIM("—")
            else:
                gcol = C.RED if gaps else C.GREEN
                id_disp = (C.RED if gaps else C.CYAN)(cid)
                tested_disp = str(tested)
                gaps_disp = gcol(str(gaps))
            name = c["name"]
            if len(name) > width - 32:
                name = name[:width - 35] + "..."
            print(f"  {id_disp:<19} {tested_disp:>7} {gaps_disp:>6}   {C.DIM(name)}")

    print("\n  " + C.DIM("Note: 'Gaps' = controls with >=1 failing finding (FAIL / WARN / "
                         "partial refusal). Evidence, not a certification."))
    print("═" * width + "\n")


def export_compliance_json(results: list, path: str) -> str:
    """
    Write a SOC 2 / ISO 42001 / EU AI Act evidence-pack JSON to *path*.

    The pack contains, per framework: the coverage summary, every control with its
    tested/failed counts, and the list of finding ids that map to each control (so an
    auditor can trace evidence back to specific test cases).
    """
    summary = compliance_summary(results)

    # Build per-control evidence: control_id -> [finding ids that mapped to it].
    evidence: dict = {fw: {cid: {"pass": [], "fail": []}
                           for cid in COMPLIANCE_FRAMEWORKS[fw]}
                      for fw in COMPLIANCE_FRAMEWORKS}
    for r in results:
        test = r.get("test", {})
        fid = test.get("id", "UNKNOWN")
        verdict = r.get("result", {}).get("verdict", "")
        failed = _is_failure(verdict)
        mapping = map_finding(test)
        for fw, ids in mapping.items():
            for cid in ids:
                if cid in evidence[fw]:
                    evidence[fw][cid]["fail" if failed else "pass"].append(fid)

    pack = {
        "metadata": {
            "report_type": "compliance_evidence_pack",
            "generated":   datetime.now().isoformat(),
            "frameworks":  list(COMPLIANCE_FRAMEWORKS.keys()),
            "total_findings": len(results),
            "disclaimer": ("Red-team evidence mapping. Demonstrates control testing "
                           "activity; not an attestation or certification of compliance."),
        },
        "frameworks": {},
    }

    for fw in COMPLIANCE_FRAMEWORKS:
        data = summary[fw]
        pack["frameworks"][fw] = {
            "name": _FRAMEWORK_LABEL.get(fw, fw),
            "total_controls":   data["total_controls"],
            "controls_touched": data["controls_touched"],
            "controls_failed":  data["controls_failed"],
            "coverage_percent": data["coverage_percent"],
            "controls": [
                {
                    "id":     cid,
                    "name":   COMPLIANCE_FRAMEWORKS[fw][cid],
                    "tested": data["controls"][cid]["tested"],
                    "failed": data["controls"][cid]["failed"],
                    "passing_findings": evidence[fw][cid]["pass"],
                    "failing_findings": evidence[fw][cid]["fail"],
                }
                for cid in COMPLIANCE_FRAMEWORKS[fw]
            ],
        }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(pack, f, indent=2, ensure_ascii=False)
    print(f"  {C.GREEN('✓')} Compliance evidence pack saved → {path}")
    return path
