"""Tests for the threat_ontology module (AIRT block + cross-framework tags)."""
import threat_ontology as TO


def _t(**kw):
    base = {
        "id": "X-001",
        "category": "Jailbreaking",
        "severity": "Critical",
        "name": "n",
        "payload": "p",
        "expected": "refusal",
        "tags": [],
    }
    base.update(kw)
    return base


# ── ontology_for: shape ───────────────────────────────────────────────────────

def test_ontology_has_all_keys():
    onto = TO.ontology_for(_t())
    for k in ("actor", "tactic", "technique", "cwe", "cwe_name",
              "impact", "mitigation"):
        assert k in onto
        assert isinstance(onto[k], str)


def test_ontology_never_raises_on_minimal_test():
    # Only the required schema keys, no atlas/owasp/nist enrichment.
    onto = TO.ontology_for({"id": "Z", "category": "", "name": "",
                            "severity": "Low", "payload": "p",
                            "expected": "refusal", "tags": []})
    assert onto["actor"]
    assert onto["cwe"].startswith("CWE-")
    assert onto["mitigation"]


# ── Actor inference ───────────────────────────────────────────────────────────

def test_actor_scanner_for_robustness():
    assert TO.ontology_for(_t(category="Robustness"))["actor"] == "Automated Scanner"


def test_actor_insider_for_leakage():
    assert TO.ontology_for(_t(category="Data Leakage"))["actor"] == "Insider"


def test_actor_default_adversarial_user():
    assert TO.ontology_for(_t(category="Jailbreaking"))["actor"] == "Adversarial User"


# ── CWE mapping ───────────────────────────────────────────────────────────────

def test_cwe_injection():
    assert TO.ontology_for(_t(category="Prompt Injection"))["cwe"] == "CWE-89"


def test_cwe_jailbreak_default_family():
    assert TO.ontology_for(_t(category="Jailbreaking"))["cwe"] == "CWE-693"


def test_cwe_exfil_leak():
    assert TO.ontology_for(_t(category="Data Leakage", tags=["exfil"]))["cwe"] == "CWE-200"


def test_cwe_unknown_defaults_to_693():
    assert TO.ontology_for(_t(category="Totally Novel"))["cwe"] == "CWE-693"


def test_cwe_name_populated_for_known_cwe():
    onto = TO.ontology_for(_t(category="Prompt Injection"))
    assert onto["cwe_name"]  # non-empty for CWE-89


# ── Impact mapping ────────────────────────────────────────────────────────────

def test_impact_harmful_content():
    assert TO.ontology_for(_t(category="Harmful Content"))["impact"] == "Harmful Content"


def test_impact_exfiltration():
    assert TO.ontology_for(_t(category="Data Leakage"))["impact"] == "Data Exfiltration"


def test_impact_privilege_escalation():
    onto = TO.ontology_for(_t(category="Excessive Agency", tags=["tool", "plugin"]))
    assert onto["impact"] == "Privilege Escalation"


def test_impact_policy_violation_default():
    assert TO.ontology_for(_t(category="Jailbreaking"))["impact"] == "Policy Violation"


def test_mitigation_matches_impact():
    onto = TO.ontology_for(_t(category="Data Leakage"))
    assert "redact" in onto["mitigation"].lower()


# ── Tactic resolution ─────────────────────────────────────────────────────────

def test_tactic_from_explicit_tactic_id():
    # AML.TA0005 == ML Attack Staging in the ATLAS registry.
    onto = TO.ontology_for(_t(atlas_tactic="AML.TA0005", atlas_id="AML.T0054"))
    assert onto["tactic"] == "ML Attack Staging"


def test_tactic_derived_from_technique_when_no_tactic_id():
    # AML.T0054 (Indirect Prompt Injection) -> parent tactic ML Attack Staging.
    onto = TO.ontology_for(_t(atlas_id="AML.T0054"))
    assert onto["tactic"] == "ML Attack Staging"


def test_tactic_unknown_when_no_atlas_data():
    assert TO.ontology_for(_t())["tactic"] == "Unknown Tactic"


def test_technique_passthrough():
    assert TO.ontology_for(_t(atlas_id="AML.T0051"))["technique"] == "AML.T0051"


def test_technique_defaults_to_na():
    assert TO.ontology_for(_t())["technique"] == "N/A"


# ── inline_tags ───────────────────────────────────────────────────────────────

def test_inline_tags_format_with_full_enrichment():
    t = _t(nist_rmf="MEASURE", owasp_id="LLM01", atlas_id="AML.T0054")
    assert TO.inline_tags(t) == "[NIST: MEASURE][OWASP: LLM01][ATLAS: AML.T0054]"


def test_inline_tags_derives_when_unenriched():
    # No nist_rmf / owasp_id / atlas_id present -> derived NIST + OWASP at least.
    tags = TO.inline_tags(_t(id="JB-001", category="Jailbreaking"))
    assert "[NIST:" in tags
    assert "[OWASP:" in tags


def test_inline_tags_omits_na_atlas():
    tags = TO.inline_tags(_t(nist_rmf="GOVERN", owasp_id="LLM01", atlas_id="N/A"))
    assert "ATLAS" not in tags
    assert "[NIST: GOVERN]" in tags
    assert "[OWASP: LLM01]" in tags


def test_inline_tags_returns_string():
    assert isinstance(TO.inline_tags(_t()), str)


# ── print_threat_block ────────────────────────────────────────────────────────

def test_print_threat_block_runs(capsys):
    t = _t(category="Prompt Injection", atlas_id="AML.T0051",
           atlas_tactic="AML.TA0005")
    TO.print_threat_block(t, {"verdict": "FAIL"})
    out = capsys.readouterr().out
    assert "AIRT THREAT BLOCK" in out
    assert "ACTOR" in out
    assert "CWE-89" in out
    assert "FAIL" in out


def test_print_threat_block_handles_missing_result_fields(capsys):
    TO.print_threat_block(_t(), {})
    out = capsys.readouterr().out
    assert "AIRT THREAT BLOCK" in out
    assert "ERROR" in out  # default verdict
