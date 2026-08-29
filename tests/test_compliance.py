# -*- coding: utf-8 -*-
"""Tests for compliance evidence mapping (SOC 2 / ISO 42001 / EU AI Act)."""
import json

import compliance


def _t(category="Jailbreaking", name="n", tags=None, tid="X-001",
       owasp_id=None, verdict="FAIL"):
    test = {
        "id": tid, "category": category, "name": name, "severity": "High",
        "payload": "p", "expected": "refusal", "tags": tags or [],
    }
    if owasp_id is not None:
        test["owasp_id"] = owasp_id
    return {"test": test, "result": {"verdict": verdict, "response_text": "", "reason": ""}}


# ── Framework registry ────────────────────────────────────────────────────────

def test_three_frameworks_defined():
    assert set(compliance.COMPLIANCE_FRAMEWORKS) == {"SOC2", "ISO42001", "EU_AI_ACT"}


def test_each_framework_has_controls():
    for fw, controls in compliance.COMPLIANCE_FRAMEWORKS.items():
        assert isinstance(controls, dict) and controls
        for cid, name in controls.items():
            assert isinstance(cid, str) and isinstance(name, str) and name


# ── map_finding ───────────────────────────────────────────────────────────────

def test_map_finding_returns_all_frameworks():
    mapping = compliance.map_finding(_t()["test"])
    assert set(mapping) == {"SOC2", "ISO42001", "EU_AI_ACT"}
    for fw, ids in mapping.items():
        assert isinstance(ids, list)


def test_map_finding_only_known_control_ids():
    for cat in ("Jailbreaking", "Data Leakage", "Harmful Content", "Robustness"):
        mapping = compliance.map_finding(_t(category=cat)["test"])
        for fw, ids in mapping.items():
            assert all(cid in compliance.COMPLIANCE_FRAMEWORKS[fw] for cid in ids)


def test_baseline_controls_always_present():
    # An unmatched / empty finding still maps to the baseline controls.
    mapping = compliance.map_finding(
        {"id": "Z", "category": "Totally Novel", "name": "", "tags": []})
    assert "CC7.2" in mapping["SOC2"]
    assert "A.6.2" in mapping["ISO42001"]
    assert "ART9" in mapping["EU_AI_ACT"]


def test_jailbreak_maps_to_access_and_robustness():
    mapping = compliance.map_finding(_t(category="Jailbreaking")["test"])
    assert "CC6.6" in mapping["SOC2"]
    assert "A.9.2" in mapping["ISO42001"]
    assert "ART15" in mapping["EU_AI_ACT"]


def test_data_leakage_maps_to_confidentiality():
    mapping = compliance.map_finding(_t(category="Data Leakage", tags=["disclosure"])["test"])
    assert "CC6.7" in mapping["SOC2"]
    assert "ART10" in mapping["EU_AI_ACT"]


def test_harmful_content_maps_to_prohibited_use():
    mapping = compliance.map_finding(
        _t(category="Harmful Content", tags=["weapon"])["test"])
    assert "ART5" in mapping["EU_AI_ACT"]
    assert "A.5.2" in mapping["ISO42001"]


def test_owasp_id_supplements_mapping():
    base = compliance.map_finding(_t(category="Misc", name="x", tags=[])["test"])
    enriched = compliance.map_finding(
        _t(category="Misc", name="x", tags=[], owasp_id="LLM06")["test"])
    # LLM06 (excessive agency) adds CC6.1 / A.9.3 / ART14
    assert "CC6.1" in enriched["SOC2"]
    assert "A.9.3" in enriched["ISO42001"]
    assert "ART14" in enriched["EU_AI_ACT"]
    assert len(enriched["SOC2"]) >= len(base["SOC2"])


def test_map_finding_dedups_control_ids():
    mapping = compliance.map_finding(
        _t(category="Prompt Injection", tags=["injection", "jailbreak"],
           owasp_id="LLM01")["test"])
    for ids in mapping.values():
        assert len(ids) == len(set(ids))


# ── compliance_summary ────────────────────────────────────────────────────────

def test_summary_has_all_frameworks_and_keys():
    summary = compliance.compliance_summary([_t()])
    assert set(summary) == {"SOC2", "ISO42001", "EU_AI_ACT"}
    for fw, data in summary.items():
        for key in ("total_controls", "controls_touched", "controls_failed",
                    "coverage_percent", "controls"):
            assert key in data
        assert data["total_controls"] == len(compliance.COMPLIANCE_FRAMEWORKS[fw])


def test_summary_counts_touched_and_failed():
    results = [
        _t(category="Jailbreaking", verdict="FAIL"),
        _t(category="Data Leakage", tags=["disclosure"], verdict="PASS"),
    ]
    summary = compliance.compliance_summary(results)
    for fw, data in summary.items():
        assert data["controls_touched"] >= 1
        # A FAIL exists, so at least one control should register a gap.
        assert data["controls_failed"] >= 1


def test_summary_pass_only_has_no_gaps():
    results = [_t(category="Jailbreaking", verdict="PASS")]
    summary = compliance.compliance_summary(results)
    for fw, data in summary.items():
        assert data["controls_failed"] == 0
        assert data["controls_touched"] >= 1


def test_summary_warn_counts_as_gap():
    results = [_t(category="Robustness", tags=["adversarial"], verdict="WARN")]
    summary = compliance.compliance_summary(results)
    assert summary["SOC2"]["controls_failed"] >= 1


def test_summary_empty_results():
    summary = compliance.compliance_summary([])
    for fw, data in summary.items():
        assert data["controls_touched"] == 0
        assert data["controls_failed"] == 0
        assert data["coverage_percent"] == 0.0


def test_coverage_percent_in_range():
    results = [_t(category=c, verdict="FAIL") for c in
               ("Jailbreaking", "Data Leakage", "Harmful Content", "Robustness")]
    summary = compliance.compliance_summary(results)
    for data in summary.values():
        assert 0.0 <= data["coverage_percent"] <= 100.0


# ── export_compliance_json ────────────────────────────────────────────────────

def test_export_json_writes_valid_pack(tmp_path):
    results = [
        _t(category="Jailbreaking", tid="JB-001", verdict="FAIL"),
        _t(category="Data Leakage", tid="DL-001", tags=["disclosure"], verdict="PASS"),
    ]
    out = tmp_path / "compliance.json"
    returned = compliance.export_compliance_json(results, str(out))
    assert returned == str(out)
    assert out.exists()

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["metadata"]["report_type"] == "compliance_evidence_pack"
    assert data["metadata"]["total_findings"] == 2
    assert set(data["frameworks"]) == {"SOC2", "ISO42001", "EU_AI_ACT"}

    for fw, fwdata in data["frameworks"].items():
        assert fwdata["total_controls"] == len(compliance.COMPLIANCE_FRAMEWORKS[fw])
        assert isinstance(fwdata["controls"], list)
        for ctrl in fwdata["controls"]:
            assert set(ctrl) == {"id", "name", "tested", "failed",
                                 "passing_findings", "failing_findings"}


def test_export_json_traces_finding_ids(tmp_path):
    results = [_t(category="Jailbreaking", tid="JB-007", verdict="FAIL")]
    out = tmp_path / "evidence.json"
    compliance.export_compliance_json(results, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    # The failing finding id should appear in at least one control's failing_findings.
    failing_ids = set()
    for fwdata in data["frameworks"].values():
        for ctrl in fwdata["controls"]:
            failing_ids.update(ctrl["failing_findings"])
    assert "JB-007" in failing_ids


def test_export_json_utf8_roundtrip(tmp_path):
    # A non-ASCII finding id is serialized verbatim into the evidence trail, so it
    # exercises ensure_ascii=False / encoding=utf-8 on the write path. Built from
    # escapes to keep this source pure-ASCII regardless of how the file is decoded.
    nonascii_id = "HC-éç-—001"  # e.g. "HC-éç-—001"
    row = _t(category="Harmful Content", name="bias probe",
             tags=["bias"], tid=nonascii_id, verdict="FAIL")
    out = tmp_path / "utf8.json"
    compliance.export_compliance_json([row], str(out))

    raw = out.read_text(encoding="utf-8")
    assert nonascii_id in raw           # written literally, not as \\u escapes
    assert "\\u00e9" not in raw         # ensure_ascii=False — no escaping
    data = json.loads(raw)              # still valid JSON
    assert data["metadata"]["total_findings"] == 1
