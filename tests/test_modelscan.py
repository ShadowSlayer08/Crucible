"""Tests for modelscan.py — the model-artifact supply-chain scanner.

The scanner disassembles pickle opcodes with pickletools and NEVER unpickles, so
the malicious fixtures below are analysed without their payloads ever running.
"""
import json
import os
import pickle

import pytest

import modelscan


# ── Fixtures: crafted pickle streams (created but NEVER unpickled) ────────────
class _Exploit:
    """__reduce__ makes unpickling call os.system — the classic poisoned-model RCE."""
    def __reduce__(self):
        return (os.system, ("echo pwned",))


class _EvalExploit:
    def __reduce__(self):
        return (eval, ("__import__('os').listdir('.')",))


def _malicious_bytes(protocol):
    return pickle.dumps(_Exploit(), protocol=protocol)


# ── Pickle scanning ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("protocol", [0, 2, pickle.DEFAULT_PROTOCOL])
def test_malicious_pickle_flagged_critical(protocol):
    findings = modelscan.scan_pickle_bytes(_malicious_bytes(protocol), "evil.pkl")
    crit = [f for f in findings if f.severity == "CRITICAL"]
    assert crit, f"expected a CRITICAL finding at protocol {protocol}: {findings}"
    # the sink reference should name the system() call regardless of os/nt/posix
    assert any("system" in f.reference for f in crit)
    assert all(f.kind == "pickle-code-exec" for f in crit)


def test_eval_sink_flagged_critical():
    findings = modelscan.scan_pickle_bytes(pickle.dumps(_EvalExploit()), "evil2.pkl")
    assert any(f.severity == "CRITICAL" and "eval" in f.reference for f in findings)


def test_benign_pickle_not_dangerous():
    blob = pickle.dumps({"weights": [1.0, 2.0, 3.0], "name": "toy", "layers": (1, 2)})
    findings = modelscan.scan_pickle_bytes(blob, "clean.pkl")
    assert not any(modelscan.SEVERITY_ORDER[f.severity] >= modelscan.SEVERITY_ORDER["HIGH"]
                   for f in findings)


def test_dangerous_import_without_direct_sink_is_high():
    # A reduce over subprocess.Popen — dangerous module, code execution.
    import subprocess
    class _P:
        def __reduce__(self):
            return (subprocess.Popen, (["echo", "hi"],))
    findings = modelscan.scan_pickle_bytes(pickle.dumps(_P()), "p.pkl")
    assert any(f.severity == "CRITICAL" for f in findings)  # subprocess.Popen is a sink


def test_truncated_pickle_reports_parse_error():
    blob = _malicious_bytes(2)[:10]  # cut mid-stream
    findings = modelscan.scan_pickle_bytes(blob, "trunc.pkl")
    assert any(f.kind in ("pickle-parse-error", "pickle-code-exec") for f in findings)


# ── Config scanning ──────────────────────────────────────────────────────────
def test_config_trust_remote_code_flagged(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"model_type": "custom", "trust_remote_code": True}))
    findings = modelscan.scan_config(str(p))
    assert any(f.kind == "config-remote-code" and f.severity == "HIGH" for f in findings)


def test_config_auto_map_flagged(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"auto_map": {"AutoModel": "modeling_custom.MyModel"}}))
    findings = modelscan.scan_config(str(p))
    assert any(f.kind == "config-auto-map" for f in findings)


def test_clean_config_no_findings(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"hidden_size": 768, "num_layers": 12}))
    assert modelscan.scan_config(str(p)) == []


# ── safetensors is safe-by-format ────────────────────────────────────────────
def test_safetensors_reported_safe(tmp_path):
    p = tmp_path / "model.safetensors"
    header = json.dumps({"__metadata__": {"format": "pt"}}).encode()
    with open(p, "wb") as f:
        f.write(len(header).to_bytes(8, "little"))
        f.write(header)
    findings = modelscan.scan_safetensors(str(p))
    assert any(f.kind == "safetensors-safe" and f.severity == "INFO" for f in findings)


# ── Directory scan + report aggregation ──────────────────────────────────────
def test_scan_path_directory_flags_dangerous(tmp_path):
    (tmp_path / "evil.pkl").write_bytes(_malicious_bytes(2))
    (tmp_path / "clean.pkl").write_bytes(pickle.dumps({"ok": True}))
    (tmp_path / "config.json").write_text(json.dumps({"hidden_size": 10}))
    report = modelscan.scan_path(str(tmp_path))
    assert report.is_dangerous is True
    assert report.overall == "CRITICAL"
    assert len(report.scanned_files) == 3


def test_scan_path_clean_directory_is_safe(tmp_path):
    (tmp_path / "clean.pkl").write_bytes(pickle.dumps({"ok": True}))
    (tmp_path / "model.safetensors").write_bytes(
        (2).to_bytes(8, "little") + b"{}")
    report = modelscan.scan_path(str(tmp_path))
    assert report.is_dangerous is False
    assert report.overall in ("SAFE", "INFO")


def test_scan_path_missing_target():
    report = modelscan.scan_path("does-not-exist-xyz.pkl")
    assert report.skipped_files and report.overall == "SAFE"


def test_report_to_dict_shape(tmp_path):
    (tmp_path / "evil.pkl").write_bytes(_malicious_bytes(2))
    d = modelscan.report_to_dict(modelscan.scan_path(str(tmp_path)))
    assert d["is_dangerous"] is True
    assert d["overall"] == "CRITICAL"
    assert isinstance(d["findings"], list) and d["findings"]
    for key in ("source", "severity", "kind", "detail"):
        assert key in d["findings"][0]


def test_print_report_smoke(tmp_path, capsys):
    (tmp_path / "evil.pkl").write_bytes(_malicious_bytes(2))
    modelscan.print_model_scan_report(modelscan.scan_path(str(tmp_path)))
    out = capsys.readouterr().out
    assert "MODEL SUPPLY-CHAIN SCAN" in out
    assert "CRITICAL" in out
