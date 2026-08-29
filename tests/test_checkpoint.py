"""Tests for checkpoint save/load/resume (isolated to a tmp file)."""
import pytest

import checkpoint


@pytest.fixture(autouse=True)
def isolate_checkpoint(tmp_path, monkeypatch):
    """Redirect the checkpoint file into tmp so tests never touch the real one."""
    monkeypatch.setattr(checkpoint, "CHECKPOINT_FILE", str(tmp_path / "cp.json"))
    yield


def _results():
    return [
        {"test": {"id": "PI-001", "severity": "Critical", "category": "PI",
                  "name": "n", "payload": "p", "expected": "refusal"},
         "result": {"verdict": "FAIL", "confidence": "high", "reason": "r",
                    "flagged_excerpt": "e", "status_code": 200,
                    "response_text": "x" * 1000, "raw_response": {"big": "obj"}}},
        {"test": {"id": "PI-002", "severity": "High", "category": "PI",
                  "name": "n2", "payload": "p2", "expected": "refusal"},
         "result": {"verdict": "PASS", "response_text": "ok"}},
    ]


def test_save_creates_file_and_has_checkpoint():
    assert checkpoint.has_checkpoint() is False
    checkpoint.save_checkpoint("run1", "vapt", {"schema": "openai"},
                               ["PI-001", "PI-002", "PI-003"], _results())
    assert checkpoint.has_checkpoint() is True


def test_save_load_roundtrip():
    checkpoint.save_checkpoint("run1", "vapt", {"schema": "openai", "model": "m"},
                               ["PI-001", "PI-002", "PI-003"], _results())
    cp = checkpoint.load_checkpoint()
    assert cp["run_id"] == "run1"
    assert cp["total"] == 3
    assert cp["completed"] == 2
    assert set(cp["done_ids"]) == {"PI-001", "PI-002"}


def test_serialize_strips_raw_response_and_trims_text():
    cp_results = checkpoint._serialize_results(_results())
    assert "raw_response" not in cp_results[0]["result"]
    assert len(cp_results[0]["result"]["response_text"]) <= 500


def test_resume_returns_done_and_remaining():
    all_tests = [{"id": "PI-001"}, {"id": "PI-002"}, {"id": "PI-003"}]
    checkpoint.save_checkpoint("run1", "vapt", {"schema": "openai"},
                               ["PI-001", "PI-002", "PI-003"], _results())
    cp = checkpoint.load_checkpoint()
    done, remaining = checkpoint.resume_checkpoint(cp, all_tests)
    assert len(done) == 2
    assert [t["id"] for t in remaining] == ["PI-003"]


def test_clear_checkpoint_removes_file():
    checkpoint.save_checkpoint("r", "vapt", {}, ["A"], [])
    assert checkpoint.has_checkpoint()
    checkpoint.clear_checkpoint()
    assert not checkpoint.has_checkpoint()


def test_load_missing_returns_none():
    assert checkpoint.load_checkpoint() is None
