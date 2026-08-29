"""Tests for SQLite trend tracking (isolated to a tmp DB)."""
import trend


def _scores(score, fail=0, warn=0, error=0, npass=0):
    return {
        "overall_risk_score": score, "risk_level": "HIGH" if score >= 45 else "LOW",
        "totals": {"pass": npass, "fail": fail, "warn": warn, "error": error},
    }


def _cfg(model="gpt-4o"):
    return {"schema": "openai", "model": model, "endpoint": "https://api.example.com"}


def test_save_and_get_history(tmp_path):
    db = str(tmp_path / "h.db")
    trend.save_run(_cfg(), "vapt", _scores(30, fail=3), db_path=db, timestamp="2026-01-01T10:00:00")
    rows = trend.get_history(db, limit=10)
    assert len(rows) == 1
    assert rows[0]["score"] == 30
    assert rows[0]["mode"] == "vapt"
    assert rows[0]["n_fail"] == 3


def test_endpoint_is_hashed_not_stored_raw(tmp_path):
    db = str(tmp_path / "h.db")
    trend.save_run(_cfg(), "vapt", _scores(10), db_path=db)
    row = trend.get_history(db, limit=1)[0]
    assert "example.com" not in (row["endpoint_hash"] or "")
    assert len(row["endpoint_hash"]) == 12


def test_history_newest_first(tmp_path):
    db = str(tmp_path / "h.db")
    trend.save_run(_cfg(), "vapt", _scores(10), db_path=db, timestamp="2026-01-01T10:00:00")
    trend.save_run(_cfg(), "vapt", _scores(40), db_path=db, timestamp="2026-01-02T10:00:00")
    rows = trend.get_history(db, limit=10)
    assert rows[0]["score"] == 40  # newest first


def test_regression_delta(tmp_path):
    db = str(tmp_path / "h.db")
    trend.save_run(_cfg("m"), "vapt", _scores(20, fail=2), db_path=db, timestamp="2026-01-01T10:00:00")
    trend.save_run(_cfg("m"), "vapt", _scores(50, fail=5), db_path=db, timestamp="2026-01-02T10:00:00")
    d = trend.regression_delta(db, mode="vapt", model="m")
    assert d["delta"] == 30
    assert d["new_fails"] == 3


def test_get_history_missing_db_is_empty(tmp_path):
    assert trend.get_history(str(tmp_path / "nope.db")) == []


def test_save_run_never_raises_on_bad_path():
    # An unwritable path must not crash a run — history is best-effort.
    assert trend.save_run(_cfg(), "vapt", _scores(10),
                          db_path="/nonexistent-dir-xyz/sub/h.db") is None
