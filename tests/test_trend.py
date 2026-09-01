"""Tests for SQLite trend tracking (isolated to a tmp DB)."""
import trend


def _scores(score, fail=0, warn=0, error=0, npass=0, silent=0):
    return {
        "overall_risk_score": score, "risk_level": "HIGH" if score >= 45 else "LOW",
        "totals": {"pass": npass, "fail": fail, "warn": warn, "error": error,
                   "silent": silent},
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


# ── SILENT persistence (roadmap #38) ─────────────────────────────────────────
def test_silent_count_persisted(tmp_path):
    db = str(tmp_path / "h.db")
    trend.save_run(_cfg(), "policy", _scores(30, fail=2, silent=4), db_path=db)
    row = trend.get_history(db, limit=1)[0]
    assert row["n_silent"] == 4
    # total counts every evaluated verdict incl. silent
    assert row["total"] == row["n_pass"] + row["n_fail"] + row["n_warn"] \
        + row["n_error"] + row["n_silent"]


def test_export_history_includes_silent_column(tmp_path):
    db = str(tmp_path / "h.db")
    trend.save_run(_cfg(), "vapt", _scores(20, silent=3), db_path=db)
    out = str(tmp_path / "hist.csv")
    trend.export_history_csv(out, db_path=db)
    header = open(out, encoding="utf-8").readline()
    assert "n_silent" in header


def test_migration_adds_silent_column_to_old_db(tmp_path):
    # Simulate a pre-#38 DB: a runs table with no n_silent column.
    import sqlite3
    db = str(tmp_path / "old.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                 "timestamp TEXT, mode TEXT, schema TEXT, model TEXT, endpoint_hash TEXT, "
                 "score INTEGER, risk_level TEXT, n_pass INTEGER, n_fail INTEGER, "
                 "n_warn INTEGER, n_error INTEGER, total INTEGER, framework TEXT, duration REAL)")
    conn.commit(); conn.close()
    # save_run must migrate the schema in place and persist without raising.
    assert trend.save_run(_cfg(), "vapt", _scores(10, silent=2), db_path=db) is not None
    assert trend.get_history(db, limit=1)[0]["n_silent"] == 2
