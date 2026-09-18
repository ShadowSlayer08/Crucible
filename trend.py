"""
Trend Tracking — SQLite run history
Roadmap milestone G03 / "Trend Tracking (SQLite)".

Persists one row per completed run to a local SQLite database so risk scores can
be tracked over time and regression deltas reported on re-runs. The endpoint is
stored only as a short hash (never the raw URL or any credential).

Public API:
    save_run(config, mode, scores)     -> int | None   (row id, or None on failure)
    get_history(db_path, mode, model, limit) -> list[dict]
    print_trend(db_path, limit)        -> None
    regression_delta(db_path, mode, model) -> dict | None
"""
import hashlib
import os
import sqlite3
from datetime import datetime

import colors as C

DB_FILE = os.environ.get("CRUCIBLE_HISTORY_DB", ".crucible-history.db")


def _endpoint_hash(endpoint: str) -> str:
    if not endpoint:
        return "n/a"
    return hashlib.sha256(endpoint.encode("utf-8")).hexdigest()[:12]


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT NOT NULL,
            mode          TEXT,
            schema        TEXT,
            model         TEXT,
            endpoint_hash TEXT,
            score         INTEGER,
            risk_level    TEXT,
            n_pass        INTEGER,
            n_fail        INTEGER,
            n_warn        INTEGER,
            n_error       INTEGER,
            n_silent      INTEGER,
            total         INTEGER,
            framework     TEXT,
            duration      REAL
        )
        """
    )
    # Migrate a DB created before n_silent existed (add the column in place so
    # older history files keep working instead of silently failing to save).
    cols = {r[1] for r in conn.execute("PRAGMA table_info(runs)").fetchall()}
    if "n_silent" not in cols:
        conn.execute("ALTER TABLE runs ADD COLUMN n_silent INTEGER DEFAULT 0")
    conn.commit()
    return conn


def save_run(config: dict, mode: str, scores: dict,
             db_path: str = None, timestamp: str = None,
             framework: str = "", duration: float = 0.0) -> int | None:
    """Append a run summary to the history DB. Never raises — history is best-effort."""
    db_path = db_path or DB_FILE
    try:
        totals = scores.get("totals", {})
        ts = timestamp or datetime.now().isoformat(timespec="seconds")
        conn = _connect(db_path)
        cur = conn.execute(
            """INSERT INTO runs
               (timestamp, mode, schema, model, endpoint_hash, score, risk_level,
                n_pass, n_fail, n_warn, n_error, n_silent, total, framework, duration)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                ts, mode, config.get("schema", ""), config.get("model", ""),
                _endpoint_hash(config.get("endpoint", "")),
                scores.get("overall_risk_score", 0), scores.get("risk_level", ""),
                totals.get("pass", 0), totals.get("fail", 0),
                totals.get("warn", 0), totals.get("error", 0),
                totals.get("silent", 0),
                sum(totals.get(k, 0) for k in
                    ("pass", "fail", "warn", "error", "silent", "partial_refusal")),
                framework or "", float(duration or 0.0),
            ),
        )
        conn.commit()
        row_id = cur.lastrowid
        conn.close()
        return row_id
    except Exception:
        return None


def export_history_csv(path: str, db_path: str = None) -> int:
    """Write the full run history to a CSV file. Returns the row count."""
    import csv
    rows = get_history(db_path, limit=100000)
    cols = ["id", "timestamp", "mode", "schema", "model", "endpoint_hash",
            "score", "risk_level", "n_pass", "n_fail", "n_warn", "n_error",
            "n_silent", "total", "framework", "duration"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in reversed(rows):  # oldest first for a timeline
            w.writerow([r.get(c, "") for c in cols])
    return len(rows)


def clear_history(db_path: str = None) -> bool:
    """Delete the run-history database file. Returns True if a file was removed."""
    db_path = db_path or DB_FILE
    try:
        if os.path.exists(db_path):
            os.remove(db_path)
            return True
    except Exception:
        pass
    return False


def get_history(db_path: str = None, mode: str = None,
                model: str = None, limit: int = 20) -> list:
    """Return recent run rows (newest first) as dicts, optionally filtered."""
    db_path = db_path or DB_FILE
    if not os.path.exists(db_path):
        return []
    try:
        conn = _connect(db_path)
        conn.row_factory = sqlite3.Row
        q = "SELECT * FROM runs"
        clauses, params = [], []
        if mode:
            clauses.append("mode = ?"); params.append(mode)
        if model:
            clauses.append("model = ?"); params.append(model)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = [dict(r) for r in conn.execute(q, params).fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def regression_delta(db_path: str = None, mode: str = None, model: str = None) -> dict | None:
    """Compare the two most recent runs for a (mode, model). Returns delta info or None."""
    rows = get_history(db_path, mode=mode, model=model, limit=2)
    if len(rows) < 2:
        return None
    latest, prev = rows[0], rows[1]
    return {
        "latest_score": latest["score"],
        "prev_score":   prev["score"],
        "delta":        latest["score"] - prev["score"],
        "new_fails":    latest["n_fail"] - prev["n_fail"],
    }


def print_trend(db_path: str = None, limit: int = 20) -> None:
    """Print the recent run history as a table."""
    rows = get_history(db_path, limit=limit)
    width = 78
    print(f"\n{'═' * width}")
    print(C.BOLD("  RUN HISTORY  (SQLite trend tracking)"))
    print(f"{'═' * width}")
    if not rows:
        print(f"\n  {C.DIM('No history yet. Complete a run to start tracking trends.')}\n")
        return
    print(f"\n  {'When':<20} {'Mode':<8} {'Model':<18} {'Score':>5}  {'Risk':<8} "
          f"{'F':>3} {'W':>3} {'S':>3} {'E':>3}")
    print(f"  {'─' * (width - 4)}")
    for r in rows:
        when = (r["timestamp"] or "")[:19].replace("T", " ")
        score = r["score"] or 0
        scol = C.RED if score >= 45 else (C.YELLOW if score >= 20 else C.GREEN)
        print(f"  {when:<20} {(r['mode'] or '')[:8]:<8} {(r['model'] or '')[:18]:<18} "
              f"{scol(f'{score:>5}')}  {(r['risk_level'] or ''):<8} "
              f"{r['n_fail']:>3} {r['n_warn']:>3} {(r.get('n_silent') or 0):>3} "
              f"{r['n_error']:>3}")
    # Regression note for the most recent (mode, model)
    top = rows[0]
    delta = regression_delta(db_path, mode=top["mode"], model=top["model"])
    if delta:
        d = delta["delta"]
        sign = "+" if d >= 0 else ""
        dcol = C.RED if d > 0 else (C.GREEN if d < 0 else C.DIM)
        print(f"\n  {C.CYAN('◈ Latest vs previous')} ({top['mode']}/{top['model']}): "
              f"score {delta['prev_score']} → {delta['latest_score']} "
              f"({dcol(f'{sign}{d}')}),  new FAILs: {dcol(str(delta['new_fails']))}")
    print(f"\n{'═' * width}\n")
