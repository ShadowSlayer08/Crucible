"""
slm/versioning.py — version control for the local red-team SLM (Phase 6C, roadmap #78).

Every LoRA fine-tune of the local red-team SLM produces a new model checkpoint
(exported to Ollama as e.g. "redai-slm:v3"). This module is the registry that
tracks those checkpoints: what base model + how much data + how many epochs made
each one, how it scored on the two held-out evals (attack ASR, judge accuracy),
which Ollama model name it maps to, and which one is currently "active" (the one
the tool should actually load). Promote / rollback just flip the active flag, so
recovering from a bad fine-tune is one command.

Pure stdlib (sqlite3). No torch, no GPU, nothing heavy — this is bookkeeping, so
it is fully runnable and testable in the authoring env. It records the metadata
of training runs that happen elsewhere; it does not train anything itself.

Schema:
    slm_versions(
        version_id       INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at       TEXT,      -- ISO string, passed in (never datetime.now() at import)
        base_model       TEXT,
        training_samples INTEGER,
        epochs           INTEGER,
        eval_attack_asr  REAL,      -- attack success rate on held-out eval (0..1)
        eval_judge_acc   REAL,      -- judge agreement/accuracy on held-out eval (0..1)
        ollama_model_name TEXT,
        notes            TEXT,
        active           INTEGER    -- 1 for exactly one row (the live model)
    )

Public API:
    register(meta, db_path=None)        -> version_id | None
    list_versions(db_path=None)         -> [row_dict, ...]
    get_version(version_id, db_path=None) -> row_dict | None
    promote(version_id, db_path=None)   -> bool
    rollback(version_id, db_path=None)  -> bool   (alias of promote)
    get_active(db_path=None)            -> row_dict | None
    diff(v1, v2, db_path=None)          -> {field: (a, b)} over eval metrics
    print_versions(db_path=None)        -> None    (table with active marker)

Every function is best-effort: a bad/locked/corrupt DB yields None / [] / False,
never an exception. Timestamps are the caller's responsibility (pass created_at
in meta) so importing this module has no side effects and touches no clock.
"""

import argparse
import os
import sqlite3

try:
    import colors as C
except Exception:  # pragma: no cover - colors is repo-local; degrade gracefully
    class _NoColor:
        def __getattr__(self, _):
            return lambda t: str(t)
    C = _NoColor()


DEFAULT_DB = os.path.join("slm", "versions.sqlite")

# Columns in declaration order — single source of truth for row dicts.
_COLUMNS = [
    "version_id",
    "created_at",
    "base_model",
    "training_samples",
    "epochs",
    "eval_attack_asr",
    "eval_judge_acc",
    "ollama_model_name",
    "notes",
    "active",
]

# Fields compared by diff() — the metrics that tell you if a fine-tune got better.
_DIFF_FIELDS = [
    "base_model",
    "training_samples",
    "epochs",
    "eval_attack_asr",
    "eval_judge_acc",
    "created_at",
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS slm_versions (
    version_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at        TEXT,
    base_model        TEXT,
    training_samples  INTEGER,
    epochs            INTEGER,
    eval_attack_asr   REAL,
    eval_judge_acc    REAL,
    ollama_model_name TEXT,
    notes             TEXT,
    active            INTEGER DEFAULT 0
)
"""


# ── connection helper ─────────────────────────────────────────────────────────
def _connect(db_path=None):
    """Open (creating parent dir + schema) the versions DB. Returns conn or None."""
    path = db_path or DEFAULT_DB
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute(_SCHEMA)
        conn.commit()
        return conn
    except Exception:
        return None


def _row_to_dict(row):
    try:
        return {k: row[k] for k in _COLUMNS}
    except Exception:
        return dict(row) if row is not None else None


# ── writes ─────────────────────────────────────────────────────────────────────
def register(meta, db_path=None):
    """
    Record a new SLM version from a metadata dict and return its version_id.

    Recognised keys (all optional, sensible defaults):
        created_at, base_model, training_samples, epochs,
        eval_attack_asr, eval_judge_acc, ollama_model_name, notes,
        active (if truthy, the new version becomes the active one)

    Best-effort: returns None on any failure.
    """
    if not isinstance(meta, dict):
        return None
    conn = _connect(db_path)
    if conn is None:
        return None
    try:
        make_active = bool(meta.get("active"))
        with conn:
            if make_active:
                conn.execute("UPDATE slm_versions SET active = 0")
            cur = conn.execute(
                """
                INSERT INTO slm_versions
                    (created_at, base_model, training_samples, epochs,
                     eval_attack_asr, eval_judge_acc, ollama_model_name, notes, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    meta.get("created_at"),
                    meta.get("base_model"),
                    meta.get("training_samples"),
                    meta.get("epochs"),
                    meta.get("eval_attack_asr"),
                    meta.get("eval_judge_acc"),
                    meta.get("ollama_model_name"),
                    meta.get("notes"),
                    1 if make_active else 0,
                ),
            )
            return cur.lastrowid
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def promote(version_id, db_path=None):
    """Make version_id the sole active version. Returns True on success."""
    conn = _connect(db_path)
    if conn is None:
        return False
    try:
        with conn:
            cur = conn.execute(
                "SELECT 1 FROM slm_versions WHERE version_id = ?", (version_id,)
            )
            if cur.fetchone() is None:
                return False
            conn.execute("UPDATE slm_versions SET active = 0")
            conn.execute(
                "UPDATE slm_versions SET active = 1 WHERE version_id = ?", (version_id,)
            )
        return True
    except Exception:
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def rollback(version_id, db_path=None):
    """Roll back to an earlier version — identical to promote()."""
    return promote(version_id, db_path=db_path)


# ── reads ──────────────────────────────────────────────────────────────────────
def list_versions(db_path=None):
    """Return all versions as row dicts, newest version_id first. [] on failure."""
    conn = _connect(db_path)
    if conn is None:
        return []
    try:
        cur = conn.execute("SELECT * FROM slm_versions ORDER BY version_id DESC")
        return [_row_to_dict(r) for r in cur.fetchall()]
    except Exception:
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_version(version_id, db_path=None):
    """Return one version as a row dict, or None."""
    conn = _connect(db_path)
    if conn is None:
        return None
    try:
        cur = conn.execute(
            "SELECT * FROM slm_versions WHERE version_id = ?", (version_id,)
        )
        row = cur.fetchone()
        return _row_to_dict(row) if row is not None else None
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_active(db_path=None):
    """Return the currently active version dict, or None if none set."""
    conn = _connect(db_path)
    if conn is None:
        return None
    try:
        cur = conn.execute(
            "SELECT * FROM slm_versions WHERE active = 1 ORDER BY version_id DESC LIMIT 1"
        )
        row = cur.fetchone()
        return _row_to_dict(row) if row is not None else None
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def diff(v1, v2, db_path=None):
    """
    Compare two versions over their eval metrics + training config.

    Returns {field: (value_in_v1, value_in_v2)} for every field that differs.
    Returns {} if either version is missing or on any failure.
    """
    a = get_version(v1, db_path=db_path)
    b = get_version(v2, db_path=db_path)
    if not a or not b:
        return {}
    out = {}
    for field in _DIFF_FIELDS:
        av, bv = a.get(field), b.get(field)
        if av != bv:
            out[field] = (av, bv)
    return out


# ── display ────────────────────────────────────────────────────────────────────
def _fmt(v):
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.3f}"
    return str(v)


def print_versions(db_path=None):
    """Print a table of all versions with a marker on the active one."""
    rows = list_versions(db_path=db_path)
    if not rows:
        print(C.DIM("No SLM versions registered yet."))
        return

    header = "{:<2} {:<4} {:<19} {:<16} {:>7} {:>4} {:>8} {:>8} {:<16}".format(
        "", "ver", "created_at", "base_model", "samples", "ep",
        "atk_asr", "jdg_acc", "ollama_name",
    )
    print(C.BOLD(header))
    print(C.DIM("-" * len(header)))
    for r in rows:
        active = r.get("active")
        marker = C.GREEN("*") if active else " "
        line = "{:<4} {:<19} {:<16} {:>7} {:>4} {:>8} {:>8} {:<16}".format(
            _fmt(r.get("version_id")),
            _fmt(r.get("created_at"))[:19],
            _fmt(r.get("base_model"))[:16],
            _fmt(r.get("training_samples")),
            _fmt(r.get("epochs")),
            _fmt(r.get("eval_attack_asr")),
            _fmt(r.get("eval_judge_acc")),
            _fmt(r.get("ollama_model_name"))[:16],
        )
        line = C.GREEN(line) if active else line
        print(" {} {}".format(marker, line))
    print(C.DIM("-" * len(header)))
    print(C.DIM("  * = active (the model the tool loads)"))


def _print_diff(v1, v2, db_path=None):
    d = diff(v1, v2, db_path=db_path)
    if not d:
        print(C.DIM("No differences (or one/both versions missing)."))
        return
    print(C.BOLD("diff  v{} -> v{}".format(v1, v2)))
    for field, (a, b) in d.items():
        arrow = C.CYAN("->")
        print("  {:<18} {} {} {}".format(field, C.RED(_fmt(a)), arrow, C.GREEN(_fmt(b))))


# ── CLI ────────────────────────────────────────────────────────────────────────
def _main(argv=None):
    parser = argparse.ArgumentParser(
        prog="slm.versioning",
        description="Version control for the local red-team SLM (roadmap #78).",
    )
    parser.add_argument("--db", default=None, help="path to versions.sqlite (default: slm/versions.sqlite)")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("list", help="list all registered versions")

    p_prom = sub.add_parser("promote", help="make a version the active one")
    p_prom.add_argument("version_id", type=int)

    p_roll = sub.add_parser("rollback", help="roll back to a version (alias of promote)")
    p_roll.add_argument("version_id", type=int)

    p_diff = sub.add_parser("diff", help="compare two versions over eval metrics")
    p_diff.add_argument("v1", type=int)
    p_diff.add_argument("v2", type=int)

    args = parser.parse_args(argv)

    if args.cmd in (None, "list"):
        print_versions(db_path=args.db)
        return 0

    if args.cmd == "promote":
        ok = promote(args.version_id, db_path=args.db)
        print(C.GREEN("promoted v{} -> active".format(args.version_id)) if ok
              else C.RED("could not promote v{} (missing or db error)".format(args.version_id)))
        print_versions(db_path=args.db)
        return 0 if ok else 1

    if args.cmd == "rollback":
        ok = rollback(args.version_id, db_path=args.db)
        print(C.GREEN("rolled back to v{}".format(args.version_id)) if ok
              else C.RED("could not roll back to v{} (missing or db error)".format(args.version_id)))
        print_versions(db_path=args.db)
        return 0 if ok else 1

    if args.cmd == "diff":
        _print_diff(args.v1, args.v2, db_path=args.db)
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    try:
        import colors as _cinit
        _cinit.init(True)
        _cinit.force_utf8()
    except Exception:
        pass
    raise SystemExit(_main())
