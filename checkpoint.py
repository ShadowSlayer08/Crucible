"""
Checkpoint System
Saves run progress after every test to a .checkpoint.json file.
Allows resuming an interrupted run with --resume.

Checkpoint file format:
{
  "run_id":    "vapt_20260501_143022",
  "mode":      "vapt",
  "schema":    "openai",
  "endpoint":  "https://api.openai.com",
  "model":     "gpt-4o",
  "total":     77,
  "completed": 45,
  "test_ids":  ["PI-001", "PI-002", ...],   # full ordered list
  "done_ids":  ["PI-001", "PI-002", ...],   # completed so far
  "results":   [...]                         # result dicts saved
}
"""

import json
import os
from datetime import datetime

import colors as C

CHECKPOINT_FILE = ".ai-redteam-checkpoint.json"


# ─────────────────────────────────────────────────────────────────────────────
# SAVE
# ─────────────────────────────────────────────────────────────────────────────

def save_checkpoint(run_id: str, mode: str, config: dict,
                    all_test_ids: list, results: list):
    """
    Save current progress to checkpoint file.
    Called after every test completes.
    """
    done_ids = [r["test"]["id"] for r in results]

    checkpoint = {
        "run_id":    run_id,
        "mode":      mode,
        "schema":    config.get("schema", "openai"),
        "endpoint":  config.get("endpoint", ""),
        "model":     config.get("model", ""),
        "total":     len(all_test_ids),
        "completed": len(done_ids),
        "test_ids":  all_test_ids,
        "done_ids":  done_ids,
        "saved_at":  datetime.now().isoformat(),
        "results":   _serialize_results(results),
    }

    try:
        with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
            json.dump(checkpoint, f, indent=2, ensure_ascii=False)
    except Exception:
        pass  # never crash a test run because of a checkpoint write failure


def clear_checkpoint():
    """Delete the checkpoint file after a successful complete run."""
    try:
        if os.path.exists(CHECKPOINT_FILE):
            os.remove(CHECKPOINT_FILE)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# LOAD / RESUME
# ─────────────────────────────────────────────────────────────────────────────

def load_checkpoint() -> dict | None:
    """Load checkpoint file if it exists. Returns None if not found."""
    if not os.path.exists(CHECKPOINT_FILE):
        return None
    try:
        with open(CHECKPOINT_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def resume_checkpoint(checkpoint: dict, all_tests: list) -> tuple[list, list]:
    """
    Given a checkpoint and the full test list, return:
      - already_done:    list of result dicts from the checkpoint
      - remaining_tests: list of test dicts still to run
    """
    done_ids   = set(checkpoint.get("done_ids", []))
    saved      = _deserialize_results(checkpoint.get("results", []))

    # keep tests not yet done, preserve original order
    remaining  = [t for t in all_tests if t["id"] not in done_ids]

    return saved, remaining


def print_checkpoint_status(checkpoint: dict):
    """Print a summary of the checkpoint found."""
    completed = checkpoint.get("completed", 0)
    total     = checkpoint.get("total", 0)
    pct       = round(completed / total * 100) if total else 0
    saved_at  = checkpoint.get("saved_at", "unknown time")

    print(f"\n  {C.YELLOW('◈ CHECKPOINT FOUND')}")
    print(f"  Run ID   : {C.DIM(checkpoint.get('run_id','?'))}")
    print(f"  Mode     : {checkpoint.get('mode','?')}  |  "
          f"Schema: {checkpoint.get('schema','?')}  |  "
          f"Model: {checkpoint.get('model','?')}")
    print(f"  Progress : {C.CYAN(str(completed))}/{total} tests ({pct}%) — saved at {saved_at}")
    print(f"  Endpoint : {C.DIM(checkpoint.get('endpoint','?'))}")


def has_checkpoint() -> bool:
    return os.path.exists(CHECKPOINT_FILE)


# ─────────────────────────────────────────────────────────────────────────────
# SERIALIZATION HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _serialize_results(results: list) -> list:
    """Strip non-serializable fields (raw_response) before saving."""
    serialized = []
    for r in results:
        test   = {k: v for k, v in r["test"].items()}
        result = {
            "verdict":         r["result"].get("verdict", ""),
            "confidence":      r["result"].get("confidence", ""),
            "reason":          r["result"].get("reason", ""),
            "flagged_excerpt": r["result"].get("flagged_excerpt", ""),
            "status_code":     r["result"].get("status_code", 0),
            "response_text":   r["result"].get("response_text", "")[:500],  # trim
        }
        serialized.append({"test": test, "result": result})
    return serialized


def _deserialize_results(raw: list) -> list:
    """Restore results from checkpoint — already in the right format."""
    return raw if isinstance(raw, list) else []
