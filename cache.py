"""
Response Cache  —  free/fast/deterministic re-runs.

Content-addressed cache of target responses, keyed by
(schema, model, endpoint, modality, payload[, media]). On a hit the API call is
skipped entirely — so a cached re-run costs nothing, runs instantly, and is fully
deterministic (reinforcing --seed). Verdicts are NOT cached, so classifier
improvements always re-apply to cached responses.

Opt-in via --cache (red-teaming often wants fresh responses). SQLite-backed,
thread-safe, and never raises — a cache failure just falls through to a live call.
"""
import hashlib
import os
import sqlite3
from threading import Lock

CACHE_FILE = os.environ.get("AI_RT_CACHE", ".ai-redteam-cache.db")


class ResponseCache:
    def __init__(self, path: str = None):
        self.path = path or CACHE_FILE
        self._lock = Lock()
        self.hits = 0
        self.misses = 0
        self.stored = 0
        try:
            self._conn().close()
        except Exception:
            pass

    def _conn(self):
        c = sqlite3.connect(self.path)
        c.execute("CREATE TABLE IF NOT EXISTS cache ("
                  "key TEXT PRIMARY KEY, response TEXT, ts TEXT)")
        c.commit()
        return c

    def key(self, config: dict, test: dict, modality: str = "text") -> str:
        h = hashlib.sha256()
        for part in (config.get("schema", ""), config.get("model", ""),
                     config.get("endpoint", ""), modality, test.get("payload", "")):
            h.update(str(part).encode("utf-8")); h.update(b"\x00")
        for m in ("image", "audio", "video"):
            if test.get(m):
                h.update(str(test[m])[:64].encode("utf-8"))
        return h.hexdigest()

    def get(self, key: str):
        try:
            with self._lock:
                c = self._conn()
                row = c.execute("SELECT response FROM cache WHERE key=?", (key,)).fetchone()
                c.close()
            if row is not None:
                self.hits += 1
                return row[0]
            self.misses += 1
            return None
        except Exception:
            self.misses += 1
            return None

    def put(self, key: str, response: str) -> None:
        try:
            from datetime import datetime
            with self._lock:
                c = self._conn()
                c.execute("INSERT OR REPLACE INTO cache (key, response, ts) VALUES (?,?,?)",
                          (key, response, datetime.now().isoformat(timespec="seconds")))
                c.commit(); c.close()
            self.stored += 1
        except Exception:
            pass

    def size(self) -> int:
        try:
            with self._lock:
                c = self._conn()
                n = c.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
                c.close()
            return n
        except Exception:
            return 0

    def stats(self) -> dict:
        total = self.hits + self.misses
        return {"hits": self.hits, "misses": self.misses, "stored": self.stored,
                "hit_rate": round(self.hits / total * 100, 1) if total else 0.0,
                "entries": self.size()}


def clear_cache(path: str = None) -> bool:
    path = path or CACHE_FILE
    try:
        if os.path.exists(path):
            os.remove(path)
            return True
    except Exception:
        pass
    return False


def print_cache_summary(cache: "ResponseCache") -> None:
    import colors as C
    s = cache.stats()
    if s["hits"] == 0 and s["stored"] == 0:
        return
    print(f"  {C.CYAN('◈ Cache')}: {s['hits']} hit(s) / {s['stored']} stored  "
          f"({s['hit_rate']}% hit rate, {s['entries']} entries)  "
          f"{C.DIM('— API calls saved on hits')}\n")
