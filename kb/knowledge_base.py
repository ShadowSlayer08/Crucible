"""
kb/knowledge_base.py — RedTeamKB: a lean, local, persistent vector knowledge base.

Design goal: the "starter knowledge base" the tool grows from. Static payload
suites SEED it; every dynamic attack that beats a target with high confidence is
written BACK into it; future generations retrieve from it — so the local attacker
gets smarter over time without any external service.

Deliberately dependency-light — **no chromadb, no sentence-transformers**. It uses:
  * SQLite for durable storage (one file under persist_dir),
  * the project's existing local bge-m3 embeddings (embeddings.ollama_embed) for
    semantic search when Ollama is up,
  * a token-Jaccard fallback when embeddings are unavailable, so the KB still works
    offline-lite and unit tests run with no daemon.

Public API:
    kb = RedTeamKB(persist_dir=".ai-redteam-kb")
    kb.add(collection, text, metadata=None, doc_id=None) -> doc_id
    kb.add_many(collection, [(text, metadata), ...])      -> [doc_id, ...]
    kb.query(collection, text, n=5)                       -> [{doc_id,text,metadata,score}]
    kb.find_similar(text, threshold=0.6, collection=...)  -> [...]
    kb.count(collection=None) / kb.get_stats()            -> int / dict
    kb.delete(collection, doc_id) / kb.reset()
"""

import hashlib
import json
import math
import os
import re
import sqlite3

DEFAULT_DIR = os.environ.get("AI_RT_KB_DIR", ".ai-redteam-kb")
COLLECTIONS = ("attack_patterns", "run_history", "mitre_atlas", "owasp_llm", "research")
_WORD = re.compile(r"\w+")


def _doc_id(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:16]


def _tokens(text: str):
    return set(_WORD.findall((text or "").lower()))


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _cosine(a, b) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _default_embed_fn():
    """Return the local bge-m3 embed fn if reachable, else None (→ lexical mode)."""
    try:
        import embeddings
        if embeddings.available():
            return embeddings.ollama_embed
    except Exception:
        pass
    return None


class RedTeamKB:
    def __init__(self, persist_dir: str = DEFAULT_DIR, embed_fn="auto"):
        self.persist_dir = persist_dir
        os.makedirs(persist_dir, exist_ok=True)
        self.db_path = os.path.join(persist_dir, "kb.sqlite")
        # embed_fn: "auto" resolves to bge-m3 if up else None; None forces lexical;
        # a callable([text])->[vec] is used directly (tests inject a deterministic one).
        self.embed_fn = _default_embed_fn() if embed_fn == "auto" else embed_fn
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS documents (
                   collection TEXT NOT NULL,
                   doc_id     TEXT NOT NULL,
                   text       TEXT NOT NULL,
                   metadata   TEXT,
                   embedding  TEXT,
                   PRIMARY KEY (collection, doc_id)
               )""")
        self._conn.commit()

    # ── embedding helper ──────────────────────────────────────────────────────
    def _embed(self, text: str):
        if not self.embed_fn:
            return None
        try:
            vecs = self.embed_fn([text])
            return vecs[0] if vecs else None
        except Exception:
            return None

    @property
    def semantic(self) -> bool:
        """True when embeddings are active (semantic search), False = lexical."""
        return self.embed_fn is not None

    # ── writes ────────────────────────────────────────────────────────────────
    def add(self, collection: str, text: str, metadata: dict = None,
            doc_id: str = None) -> str:
        text = (text or "").strip()
        if not text:
            return ""
        did = doc_id or _doc_id(text)
        emb = self._embed(text)
        self._conn.execute(
            "INSERT OR REPLACE INTO documents VALUES (?,?,?,?,?)",
            (collection, did, text, json.dumps(metadata or {}),
             json.dumps(emb) if emb is not None else None))
        self._conn.commit()
        return did

    def add_many(self, collection: str, items) -> list:
        """items: iterable of (text, metadata) or dicts {text, metadata, doc_id}."""
        out = []
        for it in items:
            if isinstance(it, dict):
                out.append(self.add(collection, it.get("text", ""),
                                    it.get("metadata"), it.get("doc_id")))
            else:
                text, meta = it
                out.append(self.add(collection, text, meta))
        return [d for d in out if d]

    # ── reads ─────────────────────────────────────────────────────────────────
    def _rows(self, collection: str = None):
        if collection:
            cur = self._conn.execute(
                "SELECT collection, doc_id, text, metadata, embedding "
                "FROM documents WHERE collection=?", (collection,))
        else:
            cur = self._conn.execute(
                "SELECT collection, doc_id, text, metadata, embedding FROM documents")
        return cur.fetchall()

    def query(self, collection: str, text: str, n: int = 5) -> list:
        """Return the n most similar docs in *collection* to *text* (highest first)."""
        rows = self._rows(collection)
        if not rows:
            return []
        q_emb = self._embed(text) if self.semantic else None
        q_tok = _tokens(text)
        scored = []
        for _c, did, dtext, meta, emb_json in rows:
            score = 0.0
            if q_emb is not None and emb_json:
                try:
                    score = _cosine(q_emb, json.loads(emb_json))
                except Exception:
                    score = 0.0
            if score == 0.0:  # lexical fallback (or no embedding stored)
                score = _jaccard(q_tok, _tokens(dtext))
            scored.append({"doc_id": did, "text": dtext,
                           "metadata": json.loads(meta or "{}"),
                           "score": round(score, 4)})
        scored.sort(key=lambda r: r["score"], reverse=True)
        return scored[:max(1, n)]

    def find_similar(self, text: str, threshold: float = 0.6,
                     collection: str = "attack_patterns", n: int = 5) -> list:
        return [r for r in self.query(collection, text, n) if r["score"] >= threshold]

    def has_similar(self, text: str, threshold: float = 0.9,
                    collection: str = "attack_patterns") -> bool:
        """Dedup helper: is a near-identical doc already stored?"""
        top = self.query(collection, text, n=1)
        return bool(top and top[0]["score"] >= threshold)

    # ── admin ─────────────────────────────────────────────────────────────────
    def count(self, collection: str = None) -> int:
        if collection:
            return self._conn.execute(
                "SELECT COUNT(*) FROM documents WHERE collection=?",
                (collection,)).fetchone()[0]
        return self._conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]

    def get_stats(self) -> dict:
        rows = self._conn.execute(
            "SELECT collection, COUNT(*) FROM documents GROUP BY collection").fetchall()
        return {"path": self.db_path, "semantic": self.semantic,
                "total": self.count(), "collections": {c: n for c, n in rows}}

    def delete(self, collection: str, doc_id: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM documents WHERE collection=? AND doc_id=?", (collection, doc_id))
        self._conn.commit()
        return cur.rowcount > 0

    def reset(self) -> None:
        self._conn.execute("DELETE FROM documents")
        self._conn.commit()

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
