"""RedTeam Knowledge Base — lean, local, self-growing attack corpus (Phase 6B)."""
from .knowledge_base import RedTeamKB, COLLECTIONS, DEFAULT_DIR
from .ingest import seed_attack_patterns, ingest_atlas_owasp, seed_all

__all__ = [
    "RedTeamKB", "COLLECTIONS", "DEFAULT_DIR",
    "seed_attack_patterns", "ingest_atlas_owasp", "seed_all",
]
