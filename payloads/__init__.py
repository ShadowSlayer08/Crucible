from .vapt import VAPT_TESTS
from .redteam import REDTEAM_TESTS
from .provider_specific import PROVIDER_PAYLOADS, SUPPORTED_PROVIDERS
from .atlas import (
    ATLAS_TACTICS, ATLAS_TECHNIQUES, TEST_TO_ATLAS,
    ATLAS_NEW_TESTS, enrich_test, build_coverage_map,
    tactic_summary, TOTAL_ATLAS_TECHNIQUES, COVERED_TECHNIQUES,
)

# ── v3.0 expanded attack-surface modes (Phase 5 / Phase 5.5 roadmap) ──────────
from .mcp_tests import MCP_TESTS
from .agentic import AGENTIC_TESTS
from .rag import RAG_TESTS
from .swarm import SWARM_TESTS
from .policy import POLICY_TESTS
from .benign import BENIGN_TESTS
from .obfuscation import OBFUSCATION_TESTS
from .multilingual import (
    MULTILINGUAL_TESTS, available_languages, filter_by_language,
)
from .multimodal_tests import MULTIMODAL_TESTS
from .memory_poison import MEMORY_POISON_TESTS
from .pismith_rag import PISMITH_TESTS
from .authz import AUTHZ_TESTS

# Maps a --mode name to its static test pool, for the modes that simply run a
# dedicated suite through the standard pipeline.
EXPANDED_MODE_TESTS = {
    "mcp":          MCP_TESTS,
    "agentic":      AGENTIC_TESTS,
    "rag":          RAG_TESTS,
    "swarm":        SWARM_TESTS,
    "policy":       POLICY_TESTS,
    "benign":       BENIGN_TESTS,
    "obfuscation":  OBFUSCATION_TESTS,
    "multilingual": MULTILINGUAL_TESTS,
    "multimodal":   MULTIMODAL_TESTS,
    "memory-poison": MEMORY_POISON_TESTS,
    "pismith":      PISMITH_TESTS,
    "authz":        AUTHZ_TESTS,
}

__all__ = [
    "VAPT_TESTS", "REDTEAM_TESTS",
    "PROVIDER_PAYLOADS", "SUPPORTED_PROVIDERS",
    "ATLAS_TACTICS", "ATLAS_TECHNIQUES", "TEST_TO_ATLAS",
    "ATLAS_NEW_TESTS", "enrich_test", "build_coverage_map",
    "tactic_summary", "TOTAL_ATLAS_TECHNIQUES", "COVERED_TECHNIQUES",
    "MCP_TESTS", "AGENTIC_TESTS", "RAG_TESTS", "SWARM_TESTS",
    "POLICY_TESTS", "BENIGN_TESTS", "OBFUSCATION_TESTS",
    "MULTILINGUAL_TESTS", "MULTIMODAL_TESTS",
    "MEMORY_POISON_TESTS", "PISMITH_TESTS", "AUTHZ_TESTS",
    "available_languages", "filter_by_language",
    "EXPANDED_MODE_TESTS",
]
