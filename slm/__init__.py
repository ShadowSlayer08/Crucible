"""SLM training pipeline — turn accumulated red-team wins into a local model (Phase 6C).

dataset_collector runs anywhere (stdlib). train/export/evaluate need a GPU + torch/
unsloth/llama.cpp and are intended to run on the operator's machine, not in CI.
"""
from .dataset_collector import from_kb_winners, from_results, collect, write_jsonl

__all__ = ["from_kb_winners", "from_results", "collect", "write_jsonl"]
