"""Saved target profiles (no keys stored)."""
import argparse

import targets


def test_save_and_get(tmp_path):
    p = str(tmp_path / "t.yaml")
    targets.save_target("prod", "https://api.x.ai", "claude", "anthropic", path=p)
    t = targets.get_target("prod", path=p)
    assert t["endpoint"] == "https://api.x.ai"
    assert t["model"] == "claude"
    assert t["schema"] == "anthropic"


def test_api_key_is_never_stored(tmp_path):
    p = str(tmp_path / "t.yaml")
    targets.save_target("prod", "https://api.x.ai", "m", "openai", path=p)
    stored = targets.get_target("prod", path=p)
    assert set(stored.keys()) == {"endpoint", "model", "schema"}   # no api_key field
    assert "api_key:" not in open(p, encoding="utf-8").read()      # not in the YAML


def test_apply_target_fills_only_unset(tmp_path, monkeypatch):
    p = str(tmp_path / "t.yaml")
    monkeypatch.setattr(targets, "TARGETS_FILE", p)
    targets.save_target("box", "http://localhost:11434", "qwen2.5:7b", "ollama", path=p)
    args = argparse.Namespace(endpoint=None, model="gpt-4o", schema="openai")
    assert targets.apply_target(args, "box")
    assert args.endpoint == "http://localhost:11434"
    assert args.model == "qwen2.5:7b"     # gpt-4o was the default → overridden
    assert args.schema == "ollama"


def test_apply_target_respects_explicit_flags(tmp_path, monkeypatch):
    p = str(tmp_path / "t.yaml")
    monkeypatch.setattr(targets, "TARGETS_FILE", p)
    targets.save_target("box", "http://localhost:11434", "qwen2.5:7b", "ollama", path=p)
    args = argparse.Namespace(endpoint="https://override.ai", model="my-model", schema="anthropic")
    targets.apply_target(args, "box")
    assert args.endpoint == "https://override.ai"   # explicit flag wins
    assert args.model == "my-model"


def test_delete_and_missing(tmp_path):
    p = str(tmp_path / "t.yaml")
    targets.save_target("a", "http://x", "m", "openai", path=p)
    assert targets.delete_target("a", path=p)
    assert not targets.delete_target("a", path=p)
    assert targets.get_target("nope", path=p) is None


def test_unknown_target_apply_returns_false(tmp_path, monkeypatch):
    monkeypatch.setattr(targets, "TARGETS_FILE", str(tmp_path / "empty.yaml"))
    args = argparse.Namespace(endpoint=None, model="gpt-4o", schema="openai")
    assert targets.apply_target(args, "ghost") is False
