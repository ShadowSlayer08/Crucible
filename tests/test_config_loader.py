"""Tests for YAML config discovery, CLI-over-config merge precedence, and template
generation (including the Windows UTF-8 write fix)."""
import argparse

import config_loader


def _args(**overrides):
    """A namespace pre-populated with argparse defaults."""
    ns = argparse.Namespace(
        api_key=None, endpoint=None, model="gpt-4o", schema="openai",
        framework=None, mode=None, concurrency=1, output_dir="./reports",
        owasp=False, no_color=False, verbose=False, ci=False, ci_threshold=30,
        severity=None, categories=None, payload_file=None,
        skip_connection_test=False, no_save=False,
    )
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


def test_config_fills_unset_args():
    args = _args()
    config_loader.merge_config_with_args(args, {"endpoint": "https://x.ai", "model": "llama"})
    assert args.endpoint == "https://x.ai"
    assert args.model == "llama"  # was at default → overridden


def test_cli_overrides_config():
    args = _args(model="claude-sonnet-4-6", concurrency=8)  # explicit, non-default
    config_loader.merge_config_with_args(args, {"model": "llama", "concurrency": 1})
    assert args.model == "claude-sonnet-4-6"  # CLI wins
    assert args.concurrency == 8


def test_bool_default_overridden_by_config():
    args = _args()
    config_loader.merge_config_with_args(args, {"owasp": True})
    assert args.owasp is True


def test_unmapped_keys_ignored():
    args = _args()
    config_loader.merge_config_with_args(args, {"totally_unknown_key": "x"})
    assert not hasattr(args, "totally_unknown_key")


def test_load_config_missing_file_returns_empty(tmp_path):
    missing = tmp_path / "nope.yaml"
    assert config_loader.load_config(str(missing)) == {}


def test_load_config_roundtrip(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("model: llama\nconcurrency: 4\nowasp: true\n", encoding="utf-8")
    cfg = config_loader.load_config(str(p))
    assert cfg.get("model") == "llama"
    assert cfg.get("concurrency") == 4
    assert cfg.get("owasp") is True


def test_generate_template_writes_utf8(tmp_path):
    """Regression: the template contains box-drawing chars and must write without a
    cp1252 UnicodeEncodeError on Windows (and must not truncate on failure)."""
    p = tmp_path / "out.yaml"
    config_loader.generate_config_template(str(p))
    text = p.read_text(encoding="utf-8")
    assert "schema" in text
    assert "─" in text  # box-drawing char survived the UTF-8 write
    # The generated template must itself be valid YAML that loads back.
    cfg = config_loader.load_config(str(p))
    assert isinstance(cfg, dict)


def test_find_config_explicit_path(tmp_path):
    p = tmp_path / ".crucible.yaml"
    p.write_text("model: x\n", encoding="utf-8")
    assert config_loader.find_config(str(p)) == str(p)
