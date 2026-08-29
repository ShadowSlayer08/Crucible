"""Tests for the multimodal vision request builder and the MULTIMODAL_TESTS suite.

Covers:
  - build_image_message shapes for the 'openai' and 'anthropic' content blocks
  - supports_modality reporting for vision-capable vs text-only schemas
  - ValueError for unsupported schemas
  - data: URI handling (pass-through for openai, stripped for anthropic)
  - MULTIMODAL_TESTS carry the 7 required keys + the optional 'image' key
"""
import base64

import pytest

from multimodal import build_image_message, supports_modality, TINY_PNG_B64
from payloads.multimodal_tests import MULTIMODAL_TESTS

REQUIRED = {"id", "category", "severity", "name", "payload", "expected", "tags"}
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_EXPECTED = {"refusal", "safe_response"}


# ── build_image_message — OpenAI shape ────────────────────────────────────────
def test_openai_shape():
    content = build_image_message("openai", "describe this", TINY_PNG_B64)
    assert isinstance(content, list) and len(content) == 2

    text_block, image_block = content
    assert text_block == {"type": "text", "text": "describe this"}
    assert image_block["type"] == "image_url"
    url = image_block["image_url"]["url"]
    assert url.startswith("data:image/png;base64,")
    assert url.endswith(TINY_PNG_B64)


def test_openai_passes_through_existing_data_uri():
    uri = "data:image/jpeg;base64," + TINY_PNG_B64
    content = build_image_message("openai", "x", uri)
    assert content[1]["image_url"]["url"] == uri


# ── build_image_message — Anthropic shape ─────────────────────────────────────
def test_anthropic_shape():
    content = build_image_message("anthropic", "what is this", TINY_PNG_B64)
    assert isinstance(content, list) and len(content) == 2

    text_block, image_block = content
    assert text_block == {"type": "text", "text": "what is this"}
    assert image_block["type"] == "image"
    source = image_block["source"]
    assert source["type"] == "base64"
    assert source["media_type"] == "image/png"
    # Bare base64 only — no data: prefix in the anthropic source block.
    assert source["data"] == TINY_PNG_B64
    assert not source["data"].startswith("data:")


def test_anthropic_strips_data_uri_prefix():
    uri = "data:image/png;base64," + TINY_PNG_B64
    content = build_image_message("anthropic", "x", uri)
    assert content[1]["source"]["data"] == TINY_PNG_B64


def test_custom_mime_type_propagates():
    oa = build_image_message("openai", "x", TINY_PNG_B64, mime_type="image/webp")
    assert oa[1]["image_url"]["url"].startswith("data:image/webp;base64,")
    an = build_image_message("anthropic", "x", TINY_PNG_B64, mime_type="image/webp")
    assert an[1]["source"]["media_type"] == "image/webp"


# ── supports_modality ─────────────────────────────────────────────────────────
def test_supports_modality_true_for_vision_schemas():
    for name in ("openai", "anthropic", "azure", "bedrock", "mistral"):
        assert supports_modality(name) is True


def test_supports_modality_false_for_text_only_schemas():
    for name in ("google", "ollama", "cohere", "custom", "does-not-exist"):
        assert supports_modality(name) is False


# ── error handling ────────────────────────────────────────────────────────────
def test_unsupported_schema_raises_value_error():
    with pytest.raises(ValueError):
        build_image_message("ollama", "x", TINY_PNG_B64)
    with pytest.raises(ValueError):
        build_image_message("nonexistent", "x", TINY_PNG_B64)


# ── TINY_PNG_B64 fixture is valid base64 ──────────────────────────────────────
def test_tiny_png_is_valid_base64():
    raw = base64.b64decode(TINY_PNG_B64)
    # PNG magic number.
    assert raw[:8] == b"\x89PNG\r\n\x1a\n"


# ── MULTIMODAL_TESTS corpus integrity ─────────────────────────────────────────
def test_multimodal_tests_non_empty():
    assert len(MULTIMODAL_TESTS) >= 8


def test_multimodal_ids_unique_and_prefixed():
    ids = [t["id"] for t in MULTIMODAL_TESTS]
    assert len(ids) == len(set(ids))
    assert all(i.startswith("MM-") for i in ids)


@pytest.mark.parametrize("test", MULTIMODAL_TESTS, ids=lambda t: t.get("id", "?"))
def test_multimodal_test_has_required_keys(test):
    assert REQUIRED <= set(test.keys())
    assert test["severity"] in VALID_SEVERITIES
    assert test["expected"] == "refusal"
    assert isinstance(test["tags"], list)
    assert "multimodal" in test["tags"]
    assert str(test["payload"]).strip()


@pytest.mark.parametrize("test", MULTIMODAL_TESTS, ids=lambda t: t.get("id", "?"))
def test_multimodal_test_carries_image_key(test):
    """The optional extra 'image' key must be present and a non-empty placeholder."""
    assert "image" in test
    assert test["image"] == TINY_PNG_B64


def test_multimodal_image_attaches_to_request():
    """End-to-end: a corpus test's text + image build a valid vision block."""
    t = MULTIMODAL_TESTS[0]
    content = build_image_message("openai", t["payload"], t["image"])
    assert content[0]["text"] == t["payload"]
    assert content[1]["type"] == "image_url"
