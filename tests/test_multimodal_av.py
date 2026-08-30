"""Multimodal frontier — audio + video builders and suites."""
import pytest

import multimodal as mm
from payloads import AUDIO_TESTS, VIDEO_TESTS

REQUIRED = {"id", "category", "severity", "name", "payload", "expected", "tags"}
VALID_SEV = {"Critical", "High", "Medium", "Low"}


# ── supports_modality per modality ────────────────────────────────────────────

def test_supports_audio_and_video():
    assert mm.supports_modality("openai", "audio")
    assert mm.supports_modality("google", "audio")
    assert mm.supports_modality("openai", "video")
    assert not mm.supports_modality("ollama", "audio")
    assert not mm.supports_modality("cohere", "video")
    # back-compat: default modality is image
    assert mm.supports_modality("openai")


# ── audio message builder ─────────────────────────────────────────────────────

def test_build_audio_openai_shape():
    c = mm.build_audio_message("openai", "listen", mm.TINY_WAV_B64)
    assert c[0]["type"] == "text"
    assert c[1]["type"] == "input_audio"
    assert c[1]["input_audio"]["format"] == "wav"


def test_build_audio_google_shape():
    c = mm.build_audio_message("google", "listen", mm.TINY_WAV_B64)
    assert "inline_data" in c[1] and c[1]["inline_data"]["mime_type"].startswith("audio/")


def test_audio_unsupported_schema_raises():
    with pytest.raises(ValueError):
        mm.build_audio_message("ollama", "x", mm.TINY_WAV_B64)


# ── video message builder ─────────────────────────────────────────────────────

def test_build_video_openai_sends_frames_as_images():
    c = mm.build_video_message("openai", "watch", [mm.TINY_PNG_B64, mm.TINY_PNG_B64])
    imgs = [b for b in c if b.get("type") == "image_url"]
    assert len(imgs) == 2


def test_build_video_google_single_blob():
    c = mm.build_video_message("google", "watch", [mm.TINY_PNG_B64])
    assert c[1]["inline_data"]["mime_type"] == "video/mp4"


def test_video_unsupported_schema_raises():
    with pytest.raises(ValueError):
        mm.build_video_message("cohere", "x", [mm.TINY_PNG_B64])


# ── payload suites ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("t", AUDIO_TESTS, ids=lambda t: t["id"])
def test_audio_suite_wellformed(t):
    assert REQUIRED <= set(t.keys())
    assert t["severity"] in VALID_SEV and t["expected"] == "refusal"
    assert t.get("audio")           # carries an audio payload


@pytest.mark.parametrize("t", VIDEO_TESTS, ids=lambda t: t["id"])
def test_video_suite_wellformed(t):
    assert REQUIRED <= set(t.keys())
    assert isinstance(t.get("video"), list) and t["video"]   # carries frames


def test_suite_ids_unique():
    ids = [t["id"] for t in AUDIO_TESTS + VIDEO_TESTS]
    assert len(ids) == len(set(ids))
