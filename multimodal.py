"""
Multimodal request builder
Roadmap: "Multimodal vision --modality image".

Wraps a text prompt plus a base64-encoded image into the provider-correct
multimodal `content` block so the standard engine can ship a vision payload to
schemas that support it. Two provider families are supported today:

  openai     → content array of {type: "text"} + {type: "image_url"} where the
               image is delivered inline as a data: URI.
  anthropic  → content array of {type: "text"} + {type: "image"} where the image
               is delivered as a {source: {type: "base64", ...}} block.

`supports_modality(schema_name)` reports whether a given engine schema can carry
an image at all (OpenAI-compatible and Anthropic-compatible endpoints can; the
text-only / non-chat schemas cannot).

Pure stdlib — no network, no optional deps. Safe to import anywhere.
"""

# ── Which engine schemas can actually carry an image ──────────────────────────
# Maps an engine.SCHEMAS name → the provider content-shape it uses.
#   "openai"    → OpenAI-style image_url data-URI blocks
#   "anthropic" → Anthropic-style base64 source blocks
# Anything not listed here is treated as text-only (no vision support).
_SCHEMA_MODALITY = {
    "openai":    "openai",     # OpenAI, Groq, Together, OpenRouter, vLLM, LM Studio, ...
    "azure":     "openai",     # Azure OpenAI is OpenAI-compatible
    "mistral":   "openai",     # Mistral chat/completions is OpenAI-compatible
    "anthropic": "anthropic",  # Anthropic Messages API
    "bedrock":   "anthropic",  # Bedrock Claude uses the Anthropic message shape
}

# Default MIME type for the inline image. PNG covers the test fixture and the
# common screenshot/diagram attack vector; callers may pass their own.
_DEFAULT_MIME = "image/png"


# Audio: OpenAI-family models take an input_audio block; Gemini takes inline_data.
_AUDIO_MODALITY = {"openai": "openai", "azure": "openai", "google": "google"}
# Video: OpenAI-family has no native video → send sampled frames as images;
# Gemini takes a video inline_data block.
_VIDEO_MODALITY = {"openai": "openai_frames", "azure": "openai_frames", "google": "google"}

_MODALITY_MAPS = {"image": _SCHEMA_MODALITY, "audio": _AUDIO_MODALITY, "video": _VIDEO_MODALITY}


# ── Tiny 1×1 transparent PNG (base64) — for tests and placeholder payloads ────
# Decodes to a valid 67-byte single-pixel PNG. No external file needed.
TINY_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNk"
    "+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)
# Tiny silent WAV (44-byte header + no samples) for audio test fixtures.
TINY_WAV_B64 = "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAIA+AAACABAAZGF0YQAAAAA="


def supports_modality(schema_name: str, modality: str = "image") -> bool:
    """Return True if *schema_name* can carry the given modality (image/audio/video)."""
    return schema_name in _MODALITY_MAPS.get(modality, {})


def build_image_message(schema_name: str, prompt: str, image_b64: str,
                        mime_type: str = _DEFAULT_MIME):
    """
    Build the provider-correct multimodal `content` value for a single user turn.

    Args:
        schema_name: an engine schema name ("openai", "anthropic", "azure", ...).
        prompt:      the accompanying text instruction (may be empty).
        image_b64:   the image payload as a base64-encoded ASCII string. A full
                     data: URI is also accepted (the prefix is stripped for the
                     anthropic shape and passed through for openai).
        mime_type:   image MIME type for the data URI / source block.

    Returns:
        The value to place under a message's "content" key — a list of typed
        content blocks shaped for the target provider.

    Raises:
        ValueError: if *schema_name* does not support the image modality.
    """
    family = _SCHEMA_MODALITY.get(schema_name)
    if family is None:
        supported = ", ".join(sorted(_SCHEMA_MODALITY))
        raise ValueError(
            f"Schema '{schema_name}' does not support the image modality. "
            f"Vision-capable schemas: {supported}"
        )

    raw_b64  = _strip_data_uri(image_b64)
    data_uri = image_b64 if image_b64.startswith("data:") else f"data:{mime_type};base64,{raw_b64}"

    if family == "openai":
        # OpenAI vision: text block + image_url block carrying a data: URI.
        return [
            {"type": "text",      "text": prompt},
            {"type": "image_url", "image_url": {"url": data_uri}},
        ]

    if family == "anthropic":
        # Anthropic vision: text block + image block with a base64 source.
        return [
            {"type": "text", "text": prompt},
            {
                "type": "image",
                "source": {
                    "type":       "base64",
                    "media_type": mime_type,
                    "data":       raw_b64,
                },
            },
        ]

    # Unreachable — _SCHEMA_MODALITY only maps to the two families above.
    raise ValueError(f"Unhandled modality family for schema '{schema_name}'")


def build_audio_message(schema_name: str, prompt: str, audio_b64: str,
                        audio_format: str = "wav"):
    """Provider-correct content block for a text prompt + base64 audio clip.
    openai family → {type:input_audio}; google → inline_data audio part."""
    family = _AUDIO_MODALITY.get(schema_name)
    if family is None:
        raise ValueError(f"Schema '{schema_name}' does not support the audio modality. "
                         f"Audio-capable: {', '.join(sorted(_AUDIO_MODALITY))}")
    raw = _strip_data_uri(audio_b64)
    if family == "openai":
        return [
            {"type": "text", "text": prompt},
            {"type": "input_audio", "input_audio": {"data": raw, "format": audio_format}},
        ]
    # google (Gemini) inline_data part
    return [
        {"text": prompt},
        {"inline_data": {"mime_type": f"audio/{audio_format}", "data": raw}},
    ]


def build_video_message(schema_name: str, prompt: str, frames, mime_type: str = "image/png"):
    """Provider-correct content for a text prompt + video. openai family has no
    native video, so *frames* (a list of base64 images) are sent as image blocks;
    google takes a single video inline_data block (pass one base64 string)."""
    family = _VIDEO_MODALITY.get(schema_name)
    if family is None:
        raise ValueError(f"Schema '{schema_name}' does not support the video modality. "
                         f"Video-capable: {', '.join(sorted(_VIDEO_MODALITY))}")
    if family == "openai_frames":
        seq = frames if isinstance(frames, (list, tuple)) else [frames]
        content = [{"type": "text", "text": prompt}]
        for fr in seq:
            raw = _strip_data_uri(fr)
            content.append({"type": "image_url",
                            "image_url": {"url": f"data:{mime_type};base64,{raw}"}})
        return content
    # google: a single video blob
    raw = _strip_data_uri(frames[0] if isinstance(frames, (list, tuple)) else frames)
    return [
        {"text": prompt},
        {"inline_data": {"mime_type": "video/mp4", "data": raw}},
    ]


def _strip_data_uri(image_b64: str) -> str:
    """Return the bare base64 payload, dropping any leading 'data:...;base64,'."""
    if image_b64.startswith("data:") and ";base64," in image_b64:
        return image_b64.split(";base64,", 1)[1]
    return image_b64
