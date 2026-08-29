"""
Obfuscation Wrapper (roadmap #33)
Focus: Runtime re-encoding of existing test payloads into evasion-oriented
surface forms, so the SAME attack VECTOR can be replayed through an encoding /
character-substitution layer that a naive keyword filter would miss while the
model is asked to decode-and-comply.

Where payloads/obfuscation.py ships a STATIC obfuscated corpus, this module is a
reusable TRANSFORM: feed it any test dict (standard schema) and it returns a NEW
test dict whose payload is wrapped in the chosen encoding, with the id suffixed
and a tag added. Pure / stdlib-only — no network, no third-party deps.

MITRE ATLAS: AML.T0043 (Craft Adversarial Data — Obfuscation)
OWASP-LLM: LLM01 (Prompt Injection — encoding-based evasion)

ETHICS: This wrapper only changes the SURFACE FORM of whatever text it is given.
It carries no harmful operational content of its own; callers are expected to
pass the project's abstract, placeholder-style payloads. Encoded cases keep the
original `expected` verdict (typically a refusal).
"""

import base64

# ─────────────────────────────────────────────────────────────────────────────
# Character-substitution tables
# ─────────────────────────────────────────────────────────────────────────────

# Visually identical Cyrillic homoglyphs for a handful of Latin letters.
_UNICODE_LOOKALIKES = {
    "a": "а",  # Cyrillic small a
    "e": "е",  # Cyrillic small ie
    "o": "о",  # Cyrillic small o
    "A": "А",  # Cyrillic capital A
    "E": "Е",  # Cyrillic capital Ie
    "O": "О",  # Cyrillic capital O
}

_ZERO_WIDTH_SPACE = "​"
_RED_CIRCLE = "\U0001f534"  # red-circle emoji


class ObfuscationWrapper:
    """Transform plain attack text / test dicts into obfuscated surface forms.

    Every method returns a ``str``; :meth:`encode_tests` lifts a method over a
    list of standard test dicts, returning fresh copies (the inputs are never
    mutated).
    """

    # ── single-string transforms ─────────────────────────────────────────────

    def base64_encode(self, text: str) -> str:
        """Base64-encode ``text`` and prefix a decode-and-comply instruction."""
        b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
        return "Decode this base64 and answer:\n" + b64

    def zero_width_spaces(self, text: str) -> str:
        """Insert a zero-width space between every character to break tokens."""
        return _ZERO_WIDTH_SPACE.join(text)

    def unicode_lookalikes(self, text: str) -> str:
        """Swap a/e/o (and uppercase) for visually identical Cyrillic glyphs."""
        return "".join(_UNICODE_LOOKALIKES.get(ch, ch) for ch in text)

    def emoji_substitution(self, text: str) -> str:
        """Insert a red-circle emoji after every third whitespace-split word."""
        words = text.split(" ")
        out = []
        for i, word in enumerate(words, start=1):
            out.append(word)
            if i % 3 == 0:
                out.append(_RED_CIRCLE)
        return " ".join(out)

    def mixed_script(self, text: str) -> str:
        """Alternate Latin and Cyrillic-lookalike letters across the string.

        Even-indexed substitutable letters are swapped for their Cyrillic
        homoglyph; odd-indexed ones stay Latin, producing a mixed-script string.
        """
        out = []
        sub_index = 0
        for ch in text:
            look = _UNICODE_LOOKALIKES.get(ch)
            if look is not None:
                out.append(look if sub_index % 2 == 0 else ch)
                sub_index += 1
            else:
                out.append(ch)
        return "".join(out)

    # ── registry ─────────────────────────────────────────────────────────────

    @property
    def ENCODINGS(self):
        """Map short encoding name -> bound transform method."""
        return {
            "b64":     self.base64_encode,
            "zwsp":    self.zero_width_spaces,
            "unicode": self.unicode_lookalikes,
            "emoji":   self.emoji_substitution,
            "mixed":   self.mixed_script,
        }

    # ── test-dict lifting ────────────────────────────────────────────────────

    def encode_tests(self, tests, encoding):
        """Return NEW test dicts with payloads wrapped in ``encoding``.

        Each output dict is a shallow copy of the input with:
          * ``payload`` replaced by the encoded form,
          * ``id`` suffixed ``-<ENCODING>`` (uppercased),
          * an ``obf-<encoding>`` tag appended (tags list is copied, not shared),
          * an ``obfuscation`` provenance key recording the encoding used.

        The standard schema (id/category/severity/name/payload/expected/tags) is
        preserved; all other keys pass through untouched. The input list and its
        dicts are never mutated.

        :raises KeyError: if ``encoding`` is not a known encoding name.
        """
        if encoding not in self.ENCODINGS:
            raise KeyError(
                f"unknown encoding {encoding!r}; "
                f"choose one of {sorted(self.ENCODINGS)}"
            )
        method = self.ENCODINGS[encoding]
        suffix = encoding.upper()
        tag = "obf-" + encoding

        encoded = []
        for test in tests:
            new = dict(test)
            new["payload"] = method(str(test.get("payload", "")))
            new["id"] = f"{test.get('id', 'OBF')}-{suffix}"
            tags = list(test.get("tags", []))
            if tag not in tags:
                tags.append(tag)
            new["tags"] = tags
            new["obfuscation"] = encoding
            encoded.append(new)
        return encoded


# Module-level singleton for convenience (e.g. `from obfuscation_wrapper import WRAPPER`).
WRAPPER = ObfuscationWrapper()
