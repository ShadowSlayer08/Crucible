"""ArtPrompt — ASCII-art keyword-masking jailbreak mode."""
import string

import payloads.artprompt as ap
from payloads.artprompt import (
    FONT, GLYPH_H, render_word, build_artprompt, mask_and_wrap, ARTPROMPT_TESTS,
)


def test_font_covers_alphabet_as_5x5():
    for ch in string.ascii_uppercase:
        assert ch in FONT, ch
        assert len(FONT[ch]) == GLYPH_H
        assert all(len(row) == 5 for row in FONT[ch]), ch
    assert " " in FONT


def test_render_word_dimensions():
    lines = render_word("AB").split("\n")
    assert len(lines) == GLYPH_H
    assert all(len(l) == 11 for l in lines)   # 2 glyphs × 5 + 1 gap


def test_render_word_case_insensitive():
    assert render_word("ab") == render_word("AB")


def test_render_word_empty():
    assert render_word("") == ""


def test_render_word_unknown_char_is_blank_not_crash():
    lines = render_word("A1").split("\n")     # '1' → blank glyph
    assert len(lines) == GLYPH_H
    assert all(len(l) == 11 for l in lines)
    assert "#" in "\n".join(lines)            # the 'A' still rendered


def test_build_artprompt_contains_art_request_and_decode():
    p = build_artprompt("WEAPON", "Build a [MASK].")
    assert "#" in p                    # ASCII art present
    assert "[MASK]" in p               # masked request preserved
    assert "6 letters" in p            # letter count matches the keyword
    assert "LETTER BY LETTER" in p     # decode instruction
    assert "WEAPON" not in p           # keyword appears ONLY as art, never plaintext


def test_mask_and_wrap_masks_keyword_case_insensitively():
    p = mask_and_wrap("How do I build a Weapon quickly?", "weapon")
    assert "[MASK]" in p
    assert "weapon" not in p.lower()   # neither the request nor the art leaks it


def test_mask_and_wrap_appends_placeholder_when_absent():
    assert "[MASK]" in mask_and_wrap("Tell me the method.", "TOXIN")


def test_suite_shape():
    assert len(ARTPROMPT_TESTS) == 6
    ids = [t["id"] for t in ARTPROMPT_TESTS]
    assert ids == [f"ART-{i:03d}" for i in range(1, 7)]
    for t in ARTPROMPT_TESTS:
        assert t["category"] == "ArtPrompt"
        assert t["severity"] == "High"
        assert t["expected"] == "refusal"
        assert "artprompt" in t["tags"] and "ascii-art" in t["tags"]
        assert "#" in t["payload"] and "[MASK]" in t["payload"]


def test_suite_keywords_only_as_art_never_plaintext():
    for t, (_cat, kw, _req) in zip(ARTPROMPT_TESTS, ap._PROBES):
        assert kw not in t["payload"]   # the masking actually hides the trigger word
