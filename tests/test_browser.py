"""Tests for engine_browser.BrowserAdapter — the generic Playwright Browser Mode.

These tests do NOT require playwright to be installed (it is an optional dep).
They verify the module imports cleanly, the capability probe returns a bool,
config schema help is well-formed, and that send() degrades gracefully with a
clear, actionable error when playwright is absent. The real browser-drive path
is skipped (no headless browser in CI)."""

import pytest

import engine_browser
from engine_browser import (
    BrowserAdapter,
    browser_schema_help,
    playwright_available,
)


# ── Import / module-surface ───────────────────────────────────────────────────

def test_module_imports_without_playwright():
    # The mere fact this test runs means `import engine_browser` succeeded even
    # though playwright is not installed in this environment.
    assert hasattr(engine_browser, "BrowserAdapter")
    assert callable(engine_browser.browser_schema_help)


def test_available_returns_bool():
    adapter = BrowserAdapter({
        "url": "http://localhost:9/chat",
        "input_selector": "#in",
        "response_selector": ".resp",
    })
    result = adapter.available()
    assert isinstance(result, bool)
    # Module-level probe and instance method agree.
    assert result == playwright_available()


def test_schema_help_describes_required_keys():
    help_text = browser_schema_help()
    assert isinstance(help_text, str)
    for flag in ("--browser-url", "--browser-input-selector",
                 "--browser-response-selector"):
        assert flag in help_text


# ── Config handling ───────────────────────────────────────────────────────────

def test_non_dict_config_rejected():
    with pytest.raises(TypeError):
        BrowserAdapter("not-a-dict")


def test_defaults_applied():
    adapter = BrowserAdapter({
        "url": "http://localhost:9/chat",
        "input_selector": "#in",
        "response_selector": ".resp",
    })
    assert adapter.headless is True
    assert adapter.timeout_ms == engine_browser.DEFAULT_TIMEOUT_MS
    assert adapter.submit_selector is None  # optional → falls back to Enter


# ── Graceful degradation when playwright is absent ────────────────────────────

def test_send_raises_clear_error_without_playwright():
    if playwright_available():
        pytest.skip("playwright is installed — the missing-dep path is not exercised")

    adapter = BrowserAdapter({
        "url": "http://localhost:9/chat",
        "input_selector": "#in",
        "response_selector": ".resp",
    })
    with pytest.raises(RuntimeError) as excinfo:
        adapter.send("hello")

    msg = str(excinfo.value)
    # Error must be actionable: name the dependency and how to install it.
    assert "playwright" in msg.lower()
    assert "pip install playwright" in msg


def test_real_browser_drive_skipped_without_playwright():
    if not playwright_available():
        pytest.skip("playwright not installed — skipping real headless drive test")
    # If playwright IS present we still avoid launching a real browser in CI;
    # just assert the adapter is wired to attempt a drive.
    adapter = BrowserAdapter({
        "url": "about:blank",
        "input_selector": "#in",
        "response_selector": ".resp",
    })
    assert adapter.available() is True
