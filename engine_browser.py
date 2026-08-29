"""
Browser Mode — generic Playwright adapter for driving a web chat UI.

Roadmap "Browser Mode": some AI chat targets have no REST API the engine can
hit directly — they only expose a browser front-end. This adapter drives ANY
user-configured web chat UI by typing the payload into an input box and reading
back the rendered response.

It is deliberately GENERIC and config-driven: the caller supplies the URL and
the CSS selectors for the input box, the submit control, and the response
element. Nothing is hardcoded to a specific provider's site (ChatGPT, Claude.ai,
Gemini, etc.) — automating those directly would violate their terms of service.
Point it only at endpoints you are authorized to test (self-hosted UIs, local
demos, your own deployments).

Playwright is an OPTIONAL dependency and is NOT bundled. The import is guarded:
the module imports cleanly without playwright installed, and a clear
RuntimeError (with install instructions) is raised ONLY when .send() is actually
invoked. Probe availability up-front with .available().

Required config keys (see browser_schema_help() for the CLI-flag mapping):
  url                → the chat UI page to open
  input_selector     → CSS selector for the message input box / textarea
  submit_selector    → CSS selector for the send button (optional; falls back
                       to pressing Enter in the input box if omitted)
  response_selector  → CSS selector matching assistant response bubbles; the
                       LAST match is read as the reply

Optional config keys:
  headless           → bool, run without a visible window (default True)
  timeout_ms         → per-action timeout in milliseconds (default 30000)
  wait_after_submit_ms → settle time after submit before reading (default 1500)
  response_attr      → read this attribute instead of inner_text (default None)
"""

from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# OPTIONAL DEPENDENCY — guarded import (never fails at module import time)
# ─────────────────────────────────────────────────────────────────────────────

try:
    from playwright.sync_api import sync_playwright as _sync_playwright
    _PLAYWRIGHT_IMPORT_ERROR: Optional[Exception] = None
except Exception as _exc:  # ImportError, or a broken partial install
    _sync_playwright = None
    _PLAYWRIGHT_IMPORT_ERROR = _exc


_INSTALL_HINT = (
    "Browser Mode requires the optional 'playwright' dependency, which is not "
    "installed.\n"
    "  Install it with:\n"
    "      pip install playwright\n"
    "      python -m playwright install chromium\n"
    "Then re-run with your --browser-* configuration."
)


# ─────────────────────────────────────────────────────────────────────────────
# DEFAULTS
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT_MS           = 30000
DEFAULT_WAIT_AFTER_SUBMIT_MS = 1500
REQUIRED_KEYS = ("url", "input_selector", "response_selector")


def playwright_available() -> bool:
    """True when playwright is importable in this environment."""
    return _sync_playwright is not None


def browser_schema_help() -> str:
    """Human-readable description of the --browser-* config keys."""
    return (
        "\n  Browser Mode — drive a user-configured web chat UI (optional: playwright)\n\n"
        "  Required:\n"
        "    --browser-url URL                Chat UI page to open\n"
        "    --browser-input-selector CSS     CSS selector for the message input box\n"
        "    --browser-response-selector CSS  CSS selector for assistant reply bubbles\n"
        "                                     (the LAST match is read as the response)\n\n"
        "  Optional:\n"
        "    --browser-submit-selector CSS    Send button; if omitted, Enter is pressed\n"
        "    --browser-headless BOOL          Run without a window (default: true)\n"
        "    --browser-timeout-ms N           Per-action timeout in ms (default: 30000)\n"
        "    --browser-wait-ms N              Settle time after submit (default: 1500)\n"
        "    --browser-response-attr ATTR     Read this attribute instead of inner text\n\n"
        "  Note: point this only at endpoints you are authorized to test (self-hosted\n"
        "  UIs, local demos, your own deployments). Do not use it to automate a\n"
        "  third-party provider's website in violation of their terms of service.\n"
    )


class BrowserAdapter:
    """
    Generic Playwright-backed adapter for a web chat UI.

    Usage:
        adapter = BrowserAdapter({
            "url": "http://localhost:8080/chat",
            "input_selector": "#prompt",
            "submit_selector": "button.send",
            "response_selector": ".message.assistant",
        })
        if adapter.available():
            reply = adapter.send("Hello")

    The adapter opens a fresh browser context per .send() call so each test is
    isolated (no cross-test conversation history leaking through the UI). For a
    reusable session, wrap calls in your own loop and rely on the same config.
    """

    def __init__(self, config: dict):
        if not isinstance(config, dict):
            raise TypeError("BrowserAdapter config must be a dict")
        self.config = dict(config)
        self.url               = self.config.get("url", "")
        self.input_selector    = self.config.get("input_selector", "")
        self.submit_selector   = self.config.get("submit_selector")  # optional
        self.response_selector = self.config.get("response_selector", "")
        self.headless          = bool(self.config.get("headless", True))
        self.timeout_ms        = int(self.config.get("timeout_ms", DEFAULT_TIMEOUT_MS))
        self.wait_after_submit_ms = int(
            self.config.get("wait_after_submit_ms", DEFAULT_WAIT_AFTER_SUBMIT_MS)
        )
        self.response_attr     = self.config.get("response_attr")  # optional

    # ── Capability probe ──────────────────────────────────────────────────────
    def available(self) -> bool:
        """True when the optional playwright dependency is importable.

        Pure capability check — does not launch a browser or touch the network.
        """
        return playwright_available()

    # ── Config validation ─────────────────────────────────────────────────────
    def _validate_config(self) -> None:
        missing = [k for k in REQUIRED_KEYS if not self.config.get(k)]
        if missing:
            raise ValueError(
                "BrowserAdapter is missing required config key(s): "
                + ", ".join(missing)
                + ". See browser_schema_help() for the required --browser-* flags."
            )

    # ── Core: drive the UI and return the model's reply ───────────────────────
    def send(self, prompt: str) -> str:
        """
        Type *prompt* into the configured chat UI and return the rendered reply.

        Raises:
            RuntimeError  if playwright is not installed (with install hint).
            ValueError    if required config keys are missing.
        """
        if not self.available():
            raise RuntimeError(_INSTALL_HINT) from _PLAYWRIGHT_IMPORT_ERROR

        self._validate_config()
        return self._drive(prompt)

    def _drive(self, prompt: str) -> str:
        """Open a browser, submit the prompt, and read back the response.

        Separated from send() so the import-guard / config-validation surface
        stays free of any playwright-only code paths.
        """
        with _sync_playwright() as pw:
            browser = pw.chromium.launch(headless=self.headless)
            try:
                context = browser.new_context()
                page = context.new_page()
                page.set_default_timeout(self.timeout_ms)

                page.goto(self.url)
                page.fill(self.input_selector, prompt)

                # Count existing response bubbles so we can detect the NEW one.
                before = page.locator(self.response_selector).count()

                if self.submit_selector:
                    page.click(self.submit_selector)
                else:
                    page.press(self.input_selector, "Enter")

                # Wait for a newly-rendered response bubble to appear.
                self._wait_for_new_response(page, before)
                page.wait_for_timeout(self.wait_after_submit_ms)

                return self._read_last_response(page)
            finally:
                browser.close()

    def _wait_for_new_response(self, page, before_count: int) -> None:
        """Best-effort wait until the response-bubble count grows past *before*.

        Falls back to a fixed settle wait if no new bubble is detected within
        the configured timeout (the UI may reuse a single response element).
        """
        try:
            page.wait_for_function(
                "([sel, n]) => document.querySelectorAll(sel).length > n",
                arg=[self.response_selector, before_count],
                timeout=self.timeout_ms,
            )
        except Exception:
            # Single-element UIs (response renders in place) won't trip the
            # count check — fall through and let the settle wait + read handle it.
            page.wait_for_timeout(self.wait_after_submit_ms)

    def _read_last_response(self, page) -> str:
        """Read the LAST matching response element as text (or an attribute)."""
        locator = page.locator(self.response_selector)
        count = locator.count()
        if count == 0:
            return ""
        last = locator.nth(count - 1)
        if self.response_attr:
            value = last.get_attribute(self.response_attr)
            return value or ""
        return (last.inner_text() or "").strip()
