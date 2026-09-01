"""
Color utility — centralized ANSI color control.
Import this instead of defining lambdas in every module.
Respects --no-color flag and NO_COLOR env var (https://no-color.org/).
"""

import os
import sys

# Will be set to False by --no-color flag at startup
_COLOR_ENABLED = True


def init(enabled: bool = True):
    """Call once at startup with the value of --no-color."""
    global _COLOR_ENABLED
    # Also respect NO_COLOR env var and non-TTY output
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        _COLOR_ENABLED = False
    else:
        _COLOR_ENABLED = enabled


def force_utf8() -> None:
    """Reconfigure stdout/stderr to UTF-8 so box-drawing/emoji output doesn't crash
    on a Windows cp1252 console. Safe to call from any module entrypoint."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # py3.7+
        except Exception:
            pass


def _c(text: str, code: str) -> str:
    if not _COLOR_ENABLED:
        return str(text)
    return f"\033[{code}m{text}\033[0m"


def strip(text: str) -> str:
    """Strip all ANSI escape codes from a string."""
    import re
    return re.sub(r"\033\[[0-9;]*m", "", text)


# ── Named color functions ─────────────────────────────────────────────────────
def BOLD(t):    return _c(t, "1")
def DIM(t):     return _c(t, "2")
def RED(t):     return _c(t, "91")
def GREEN(t):   return _c(t, "92")
def YELLOW(t):  return _c(t, "93")
def BLUE(t):    return _c(t, "94")
def MAGENTA(t): return _c(t, "95")
def CYAN(t):    return _c(t, "96")

SEV_COLOR = {
    "Critical": RED,
    "High":     MAGENTA,
    "Medium":   YELLOW,
    "Low":      DIM,
}
