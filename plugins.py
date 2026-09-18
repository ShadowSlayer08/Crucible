"""
Plugin Loader (roadmap: "Plugin Architecture")

Lets users drop standalone *.py files into a plugins directory, each exporting a
module-level list named ``TESTS`` of test dicts. ``load_plugins()`` scans the
directory, imports every plugin via importlib, validates each test dict against
the standard schema, and returns the merged list.

Standard test-dict schema (identical to payloads/ and payload_loader):
    id, category, severity (Critical|High|Medium|Low), name, payload,
    expected (refusal|safe_response), tags (list)

A plugin that fails to import, that lacks a list-valued ``TESTS`` attribute, or
that contains malformed test dicts is skipped with a warning — one bad plugin
never aborts the whole load. No network calls are performed at import or load
time; this is pure, testable filesystem + introspection logic.
"""

import os
import sys
import importlib.util

# ── Schema constants (shared shape with payload_loader / the bundled corpus) ──
REQUIRED_FIELDS  = {"id", "category", "severity", "name", "payload", "expected"}
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_EXPECTED   = {"refusal", "safe_response"}


def _warn(msg: str) -> None:
    """Emit a non-fatal warning to stderr (kept separate so tests can capture it)."""
    print(f"  [plugins] warning: {msg}", file=sys.stderr)


def _validate_test(test, index: int) -> list:
    """
    Return a list of human-readable error strings for *test* (empty == valid).
    Mirrors payload_loader._validate_test so plugin tests obey the same schema.
    """
    errors = []
    if not isinstance(test, dict):
        return [f"test #{index} is not an object (got {type(test).__name__})"]

    missing = REQUIRED_FIELDS - set(test.keys())
    if missing:
        errors.append(f"test #{index} ({test.get('id', '?')}): "
                      f"Missing required fields: {', '.join(sorted(missing))}")

    sev = test.get("severity")
    if sev is not None and sev not in VALID_SEVERITIES:
        errors.append(f"test #{index} ({test.get('id', '?')}): "
                      f"invalid severity '{sev}' (use {'/'.join(sorted(VALID_SEVERITIES))})")

    exp = test.get("expected")
    if exp is not None and exp not in VALID_EXPECTED:
        errors.append(f"test #{index} ({test.get('id', '?')}): "
                      f"invalid expected '{exp}' (use {'/'.join(sorted(VALID_EXPECTED))})")

    payload = test.get("payload")
    if payload is not None and (not isinstance(payload, str) or not payload.strip()):
        errors.append(f"test #{index} ({test.get('id', '?')}): payload is empty")

    tags = test.get("tags")
    if tags is not None and not isinstance(tags, list):
        errors.append(f"test #{index} ({test.get('id', '?')}): tags must be a list")

    return errors


def discover_plugin_files(plugins_dir: str = "plugins") -> list:
    """
    Return a sorted list of absolute paths to candidate plugin files in
    *plugins_dir*: every ``*.py`` file that is not ``__init__`` and does not
    start with an underscore. Returns [] if the directory does not exist.
    """
    if not os.path.isdir(plugins_dir):
        return []

    found = []
    for name in os.listdir(plugins_dir):
        if not name.endswith(".py"):
            continue
        if name.startswith("_") or name == "__init__.py":
            continue
        path = os.path.join(plugins_dir, name)
        if os.path.isfile(path):
            found.append(os.path.abspath(path))
    return sorted(found)


def _import_plugin_module(path: str):
    """
    Import a single plugin file by path and return the module object.
    Uses a unique synthetic module name so two plugins with the same filename
    in different directories don't collide in sys.modules.
    """
    mod_name = "crucible_plugin_" + os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not create import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_plugins(plugins_dir: str = "plugins") -> list:
    """
    Scan *plugins_dir*, import every plugin file, and collect the module-level
    ``TESTS`` list from each. Every test dict is validated against the standard
    schema; invalid dicts are skipped with a warning. Plugins that fail to import
    or expose no ``TESTS`` list are skipped with a warning.

    Returns the merged list of valid test dicts (empty if the directory is
    missing or contains nothing usable).
    """
    merged = []
    for path in discover_plugin_files(plugins_dir):
        try:
            module = _import_plugin_module(path)
        except Exception as e:  # noqa: BLE001 — a broken plugin must not abort the load
            _warn(f"failed to import {os.path.basename(path)}: {e}")
            continue

        tests = getattr(module, "TESTS", None)
        if tests is None:
            _warn(f"{os.path.basename(path)} has no module-level TESTS list — skipped")
            continue
        if not isinstance(tests, list):
            _warn(f"{os.path.basename(path)} TESTS is not a list "
                  f"(got {type(tests).__name__}) — skipped")
            continue

        for i, test in enumerate(tests):
            errors = _validate_test(test, i)
            if errors:
                _warn(f"{os.path.basename(path)}: skipping invalid test — "
                      f"{'; '.join(errors)}")
                continue
            # Normalize tags to a list and tag the source so reports can group by plugin.
            test.setdefault("tags", [])
            if "plugin" not in test["tags"]:
                test["tags"] = test["tags"] + ["plugin"]
            merged.append(test)

    return merged
