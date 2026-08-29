"""
Config File Loader
Reads .ai-redteam.yaml (or --config path) and merges defaults with CLI args.
CLI args always win over config file values.

Default search order:
  1. --config <path>          (explicit)
  2. ./.ai-redteam.yaml       (current directory)
  3. ~/.ai-redteam.yaml       (home directory)

Example .ai-redteam.yaml:
─────────────────────────
schema: anthropic
model: claude-sonnet-4-6
endpoint: https://api.anthropic.com
concurrency: 5
framework: atlas
owasp: true
output_dir: ./my-reports
no_color: false
ci: false
ci_threshold: 30
─────────────────────────
"""

import os

CONFIG_FILENAMES = [".ai-redteam.yaml", ".ai-redteam.yml"]

# Fields that can be set in config and their expected types
CONFIG_SCHEMA = {
    "api_key":       str,
    "endpoint":      str,
    "model":         str,
    "schema":        str,
    "framework":     str,
    "mode":          str,
    "concurrency":   int,
    "output_dir":    str,
    "owasp":         bool,
    "no_color":      bool,
    "verbose":       bool,
    "ci":            bool,
    "ci_threshold":  int,
    "severity":      str,
    "categories":    str,
    "payload_file":  str,
    "skip_connection_test": bool,
    "no_save":       bool,
}

# CLI arg name → config key (where they differ)
CLI_TO_CONFIG = {
    "output_dir":   "output_dir",
    "no_color":     "no_color",
    "no_save":      "no_save",
    "payload_file": "payload_file",
    "ci_threshold": "ci_threshold",
    "skip_connection_test": "skip_connection_test",
}


def find_config(explicit_path: str | None = None) -> str | None:
    """Return path to config file or None if not found."""
    if explicit_path:
        return explicit_path if os.path.exists(explicit_path) else None

    # current directory
    for name in CONFIG_FILENAMES:
        if os.path.exists(name):
            return name

    # home directory
    for name in CONFIG_FILENAMES:
        path = os.path.join(os.path.expanduser("~"), name)
        if os.path.exists(path):
            return path

    return None


def load_config(path: str) -> dict:
    """Load and validate a YAML config file. Returns a clean dict."""
    try:
        import yaml
    except ImportError:
        print("  \033[93mNote:\033[0m PyYAML not installed — config file ignored.")
        print("  Install with: pip install pyyaml --break-system-packages\n")
        return {}

    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"  \033[91mConfig file error ({path}):\033[0m {e}\n")
        return {}

    if not isinstance(raw, dict):
        print("  \033[91mConfig file must be a YAML mapping (key: value pairs).\033[0m\n")
        return {}

    config = {}
    for key, value in raw.items():
        if key not in CONFIG_SCHEMA:
            print(f"  \033[93mConfig warning:\033[0m Unknown key '{key}' — ignored.")
            continue
        expected = CONFIG_SCHEMA[key]
        try:
            config[key] = expected(value)
        except (ValueError, TypeError):
            print(f"  \033[93mConfig warning:\033[0m '{key}' should be {expected.__name__} — ignored.")
            continue

        # Bounds checks for numeric fields
        if key == "concurrency" and not (1 <= config[key] <= 10):
            print("  \033[93mConfig warning:\033[0m 'concurrency' must be 1–10 — ignored.")
            del config[key]
        elif key == "ci_threshold" and not (0 <= config[key] <= 100):
            print("  \033[93mConfig warning:\033[0m 'ci_threshold' must be 0–100 — ignored.")
            del config[key]

    return config


def merge_config_with_args(args, config: dict) -> None:
    """
    Apply config values to args namespace — only where CLI didn't set a value.
    CLI args always take precedence over config file.
    """
    # Mapping from config key → argparse dest attribute
    MAPPING = {
        "api_key":              "api_key",
        "endpoint":             "endpoint",
        "model":                "model",
        "schema":               "schema",
        "framework":            "framework",
        "mode":                 "mode",
        "concurrency":          "concurrency",
        "output_dir":           "output_dir",
        "owasp":                "owasp",
        "no_color":             "no_color",
        "verbose":              "verbose",
        "ci":                   "ci",
        "ci_threshold":         "ci_threshold",
        "severity":             "severity",
        "categories":           "categories",
        "payload_file":         "payload_file",
        "skip_connection_test": "skip_connection_test",
        "no_save":              "no_save",
    }

    # Detect argparse defaults so we only override when user didn't explicitly pass a flag
    ARGPARSE_DEFAULTS = {
        "model":         "gpt-4o",
        "schema":        "openai",
        "concurrency":   1,
        "output_dir":    "./reports",
        "owasp":         False,
        "no_color":      False,
        "verbose":       False,
        "ci":            False,
        "ci_threshold":  30,
        "no_save":       False,
        "skip_connection_test": False,
    }

    for config_key, arg_attr in MAPPING.items():
        if config_key not in config:
            continue

        current = getattr(args, arg_attr, None)
        default = ARGPARSE_DEFAULTS.get(config_key)

        # Only apply config value if the arg is still at its default
        if current == default or current is None:
            setattr(args, arg_attr, config[config_key])


def print_config_summary(path: str, config: dict):
    """Print a one-line summary of the loaded config."""
    keys = [k for k in config if k != "api_key"]  # never show api_key
    print(f"  \033[2mConfig loaded: {path}  ({len(keys)} setting(s): {', '.join(keys)})\033[0m")


def generate_config_template(path: str):
    """Write a starter config file to disk."""
    template = """\
# AI Red Team CLI — Config File
# Place as .ai-redteam.yaml in your project dir or ~/.ai-redteam.yaml
#
# All values here are defaults — CLI flags always override them.

# ── Target ──────────────────────────────────────────────────────
# api_key: sk-xxx           # or set AI_RT_API_KEY env var
# endpoint: https://api.openai.com
model: gpt-4o
schema: openai              # openai | anthropic | google | mistral | cohere | ollama | azure | bedrock | custom

# ── Run behaviour ────────────────────────────────────────────────
concurrency: 1              # parallel workers (1-10)
verbose: false              # print full payload + response per test
no_color: false             # disable ANSI colors (auto-disabled in non-TTY)

# ── Frameworks ───────────────────────────────────────────────────
# framework: atlas          # add MITRE ATLAS tactic coverage report
owasp: false                # add OWASP LLM Top 10 coverage report

# ── CI/CD ────────────────────────────────────────────────────────
ci: false                   # exit code 1 if risk score exceeds threshold
ci_threshold: 30            # score threshold for CI failure (0-100)

# ── Output ───────────────────────────────────────────────────────
output_dir: ./reports
no_save: false

# ── Filters ──────────────────────────────────────────────────────
# severity: Critical,High
# categories: Prompt Injection,Jailbreaking
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(template)
    print(f"  \033[92m✓\033[0m Config template saved → \033[96m{path}\033[0m")
    print("  Edit it, then it will be auto-loaded from that location.\n")
