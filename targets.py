"""
Saved Target Profiles  —  a target book so you don't retype endpoint/model/schema.

    crucible --save-target prod-claude --schema anthropic \
          --endpoint https://api.anthropic.com --model claude-sonnet-4-6
    crucible --target prod-claude --mode redteam        # reuse it
    crucible --list-targets

Stored in .crucible-targets.yaml (git-ignored). For security, API KEYS ARE NOT
SAVED — supply the key at run time via --api-key or the CRUCIBLE_API_KEY env var.
"""
import os

TARGETS_FILE = os.environ.get("CRUCIBLE_TARGETS", ".crucible-targets.yaml")
_FIELDS = ("endpoint", "model", "schema")


def _load_yaml(path):
    try:
        import yaml
    except ImportError:
        return {}
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def load_targets(path: str = None) -> dict:
    return _load_yaml(path or TARGETS_FILE)


def get_target(name: str, path: str = None) -> dict | None:
    return load_targets(path).get(name)


def save_target(name: str, endpoint: str, model: str, schema: str,
                path: str = None) -> str:
    """Save a named target (never the api_key). Returns the file path."""
    import yaml
    path = path or TARGETS_FILE
    data = load_targets(path)
    data[name] = {"endpoint": endpoint, "model": model, "schema": schema}
    with open(path, "w", encoding="utf-8") as f:
        f.write("# CRUCIBLE saved targets — DO NOT store API keys here (git-ignored).\n")
        yaml.safe_dump(data, f, sort_keys=True, allow_unicode=True)
    return path


def delete_target(name: str, path: str = None) -> bool:
    import yaml
    path = path or TARGETS_FILE
    data = load_targets(path)
    if name not in data:
        return False
    del data[name]
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=True, allow_unicode=True)
    return True


def apply_target(args, name: str) -> bool:
    """Fill args.endpoint/model/schema from a saved target where the user didn't
    already pass them. Returns True if the target existed."""
    t = get_target(name)
    if not t:
        return False
    if not getattr(args, "endpoint", None):
        args.endpoint = t.get("endpoint")
    if getattr(args, "model", None) in (None, "gpt-4o"):   # gpt-4o is the argparse default
        args.model = t.get("model", args.model)
    if getattr(args, "schema", None) in (None, "openai"):
        args.schema = t.get("schema", args.schema)
    return True


def print_targets(path: str = None) -> None:
    import colors as C
    data = load_targets(path)
    print(f"\n  {C.BOLD('SAVED TARGETS')}  {C.DIM('(' + (path or TARGETS_FILE) + ')')}")
    if not data:
        print(f"  {C.DIM('none yet — save one with --save-target NAME')}\n")
        return
    print(f"  {'─' * 66}")
    for name, t in sorted(data.items()):
        print(f"  {C.CYAN(name):<20} {t.get('schema', '?'):<10} "
              f"{t.get('model', '?'):<20} {C.DIM(t.get('endpoint', ''))}")
    print()
