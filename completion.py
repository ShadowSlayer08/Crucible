"""
Shell completion — emit a bash / zsh / fish completion script for the CRUCIBLE CLI.

Introspects the argparse parser (passed in, to avoid an import cycle with main) so
the option list and per-option choices stay in sync automatically. Dependency-free:
no argcomplete, no runtime hook — the user sources the printed script.

  crucible --completion bash >> ~/.bashrc         # or a bash-completion.d file
  crucible --completion zsh  > ~/.zfunc/_crucible
  crucible --completion fish > ~/.config/fish/completions/crucible.fish

Public API
----------
    SHELLS                              -> tuple[str]
    collect(parser)                    -> (options: list[str], choices: {opt: [vals]})
    render(shell, parser, prog=...)    -> str   (the completion script)
"""
SHELLS = ("bash", "zsh", "fish")
_PROGS = ("crucible", "cru")


def collect(parser):
    """Return (sorted unique option strings, {option: [choice, …]}) from *parser*."""
    opts, choices = [], {}
    for action in parser._actions:
        for opt in action.option_strings:
            opts.append(opt)
            if action.choices:
                choices[opt] = [str(c) for c in action.choices]
    return sorted(set(opts)), choices


def render(shell: str, parser, prog: str = "crucible") -> str:
    shell = (shell or "").strip().lower()
    if shell not in SHELLS:
        raise ValueError(f"unknown shell {shell!r}; choose from {SHELLS}")
    opts, choices = collect(parser)
    return {"bash": _bash, "zsh": _zsh, "fish": _fish}[shell](opts, choices)


# ── bash ──────────────────────────────────────────────────────────────────────

def _bash(opts, choices) -> str:
    all_opts = " ".join(opts)
    arms = []
    for opt, vals in sorted(choices.items()):
        arms.append(f'        {opt}) COMPREPLY=( $(compgen -W "{" ".join(vals)}" -- "$cur") ); return;;')
    case_block = ("\n    case \"$prev\" in\n" + "\n".join(arms) + "\n    esac\n") if arms else ""
    funcs = " ".join(_PROGS)
    return f"""# CRUCIBLE bash completion — source this file or add it to bash-completion.d
_crucible_complete() {{
    local cur prev
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
{case_block}
    if [[ "$cur" == -* || -z "$cur" ]]; then
        COMPREPLY=( $(compgen -W "{all_opts}" -- "$cur") )
    fi
}}
complete -F _crucible_complete {funcs}
"""


# ── zsh ───────────────────────────────────────────────────────────────────────

def _zsh(opts, choices) -> str:
    all_opts = " ".join(opts)
    arms = []
    for opt, vals in sorted(choices.items()):
        arms.append(f"        {opt}) compadd -- {' '.join(vals)}; return;;")
    case_block = ("\n    case $prev in\n" + "\n".join(arms) + "\n    esac\n") if arms else ""
    return f"""#compdef {' '.join(_PROGS)}
# CRUCIBLE zsh completion — put this on your $fpath as _crucible
_crucible() {{
    local cur prev
    cur=${{words[CURRENT]}}
    prev=${{words[CURRENT-1]}}
{case_block}
    compadd -- {all_opts}
}}
compdef _crucible {' '.join(_PROGS)}
"""


# ── fish ──────────────────────────────────────────────────────────────────────

def _fish(opts, choices) -> str:
    lines = ["# CRUCIBLE fish completion — save as ~/.config/fish/completions/crucible.fish"]
    choice_set = set(choices)
    for prog in _PROGS:
        for opt in opts:
            if not opt.startswith("--"):
                continue                       # fish long-option completion only
            name = opt[2:]
            if opt in choice_set:
                lines.append(f'complete -c {prog} -l {name} -x -a "{" ".join(choices[opt])}"')
            else:
                lines.append(f"complete -c {prog} -l {name}")
    return "\n".join(lines) + "\n"
