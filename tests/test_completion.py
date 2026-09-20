"""Shell completion — introspect the CLI parser and emit bash/zsh/fish scripts."""
import pytest

import completion
import main

parser = main.build_parser()


def test_collect_options_and_choices():
    opts, choices = completion.collect(parser)
    assert "--mode" in opts and "--grader" in opts and "--completion" in opts
    assert "vapt" in choices["--mode"]
    assert "harmbench" in choices["--grader"]


def test_shells_constant():
    assert completion.SHELLS == ("bash", "zsh", "fish")


def test_render_bash():
    s = completion.render("bash", parser)
    assert "_crucible_complete" in s
    assert "complete -F _crucible_complete crucible cru" in s
    assert "--mode" in s
    assert "--mode) COMPREPLY" in s          # per-choice case arm


def test_render_zsh():
    s = completion.render("zsh", parser)
    assert s.startswith("#compdef")
    assert "compdef _crucible crucible cru" in s
    assert "--mode) compadd" in s


def test_render_fish():
    s = completion.render("fish", parser)
    assert "complete -c crucible -l mode" in s
    assert "complete -c cru -l mode" in s
    assert "-l grader" in s and "harmbench" in s   # choice option carries its values


def test_render_unknown_shell_raises():
    with pytest.raises(ValueError):
        completion.render("powershell", parser)


def test_render_is_stable_across_calls():
    # deterministic output (sorted) — important for diffing generated scripts
    assert completion.render("bash", parser) == completion.render("bash", parser)
