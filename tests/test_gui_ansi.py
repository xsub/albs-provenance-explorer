"""ANSI (Rich) -> HTML conversion for the workbench console dialog (D128).

Pure, no Qt: the subprocess emits ANSI (Rich with FORCE_COLOR) down the
QProcess pipe and the dialog renders it as coloured HTML inside a <pre>.
"""

from __future__ import annotations

from albs_graph.gui.ansi import ansi_to_html


def test_basic_colours_become_coloured_spans() -> None:
    # Rich's standard system: 36=cyan, 33=yellow, 32=green, 0=reset.
    html = ansi_to_html("\x1b[36mstep\x1b[0m \x1b[32mok\x1b[0m")
    assert '<span style="color:#56b6c2">step</span>' in html
    assert '<span style="color:#8cc265">ok</span>' in html
    assert "step</span> <span" in html  # the plain space between is preserved


def test_reset_clears_and_bold_italic_underline() -> None:
    assert "font-weight:bold" in ansi_to_html("\x1b[1;31mx\x1b[0m")
    assert "font-style:italic" in ansi_to_html("\x1b[3mx\x1b[0m")
    assert "text-decoration:underline" in ansi_to_html("\x1b[4mx\x1b[0m")
    # After a reset, the following text carries no span styling.
    assert ansi_to_html("\x1b[31mred\x1b[0m plain").endswith("plain")


def test_text_is_html_escaped() -> None:
    # No raw HTML can leak from subprocess output.
    assert ansi_to_html("<b> & </b>") == "&lt;b&gt; &amp; &lt;/b&gt;"
    assert "<b>" not in ansi_to_html("\x1b[31m<b>\x1b[0m")


def test_strips_cursor_moves_carriage_returns_and_osc() -> None:
    # Progress-bar redraws (clear-line, CR) and window-title (OSC) are dropped.
    assert ansi_to_html("a\x1b[2Kb\rc") == "abc"
    assert ansi_to_html("\x1b]0;title\x07done") == "done"


def test_256_and_truecolour_foreground() -> None:
    assert 'color:#' in ansi_to_html("\x1b[38;5;82mx\x1b[0m")  # 256-colour index
    assert 'color:#0a141e' in ansi_to_html("\x1b[38;2;10;20;30mx\x1b[0m")  # truecolour


def test_plain_text_passes_through_without_spans() -> None:
    assert ansi_to_html("just plain text") == "just plain text"
