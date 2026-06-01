"""Render a subprocess's ANSI (Rich) output as HTML for the console dialog.

The CLI uses Rich for pretty terminal output, but a ``QProcess`` is a pipe, so
Rich would normally drop the colour. The workbench runs subprocesses with
``FORCE_COLOR=1`` so Rich emits ANSI even down the pipe, and this module turns
those ANSI SGR sequences into HTML ``<span>``s the dialog can show in colour
(D128).

``ansi_to_html`` is a pure function -- no Qt -- so it is unit-tested directly.
It handles the SGR subset Rich's *standard* colour system emits (reset, bold,
italic, underline, the 16 basic foreground colours, plus 256/truecolour for
safety) and strips other control sequences (cursor moves, line clears, ``\\r``).
"""

from __future__ import annotations

import html
import re

_SGR = re.compile(r"\x1b\[([0-9;]*)m")
# Other CSI sequences (cursor moves, clear line, ...) and OSC -- stripped.
_OTHER_CSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-ln-z]")
_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")

# The 16 basic ANSI foreground colours (30-37 normal, 90-97 bright) as hex,
# tuned for a dark console background.
_BASIC: dict[int, str] = {
    30: "#3b3b3b", 31: "#e05561", 32: "#8cc265", 33: "#d8b76a",
    34: "#5a9bf0", 35: "#c678dd", 36: "#56b6c2", 37: "#c8ccd4",
    90: "#7f848e", 91: "#ff7b86", 92: "#a5e075", 93: "#f0d488",
    94: "#73b3ff", 95: "#dd9bf0", 96: "#6fd3e0", 97: "#ffffff",
}


def _xterm256(index: int) -> str:
    if index < 16:  # the basic 16, via the normal/bright tables
        return _BASIC.get(index + 30 if index < 8 else index + 82, "#c8ccd4")
    if index < 232:  # 6x6x6 colour cube (standard xterm component levels)
        index -= 16
        levels = (0, 95, 135, 175, 215, 255)
        red = levels[(index // 36) % 6]
        green = levels[(index // 6) % 6]
        blue = levels[index % 6]
        return f"#{red:02x}{green:02x}{blue:02x}"
    grey = 8 + (index - 232) * 10  # 24-step greyscale ramp
    return f"#{grey:02x}{grey:02x}{grey:02x}"


def _style(fg: str | None, bold: bool, italic: bool, underline: bool) -> str:
    parts = []
    if fg:
        parts.append(f"color:{fg}")
    if bold:
        parts.append("font-weight:bold")
    if italic:
        parts.append("font-style:italic")
    if underline:
        parts.append("text-decoration:underline")
    return ";".join(parts)


def _apply(
    params: str, fg: str | None, bold: bool, italic: bool, underline: bool
) -> tuple[str | None, bool, bool, bool]:
    codes = [int(token) for token in params.split(";") if token != ""] or [0]
    index = 0
    while index < len(codes):
        code = codes[index]
        if code == 0:
            fg, bold, italic, underline = None, False, False, False
        elif code == 1:
            bold = True
        elif code == 22:
            bold = False
        elif code == 3:
            italic = True
        elif code == 23:
            italic = False
        elif code == 4:
            underline = True
        elif code == 24:
            underline = False
        elif 30 <= code <= 37 or 90 <= code <= 97:
            fg = _BASIC[code]
        elif code == 39:
            fg = None
        elif code == 38 and index + 1 < len(codes):
            if codes[index + 1] == 5 and index + 2 < len(codes):
                fg = _xterm256(codes[index + 2])
                index += 2
            elif codes[index + 1] == 2 and index + 4 < len(codes):
                fg = f"#{codes[index + 2]:02x}{codes[index + 3]:02x}{codes[index + 4]:02x}"
                index += 4
        # Background colours (40-49, 100-107) and other attributes are ignored.
        index += 1
    return fg, bold, italic, underline


def ansi_to_html(text: str) -> str:
    """Convert ANSI-coloured ``text`` into HTML with ``<span>`` colour runs.

    The output is meant to live inside a ``<pre>`` (it preserves newlines and
    spaces and HTML-escapes the text). Plain text passes through escaped, with no
    spans.
    """

    text = _OSC.sub("", text)
    text = _OTHER_CSI.sub("", text)
    text = text.replace("\r", "")
    out: list[str] = []
    fg: str | None = None
    bold = italic = underline = False
    position = 0
    for match in _SGR.finditer(text):
        segment = text[position : match.start()]
        if segment:
            style = _style(fg, bold, italic, underline)
            escaped = html.escape(segment)
            out.append(f'<span style="{style}">{escaped}</span>' if style else escaped)
        position = match.end()
        fg, bold, italic, underline = _apply(match.group(1), fg, bold, italic, underline)
    tail = text[position:]
    if tail:
        style = _style(fg, bold, italic, underline)
        escaped = html.escape(tail)
        out.append(f'<span style="{style}">{escaped}</span>' if style else escaped)
    return "".join(out)
