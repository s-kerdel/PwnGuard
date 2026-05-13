"""
PwnGuard UI primitives: ANSI styling, hyperlinks, spinner, terminal width,
and a minimal raw-mode key reader for the interactive review TUI.

All terminal styling lives here so a future theme (or a plain/markdown
output mode) only has to touch this one file. audit.py never emits raw
ANSI codes; it calls helpers like ``ui.bold`` / ``ui.severity_color``.
"""

import os
import re
import select
import shutil
import sys
import threading
import time
from typing import Optional


# ---------------------------------------------------------------------------
# Raw ANSI codes (use the helper functions below in normal code).
# ---------------------------------------------------------------------------

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    # Foreground colors
    RED = "\033[91m"
    YELLOW = "\033[93m"
    ORANGE = "\033[33m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"
    GREEN = "\033[92m"
    WHITE = "\033[97m"
    BLACK = "\033[30m"
    BLUE = "\033[94m"

    # Background colors. 8-color codes for portability; ORANGE uses a
    # 256-color slot since there's no good 8-color equivalent.
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_ORANGE = "\033[48;5;208m"
    BG_CYAN = "\033[46m"
    BG_GRAY = "\033[100m"


# Severity -> ANSI color. Kept here (not in audit.py) so themes are local.
#
# Severity ordering visually:
#   CRITICAL = bright red    (\x1b[91m)
#   HIGH     = normal red    (\x1b[31m, distinct from CRITICAL by brightness)
#   MEDIUM   = orange-yellow (\x1b[33m)
#   LOW      = cyan
#   INFO     = gray
#
# Previously HIGH was bright yellow (\x1b[93m), which on some terminals
# (notably WSL Ubuntu) rendered lighter than MEDIUM's \x1b[33m and made
# MEDIUM look more severe than HIGH. Using a red-family colour for HIGH
# keeps the visual gradient from "most severe" to "least severe"
# consistent across terminal palettes.
SEVERITY_COLOR = {
    "CRITICAL": C.RED,        # bright red
    "HIGH":     "\033[31m",   # normal red
    "MEDIUM":   C.ORANGE,
    "LOW":      C.CYAN,
    "INFO":     C.GRAY,
}

# Backgrounds + matching contrast letter colours for the severity badges.
# CRITICAL keeps the standard red bg; HIGH gets a darker red 256-colour
# slot so the two reds are distinguishable side-by-side. White letters on
# both red shades for contrast.
SEVERITY_BG = {
    "CRITICAL": C.BG_RED,            # \x1b[41m
    "HIGH":     "\033[48;5;124m",    # 256-colour dark red
    "MEDIUM":   C.BG_ORANGE,
    "LOW":      C.BG_CYAN,
    "INFO":     C.BG_GRAY,
}
SEVERITY_FG_ON_BG = {
    "CRITICAL": C.WHITE,
    "HIGH":     C.WHITE,
    "MEDIUM":   C.BLACK,
    "LOW":      C.BLACK,
    "INFO":     C.WHITE,
}


# ---------------------------------------------------------------------------
# Global state (set once at startup via configure()).
# ---------------------------------------------------------------------------

_use_color = True


def configure(*, color: bool = True) -> None:
    """Configure UI globals. Call once near startup, after parsing args."""
    global _use_color
    _use_color = color


def should_use_color(no_color_flag: bool = False) -> bool:
    """Decide whether to emit ANSI codes.

    Honors, in order of precedence:
      - explicit --no-color flag
      - NO_COLOR env var (https://no-color.org)
      - non-TTY stdout (pipes, file redirects, CI logs without a PTY)
    """
    if no_color_flag:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    return True


# ---------------------------------------------------------------------------
# Styling helpers
# ---------------------------------------------------------------------------

def _wrap(text: str, code: str) -> str:
    if not _use_color or not code:
        return text
    return f"{code}{text}{C.RESET}"


def bold(text: str) -> str:
    return _wrap(text, C.BOLD)


def dim(text: str) -> str:
    return _wrap(text, C.DIM)


def underline(text: str) -> str:
    return _wrap(text, C.UNDERLINE)


def green(text: str) -> str:
    return _wrap(text, C.GREEN)


def red(text: str) -> str:
    return _wrap(text, C.RED)


def cyan(text: str) -> str:
    return _wrap(text, C.CYAN)


def blue(text: str) -> str:
    return _wrap(text, C.BLUE)


def dim_cyan(text: str) -> str:
    """Cyan + dim chained. Used for file paths in the right metadata so
    the path is visually quiet but still distinct from the title text."""
    if not _use_color or not text:
        return text
    return f"{C.DIM}{C.CYAN}{text}{C.RESET}"


def link_style(text: str) -> str:
    """Bright blue + underline - the conventional 'hyperlink' look. Used
    for the CWE label so users recognise it as something they can click."""
    if not _use_color or not text:
        return text
    return f"{C.BLUE}{C.UNDERLINE}{text}{C.RESET}"


def severity_color(text: str, severity: str) -> str:
    """Wrap text in the color associated with a severity level."""
    return _wrap(text, SEVERITY_COLOR.get(severity.upper(), ""))


def severity_badge(severity: str, letter: str) -> str:
    """A 3-visible-char badge: space + letter + space, painted with the
    severity background and a contrasting letter color.

    Looks like a tag/badge in a CI status pane. Falls back to plain
    ``[L]`` brackets when colors are off so the cue is still readable.
    """
    sev_u = severity.upper()
    if not _use_color:
        return f"[{letter}]"
    bg = SEVERITY_BG.get(sev_u, "")
    fg = SEVERITY_FG_ON_BG.get(sev_u, "")
    return f"{bg}{fg} {letter} {C.RESET}"


def hyperlink(text: str, url: str) -> str:
    """OSC 8 clickable hyperlink.

    Modern terminals (iTerm2, WezTerm, Windows Terminal, recent GNOME
    Terminal, kitty) render ``text`` as a clickable link to ``url``.
    Older terminals just show ``text`` and discard the escape, so we
    don't pollute output with a long URL alongside the label.
    """
    if not _use_color:
        return text
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"


def file_link(rel_path: str, line: Optional[int] = None) -> str:
    """Render a path (with optional :line) as a clickable file:// link.

    Visible text stays ``path`` / ``path:line`` so terminals that drop
    OSC 8 still print a clean string and smart-selection (cmd-click in
    iTerm2 / WezTerm) keeps working on the ``path:line`` pattern.

    The URL appends ``#L<line>`` because some terminals and editors
    interpret it as a line anchor; the rest ignore it harmlessly.
    """
    abs_path = os.path.abspath(rel_path)
    url = f"file://{abs_path}"
    if line is not None:
        url += f"#L{line}"
    display = f"{rel_path}:{line}" if line else rel_path
    return hyperlink(display, url)


# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------

def term_width(default: int = 80) -> int:
    """Detected terminal width, with a sane lower bound."""
    try:
        cols = shutil.get_terminal_size((default, 24)).columns
    except OSError:
        cols = default
    return max(40, cols)


# Strips both SGR (colors) and OSC 8 hyperlink sequences so visible_len()
# returns the rendered width of a styled string for alignment math.
_ANSI_RE = re.compile(r"\033\[[0-9;]*m|\033\]8;;[^\033]*\033\\")


def visible_len(s: str) -> int:
    """Length of a string ignoring ANSI escapes (used for column alignment)."""
    return len(_ANSI_RE.sub("", s))


# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Raw-mode terminal for the interactive review TUI
# ---------------------------------------------------------------------------

class CbreakTerminal:
    """Context manager that puts the terminal into cbreak (single-char) mode
    on the alternate screen buffer.

    - Disables line buffering so ``read_key()`` returns one keystroke at
      a time without waiting for Enter.
    - Switches to the alternate screen buffer (``\\x1b[?1049h``) so the
      TUI's redraws stay out of scrollback history - same trick vim,
      less, htop use. Restores the original buffer on exit.
    - Hides the cursor while we're drawing the TUI and restores it on exit.
    - Always restores the previous tty state, even on exception (TUIs that
      crash without restoring leave the user's terminal unusable).

    Unix-only. ``available`` is False on Windows; callers should fall back
    to a non-interactive flow in that case.
    """

    available = os.name == "posix"

    def __enter__(self) -> "CbreakTerminal":
        if not self.available:
            raise RuntimeError("Raw terminal mode is not supported on this OS.")
        # Imported lazily so the module still loads on Windows.
        import termios
        import tty
        self._termios = termios
        self._fd = sys.stdin.fileno()
        self._old = termios.tcgetattr(self._fd)
        tty.setcbreak(self._fd)
        # Enter alternate screen buffer + hide cursor. The order matters:
        # switch buffers FIRST so the cursor-hide doesn't affect the
        # caller's original screen state.
        sys.stdout.write("\x1b[?1049h\x1b[?25l")
        sys.stdout.flush()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        try:
            self._termios.tcsetattr(self._fd, self._termios.TCSADRAIN, self._old)
        finally:
            # Show cursor + leave alternate screen buffer. Inverse order
            # of __enter__ so we don't briefly show the cursor in the alt
            # buffer before the buffer switch.
            sys.stdout.write("\x1b[?25h\x1b[?1049l")
            sys.stdout.flush()


# Arrow keys come in two flavours: CSI (xterm-style, ``ESC [ A``) and SS3
# (vt100-style, ``ESC O A``). The final byte is the same in both; we map
# it to a friendly direction name.
_ARROW_FINAL = {"A": "up", "B": "down", "C": "right", "D": "left"}

# Timeout for waiting on follow-up bytes after ESC. WSL2 / SSH / slow
# multiplexers occasionally deliver the three bytes of ``ESC [ A`` with
# small gaps, so this needs to be generous enough not to misread an
# arrow press as a bare ESC keystroke.
_ESC_FOLLOWUP_TIMEOUT = 0.2


def _read_raw(fd: int, n: int = 8) -> str:
    """Read up to ``n`` bytes directly from the OS fd, bypassing Python's
    stdin buffer.

    We use ``os.read`` (not ``sys.stdin.read``) because Python's stdin
    is wrapped in a BufferedReader. When the terminal sends a 3-byte
    sequence like ``ESC [ A``, ``sys.stdin.read(1)`` returns ``ESC`` and
    the remaining ``[ A`` end up in Python's internal buffer.
    ``select.select`` then reports "no data" at the OS level and we
    mistakenly think the ESC was a lone keystroke.
    """
    try:
        return os.read(fd, n).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _wait_more(fd: int, timeout: float) -> bool:
    """True if more data is available on ``fd`` within ``timeout`` seconds."""
    return bool(select.select([fd], [], [], timeout)[0])


def read_key() -> str:
    """Read one keystroke. Returns a friendly name for navigation keys.

    Single-char input returns the literal char (``'a'``, ``' '``, ``'\\r'``).
    Arrow keys are decoded from both CSI (``ESC [ A``) and SS3
    (``ESC O A``) sequences and returned as ``'up'`` / ``'down'`` /
    ``'left'`` / ``'right'``. Plain ESC returns ``'esc'``, Enter returns
    ``'enter'``, Space returns ``'space'``. Ctrl-C raises
    KeyboardInterrupt so callers can quit cleanly.

    Bytes are read with ``os.read`` directly on the file descriptor so
    multi-byte escape sequences arrive in one call regardless of any
    buffering layered on top of ``sys.stdin``.
    """
    fd = sys.stdin.fileno()

    # Reading 8 bytes at once: arrow keys are 3 bytes total, function
    # keys up to ~6, and the terminal delivers the whole sequence in
    # one OS-level packet on every system I've seen.
    data = _read_raw(fd, 8)
    if not data:
        return ""
    c = data[0]
    if c == "\x03":
        raise KeyboardInterrupt
    if c in ("\r", "\n"):
        return "enter"
    if c == " ":
        return "space"
    if c == "\t":
        return "tab"
    if c == "\x7f":
        return "backspace"
    if c != "\x1b":
        return c

    # The lead byte was ESC. Did the terminal deliver the rest in the
    # same packet?
    rest = data[1:]
    if not rest:
        # Lone ESC byte; wait briefly in case the terminal split the
        # sequence into two packets (rare but possible over SSH/WSL).
        if _wait_more(fd, _ESC_FOLLOWUP_TIMEOUT):
            rest = _read_raw(fd, 8)
        if not rest:
            return "esc"

    if rest[0] in ("[", "O") and len(rest) >= 2:
        return _ARROW_FINAL.get(rest[1], f"esc:{rest[:2]}")
    # Alt-<key> style: ESC followed by a printable byte.
    return f"alt:{rest[0]}"


def clear_screen() -> None:
    """Move the cursor to home and clear from there to end-of-screen.

    Used by the TUI between redraws. We home-first / clear-second
    (instead of clear-everything / home-after) so there's no visible
    blank-screen frame between renders - reduces perceived flicker on
    slow terminals.
    """
    sys.stdout.write("\x1b[H\x1b[J")
    sys.stdout.flush()


class Spinner:
    """Threaded spinner shown on stderr while a long-running task runs.

    Use as a context manager:

        with Spinner("Scanning with claude-code"):
            response = query(...)

    Disabled automatically when stderr is not a TTY (so CI logs stay
    clean) or when colors are off. Falls back to a single ``label...``
    line in that case.
    """

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, label: str, enabled: Optional[bool] = None):
        self.label = label
        # Spinner needs a TTY for carriage-return overwriting and colors
        # for the dim elapsed timer; degrade gracefully otherwise.
        if enabled is None:
            enabled = sys.stderr.isatty() and _use_color
        self.enabled = enabled
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._start: Optional[float] = None
        self.elapsed: float = 0.0

    def __enter__(self) -> "Spinner":
        self._start = time.monotonic()
        if not self.enabled:
            sys.stderr.write(f"{self.label}...\n")
            sys.stderr.flush()
            return self
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.elapsed = time.monotonic() - (self._start or time.monotonic())
        if not self.enabled:
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
        # Clear the spinner line and replace with a quiet finished line.
        sys.stderr.write(f"\r\033[K{dim(self.label)}  {dim(f'{self.elapsed:.1f}s')}\n")
        sys.stderr.flush()

    def _spin(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            elapsed = time.monotonic() - (self._start or time.monotonic())
            line = f"\r{frame} {self.label}  {dim(f'{elapsed:.1f}s')}"
            sys.stderr.write(line)
            sys.stderr.flush()
            i += 1
            # 80 ms cadence; using stop.wait() makes us interruptible.
            self._stop.wait(0.08)


