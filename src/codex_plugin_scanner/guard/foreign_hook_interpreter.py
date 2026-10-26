"""Find Guard-owned hook artifacts that launch another Guard install's Python."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path, PureWindowsPath

# A source install runs every hook client isolated: ``<python> -I -s <worker>``,
# ``<python> -I -s -m codex_plugin_scanner.cli`` or ``<python> -I -c <bootstrap>``.
# The flag after ``-I`` separates those from the stdlib-only ``<python> -I <script>``
# clients, which do not depend on which Guard install owns the interpreter. The
# separators cover a shell word, a JSON or Python argv, and a JSON-escaped argv.
_ISOLATED_CLIENT = re.compile(r"(?<![^\s'\",\[])-I[\s'\",\\]+-[scm](?![\w-])")
_INTERPRETER_BEFORE = re.compile(
    r"(?:'(?P<single>[^'\r\n]+)'|\"(?P<double>[^\"\r\n]+)\"|(?<![^\s'\",\[=])(?P<bare>[^\s'\",\[=]+))[\s'\",\\]*\Z"
)
# The PowerShell form of the Cline launcher names the interpreter and worker
# on consecutive lines instead of one command.
_POWERSHELL_LAUNCHER = re.compile(
    r"^\$Python = '(?P<python>(?:[^'\r\n]|'')+)'\r?\n\$Worker = '(?P<worker>(?:[^'\r\n]|'')+)'",
    re.MULTILINE,
)
# Guard's launchers and hook configs are a few kilobytes. A manifest path that
# names a far larger file is not one of them; read no more than this prefix.
_SCAN_MAX_BYTES = 2 * 1024 * 1024
_BINARY_SNIFF_BYTES = 8192
_LOOKBEHIND_CHARS = 2048
_LOOKAHEAD_CHARS = 1024


def current_guard_python() -> str | None:
    """The interpreter this process bakes into hook artifacts, or None when frozen.

    A frozen Guard has no Python install of its own, so every launcher that
    runs the Guard package through an interpreter belongs to another install.
    """

    if bool(getattr(sys, "frozen", False)):
        return None
    return str(Path(sys.executable).absolute())


def _posix(value: str) -> str:
    return value.replace("\\\\", "/").replace("\\", "/")


def _is_absolute(value: str) -> bool:
    return Path(value).is_absolute() or PureWindowsPath(value).is_absolute()


def _is_other_interpreter(candidate: str, current: str | None) -> bool:
    if not _is_absolute(candidate):
        # Not an interpreter path: a word that merely sat before a flag.
        return False
    return current is None or os.path.normcase(candidate) != os.path.normcase(current)


def _names_guard_client(ahead: str, guard_home: str) -> bool:
    return "codex_plugin_scanner" in ahead or guard_home in ahead


def names_foreign_interpreter(path: Path, *, current: str | None, guard_home: Path) -> bool:
    """Whether one Guard-owned artifact launches an interpreter other than ``current``.

    Only an invocation of Guard's own client counts: one that imports the
    package, or runs a worker under the Guard home. A user hook that happens
    to run ``python -I`` is left alone.
    """

    try:
        with path.open("rb") as handle:
            data = handle.read(_SCAN_MAX_BYTES)
    except (OSError, ValueError):
        return False
    if b"\0" in data[:_BINARY_SNIFF_BYTES]:
        return False
    text = data.decode("utf-8", errors="replace")
    home = _posix(str(guard_home))
    for match in _ISOLATED_CLIENT.finditer(text):
        before = text[max(0, match.start() - _LOOKBEHIND_CHARS) : match.start()]
        interpreter = _INTERPRETER_BEFORE.search(before)
        if interpreter is None:
            continue
        found = interpreter.group("single") or interpreter.group("double") or interpreter.group("bare")
        # A JSON-escaped argv leaves the closing quote's backslash on the path
        # and doubles every separator in a Windows one.
        candidate = found.rstrip("\\").replace("\\\\", "\\")
        ahead = _posix(text[match.end() : match.end() + _LOOKAHEAD_CHARS])
        if _names_guard_client(ahead, home) and _is_other_interpreter(candidate, current):
            return True
    for launcher in _POWERSHELL_LAUNCHER.finditer(text):
        worker = _posix(launcher.group("worker").replace("''", "'"))
        if worker.startswith(home) and _is_other_interpreter(launcher.group("python").replace("''", "'"), current):
            return True
    return False


__all__ = ["current_guard_python", "names_foreign_interpreter"]
