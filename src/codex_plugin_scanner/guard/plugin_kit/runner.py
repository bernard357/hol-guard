"""Find and start the runtime CLIs an install plan names.

Programs come only from absolute PATH entries, never the current directory.
On POSIX a folder or program every user can write to is skipped, since anyone
could have planted it. On Windows an ``.exe`` wins over a ``.cmd`` or ``.bat``
shim in the same folder, and every argument bound for a shim must stay clear
of cmd.exe's metacharacters, because cmd.exe re-parses it. Children get no
stdin, so a prompt Guard did not expect ends the command instead of hanging.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TextIO

COMMAND_TIMEOUT_SECONDS = 600.0
_WINDOWS_EXTENSIONS = (".exe", ".cmd", ".bat")
_BATCH_EXTENSIONS = (".cmd", ".bat")
_BATCH_UNSAFE = frozenset('%^&|<>"()!')


class RunnerError(RuntimeError):
    """A program could not be started safely, or did not finish."""


@dataclass(frozen=True)
class Program:
    name: str
    #: Absolute path; the plan shows it and the confirmation covers it.
    path: str

    @property
    def batch(self) -> bool:
        return self.path.lower().endswith(_BATCH_EXTENSIONS)


@dataclass
class Lookup:
    programs: dict[str, Program] = field(default_factory=dict)
    #: One line per copy of a program Guard found and would not use.
    ignored: list[str] = field(default_factory=list)


def _world_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWOTH)


def _open_ancestor(found: str) -> str | None:
    """The first folder above ``found``, or above the file it links to, that any
    user can rename entries in. A sticky folder such as /tmp only lets owners
    rename, so it does not count."""

    for start in (found, os.path.realpath(found)):
        folder = os.path.dirname(start)
        while True:
            try:
                mode = os.stat(folder).st_mode
            except OSError:
                break
            if _world_writable(mode) and not mode & stat.S_ISVTX:
                return folder
            parent = os.path.dirname(folder)
            if parent == folder:
                break
            folder = parent
    return None


def _candidate(folder: str, name: str, *, windows: bool) -> str | None:
    if windows:
        for extension in _WINDOWS_EXTENSIONS:
            candidate = os.path.join(folder, name + extension)
            if os.path.isfile(candidate):
                return candidate
        return None
    candidate = os.path.join(folder, name)
    return candidate if os.path.isfile(candidate) and os.access(candidate, os.X_OK) else None


def find_programs(
    names: Iterable[str], environ: Mapping[str, str] | None = None, *, windows: bool | None = None
) -> Lookup:
    """Resolve each name to an absolute path Guard is willing to start."""

    environ = os.environ if environ is None else environ
    windows = os.name == "nt" if windows is None else windows
    separator = ";" if windows else ":"
    names = list(names)
    lookup = Lookup()
    seen: set[str] = set()
    folders: list[str] = []
    for entry in environ.get("PATH", "").split(separator):
        if not entry or entry in seen:
            continue
        seen.add(entry)
        reason = None
        if not os.path.isabs(entry):
            reason = "a relative PATH entry"
        else:
            try:
                info = os.stat(entry)
            except OSError:
                continue
            if not stat.S_ISDIR(info.st_mode):
                continue
            if not windows and _world_writable(info.st_mode):
                reason = "a folder every user can write to"
        if reason is None:
            folders.append(entry)
            continue
        for name in names:
            planted = _candidate(os.path.abspath(entry), name, windows=windows)
            if planted:
                lookup.ignored.append(f"Guard ignored {planted}: it is in {reason}.")
    for name in names:
        for folder in folders:
            found = _candidate(folder, name, windows=windows)
            if found is None:
                continue
            if not windows:
                try:
                    mode = os.stat(found).st_mode
                except OSError:
                    continue
                if _world_writable(mode):
                    lookup.ignored.append(f"Guard ignored {found}: every user can write to it.")
                    continue
                folder_open = _open_ancestor(found)
                if folder_open is not None:
                    lookup.ignored.append(f"Guard ignored {found}: every user can change {folder_open}.")
                    continue
            lookup.programs[name] = Program(name, found)
            break
    return lookup


def check_arguments(program: Program, arguments: Sequence[str]) -> None:
    """Refuse arguments cmd.exe could read as commands when the program is a shim."""

    if not program.batch:
        return
    for argument in arguments:
        if not argument or any(
            character in _BATCH_UNSAFE or character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in argument
        ):
            raise RunnerError(
                f"Guard will not pass {argument!a} to {program.path}: cmd.exe could read it as a command."
            )


@dataclass(frozen=True)
class Completed:
    returncode: int
    stdout: str


def run(
    program: Program,
    arguments: Sequence[str],
    *,
    capture: bool = False,
    echo: TextIO | None = None,
    timeout: float = COMMAND_TIMEOUT_SECONDS,
) -> Completed:
    """Start ``program`` without a shell or stdin.

    ``capture`` returns its stdout instead of showing it. ``echo`` sends it
    to another stream, such as stderr when stdout must stay one JSON document.
    """

    check_arguments(program, arguments)
    piped = capture or echo is not None
    try:
        completed = subprocess.run(
            [program.path, *arguments],
            shell=False,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if piped else None,
            text=True if piped else None,
            errors="replace" if piped else None,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise RunnerError(f"{program.name} did not finish within {timeout:.0f} seconds.") from error
    except OSError as error:
        raise RunnerError(f"{program.path} could not be started.") from error
    output = completed.stdout if isinstance(completed.stdout, str) else ""
    if echo is not None and not capture and output:
        echo.write(output)
        echo.flush()
    return Completed(completed.returncode, output)


def stdin_is_terminal() -> bool:
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False
