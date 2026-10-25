"""Collect the executables configured MCP servers would launch.

Candidates come from the MCP server entries Guard already reads from harness
configs. A bare command such as ``node`` or ``npx`` is resolved through the
search path the server would use (its own configured ``PATH`` when it sets
one, otherwise this process's), so the artifact is the file a launch would
find, not whatever ``node --version`` prints in a login shell. Relative
commands and relative search path entries resolve against the launch
directory, the workspace or else this process's working directory. A launcher
script's ``#!`` interpreter is added as a second candidate. Nothing here
starts a process or reads more than a script's first line, and no environment
value leaves this module.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .adapters.mcp_servers import observable_stdio_servers_with_proxy
from .models import HarnessDetection

MAX_RUNTIME_CANDIDATES = 64
_SHEBANG_BYTES = 256
_SHEBANG_NAME_LIMIT = 64
_PLACEHOLDER = re.compile(r"\$\{(\w+)\}|\$(\w+)|%(\w+)%")
# ``env`` options that take no value, and the ones whose value is the next token.
_ENV_FLAGS = frozenset({"-i", "-", "-0", "-v", "-S", "--ignore-environment", "--null", "--debug", "--split-string"})
_ENV_VALUE_OPTIONS = frozenset({"-u", "-C", "-P", "--unset", "--chdir"})


@dataclass(frozen=True)
class RuntimeCandidate:
    """One executable path and the configured servers that launch it."""

    path: str
    sources: tuple[tuple[str, str, str], ...]  # (harness, server name, role)


@dataclass(frozen=True)
class UnresolvedLaunch:
    """A configured command no search path resolved to an executable."""

    harness: str
    server: str
    command: str
    lookup: str  # "search_path" for a bare command, "configured_path" for an explicit path


@dataclass(frozen=True)
class RuntimeCandidates:
    candidates: tuple[RuntimeCandidate, ...]
    unresolved: tuple[UnresolvedLaunch, ...]
    truncated: bool


def collect_runtime_candidates(
    detections: Sequence[HarnessDetection],
    *,
    environment: Mapping[str, str] | None = None,
    workspace_dir: Path | None = None,
    limit: int = MAX_RUNTIME_CANDIDATES,
) -> RuntimeCandidates:
    """Resolve every enabled stdio MCP server's launch executable."""

    process_environment = os.environ if environment is None else environment
    found: dict[str, list[tuple[str, str, str]]] = {}
    unresolved: list[UnresolvedLaunch] = []
    truncated = False
    launch_dir = _launch_dir(workspace_dir)
    for detection in detections:
        for server in observable_stdio_servers_with_proxy(detection):
            if not server.enabled:
                continue
            search_path = _anchor_search_path(_search_path(server.env, process_environment), launch_dir)
            launch = resolve_launch_executable(server.command, search_path=search_path, workspace_dir=launch_dir)
            if launch is None:
                text = server.command.strip()
                lookup = "configured_path" if _is_explicit_path(text) else "search_path"
                unresolved.append(UnresolvedLaunch(server.harness, server.name, text, lookup))
                continue
            for path, role in _with_interpreter(launch, search_path):
                if path not in found and len(found) >= limit:
                    truncated = True
                    continue
                found.setdefault(path, []).append((server.harness, server.name, role))
    candidates = tuple(
        RuntimeCandidate(path=path, sources=tuple(dict.fromkeys(sources))) for path, sources in sorted(found.items())
    )
    return RuntimeCandidates(candidates=candidates, unresolved=tuple(unresolved), truncated=truncated)


def resolve_launch_executable(
    command: str, *, search_path: str | None, workspace_dir: Path | None = None
) -> str | None:
    """The file a launch of ``command`` would execute, or ``None`` when no search finds one."""

    text = command.strip()
    if not text:
        return None
    launch_dir = _launch_dir(workspace_dir)
    if _is_explicit_path(text):
        candidate = Path(text).expanduser()
        if not candidate.is_absolute():
            candidate = launch_dir / candidate
        return str(candidate) if candidate.is_file() else None
    return _which(text, _anchor_search_path(search_path, launch_dir))


def _is_explicit_path(command: str) -> bool:
    return os.sep in command or (os.altsep is not None and os.altsep in command)


def _launch_dir(workspace_dir: Path | None) -> Path:
    # A launch runs in the workspace, or in this process's directory without one.
    return Path(os.path.abspath(workspace_dir if workspace_dir is not None else Path.cwd()))


def _which(name: str, search_path: str | None) -> str | None:
    """An absolute regular file ``name`` resolves to; a FIFO or device is never a runtime."""

    found = shutil.which(name, path=search_path)
    return found if found is not None and os.path.isabs(found) and Path(found).is_file() else None


def _anchor_search_path(search_path: str | None, launch_dir: Path) -> str | None:
    """Make relative (and empty) search entries absolute against the launch directory."""

    if not search_path:
        return search_path
    entries = (
        entry if os.path.isabs(entry) else os.path.join(launch_dir, entry) for entry in search_path.split(os.pathsep)
    )
    return os.pathsep.join(entries)


def _search_path(server_env: Mapping[str, str], process_environment: Mapping[str, str]) -> str | None:
    configured = next((value for key, value in server_env.items() if key.upper() == "PATH"), None)
    if configured:
        return _expand_placeholders(configured, process_environment)
    return next((value for key, value in process_environment.items() if key.upper() == "PATH"), None)


def _expand_placeholders(value: str, environment: Mapping[str, str]) -> str:
    """Expand ``$NAME``, ``${NAME}`` and ``%NAME%`` the way a harness does before launch.

    A server that prepends to ``${PATH}`` keeps its own directories first. A
    variable this process does not have cannot be interpreted faithfully, so the
    search path becomes empty and the launch is reported unresolved.
    """

    unknown = False

    def swap(match: re.Match[str]) -> str:
        nonlocal unknown
        name = next(group for group in match.groups() if group)
        found = environment.get(name)
        if found is None:
            found = next((v for key, v in environment.items() if key.upper() == name.upper()), None)
        if found is None:
            unknown = True
            return match.group(0)
        return found

    expanded = _PLACEHOLDER.sub(swap, value)
    return "" if unknown else expanded


def _with_interpreter(launch: str, search_path: str | None) -> list[tuple[str, str]]:
    entries = [(launch, "launch")]
    interpreter = _shebang_interpreter(launch, search_path)
    if interpreter is not None and interpreter != launch:
        entries.append((interpreter, "interpreter"))
    return entries


def _read_head(path: str) -> bytes | None:
    """The first bytes of a regular file; a FIFO or device is never opened blocking or read."""

    if not Path(path).is_file():
        return None
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        # The path may have been swapped after the check above; judge the opened file.
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None
        return os.read(descriptor, _SHEBANG_BYTES)
    except OSError:
        return None
    finally:
        os.close(descriptor)


def _env_command(tokens: list[str]) -> str | None:
    """The program an ``env`` shebang launches, or ``None`` when the options are not understood."""

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            break
        if token in _ENV_VALUE_OPTIONS:
            index += 2
        elif token in _ENV_FLAGS or (token.startswith("--") and "=" in token) or token[:2] in {"-u", "-C", "-P"}:
            index += 1
        elif token.startswith("-"):
            return None
        elif "=" in token:
            index += 1
        else:
            break
    program = tokens[index] if index < len(tokens) else None
    if program is None or len(program) > _SHEBANG_NAME_LIMIT or program[0] in "'\"":
        return None
    return program


def _shebang_interpreter(path: str, search_path: str | None) -> str | None:
    head = _read_head(path)
    if head is None or not head.startswith(b"#!"):
        return None
    line = head[2:].split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()
    tokens = line.split()
    if not tokens:
        return None
    program = tokens[0]
    if Path(program).name == "env":
        name = _env_command(tokens[1:])
        return _which(name, search_path) if name is not None else None
    return program if os.path.isabs(program) and os.path.isfile(program) else None


__all__ = [
    "MAX_RUNTIME_CANDIDATES",
    "RuntimeCandidate",
    "RuntimeCandidates",
    "UnresolvedLaunch",
    "collect_runtime_candidates",
    "resolve_launch_executable",
]
