"""Collect the executables configured MCP servers would launch.

Candidates come from the MCP server entries Guard already reads from harness
configs. A bare command such as ``node`` or ``npx`` is resolved through the
search path the server would use (its own configured ``PATH`` when it sets
one, otherwise this process's), so the artifact is the file a launch would
find, not whatever ``node --version`` prints in a login shell. A launcher
script's ``#!`` interpreter is added as a second candidate. Nothing here
starts a process or reads more than a script's first line, and no environment
value leaves this module.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .adapters.mcp_servers import observable_stdio_servers_with_proxy
from .models import HarnessDetection

MAX_RUNTIME_CANDIDATES = 64
_SHEBANG_BYTES = 256
_SHEBANG_NAME_LIMIT = 64


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
    for detection in detections:
        for server in observable_stdio_servers_with_proxy(detection):
            if not server.enabled:
                continue
            search_path = _search_path(server.env, process_environment)
            launch = resolve_launch_executable(server.command, search_path=search_path, workspace_dir=workspace_dir)
            if launch is None:
                unresolved.append(UnresolvedLaunch(server.harness, server.name, Path(server.command).name))
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
    if os.sep in text or (os.altsep is not None and os.altsep in text):
        candidate = Path(text).expanduser()
        if not candidate.is_absolute():
            if workspace_dir is None:
                return None
            candidate = workspace_dir / candidate
        return str(candidate) if candidate.is_file() else None
    return shutil.which(text, path=search_path)


def _search_path(server_env: Mapping[str, str], process_environment: Mapping[str, str]) -> str | None:
    configured = next((value for key, value in server_env.items() if key.upper() == "PATH"), None)
    # An unexpanded ``${PATH}`` placeholder cannot be searched; fall back to the process path.
    if configured and "$" not in configured and "%" not in configured:
        return configured
    return next((value for key, value in process_environment.items() if key.upper() == "PATH"), None)


def _with_interpreter(launch: str, search_path: str | None) -> list[tuple[str, str]]:
    entries = [(launch, "launch")]
    interpreter = _shebang_interpreter(launch, search_path)
    if interpreter is not None and interpreter != launch:
        entries.append((interpreter, "interpreter"))
    return entries


def _shebang_interpreter(path: str, search_path: str | None) -> str | None:
    try:
        with open(path, "rb") as handle:
            head = handle.read(_SHEBANG_BYTES)
    except OSError:
        return None
    if not head.startswith(b"#!"):
        return None
    line = head[2:].split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()
    tokens = line.split()
    if not tokens:
        return None
    program = tokens[0]
    if Path(program).name == "env":
        rest = [token for token in tokens[1:] if not token.startswith("-") and "=" not in token]
        if not rest or len(rest[0]) > _SHEBANG_NAME_LIMIT:
            return None
        return shutil.which(rest[0], path=search_path)
    return program if os.path.isabs(program) and os.path.isfile(program) else None


__all__ = [
    "MAX_RUNTIME_CANDIDATES",
    "RuntimeCandidate",
    "RuntimeCandidates",
    "UnresolvedLaunch",
    "collect_runtime_candidates",
    "resolve_launch_executable",
]
