"""Ask the native runtime to check the MCP servers a worktree configures.

Guard's harness adapters already read every MCP configuration an agent would
load. This module keeps the servers whose configuration file sits inside the
worktree, so a server from the user's home or a global configuration never
becomes a finding about the repository. Each server's launch command,
arguments and URL go to the runtime over stdin; its environment, headers and
any other setting stay behind. The runtime reads no files and starts nothing.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final

from .models import HarnessDetection

MCP_CONFIG_COMMAND: Final = "mcp-config-assess"
MCP_CONFIG_FEATURE: Final = "mcp-config-assess-v1"
_REQUEST_SCHEMA: Final = "guard.workspace-mcp-config-request.v1"
_TIMEOUT_SECONDS: Final = 30.0
_OUTPUT_LIMIT_BYTES: Final = 1024 * 1024
_CHILD_ENVIRONMENT_KEYS: Final = ("SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP")


class McpConfigUnavailableError(RuntimeError):
    """The runtime has no MCP configuration check."""


@dataclass(frozen=True, slots=True)
class WorkspaceServers:
    """The worktree's configured servers and the harnesses Guard could not read."""

    servers: tuple[dict[str, object], ...]
    skipped_harnesses: tuple[str, ...]


def workspace_mcp_servers(store: Any, root: Path, *, home_dir: Path | None = None) -> WorkspaceServers:
    """The MCP servers configured by files inside ``root``."""

    from .adapters.harness_mcp_discovery import configured_harness_detections

    skipped: list[str] = []
    detections = configured_harness_detections(
        home_dir if home_dir is not None else Path.home(), Path(store.guard_home), root, skipped=skipped
    )
    return WorkspaceServers(servers=servers_in_root(detections, root), skipped_harnesses=tuple(sorted(set(skipped))))


def servers_in_root(detections: Sequence[HarnessDetection], root: Path) -> tuple[dict[str, object], ...]:
    """One request row per MCP server whose configuration file is inside ``root``."""

    servers: dict[tuple[str, str], dict[str, object]] = {}
    for detection in detections:
        for artifact in detection.artifacts:
            if artifact.artifact_type != "mcp_server":
                continue
            path = _root_relative(artifact.config_path, root)
            if path is None:
                continue
            servers.setdefault(
                (path, artifact.name),
                {
                    "path": path,
                    "server": artifact.name,
                    "command": artifact.command,
                    "args": list(artifact.args),
                    "url": artifact.url,
                },
            )
    return tuple(servers[key] for key in sorted(servers))


def _root_relative(config_path: str, root: Path) -> str | None:
    """The configuration file's path below ``root``, or ``None`` outside it.

    Compared without following links, so a linked configuration is named
    where the worktree keeps it.
    """

    candidate = Path(os.path.normpath(config_path))
    if not candidate.is_absolute():
        return None
    for base in dict.fromkeys((Path(os.path.normpath(root)), root.resolve())):
        try:
            relative = candidate.relative_to(base)
        except ValueError:
            continue
        posix = PurePosixPath(*relative.parts)
        return str(posix) if relative.parts else None
    return None


def assess_mcp_servers(servers: Sequence[dict[str, object]]) -> dict[str, object]:
    """The runtime's result for ``servers``.

    Raises :class:`McpConfigUnavailableError` when the runtime lacks the check and
    ``RuntimeError`` when it could not answer.
    """

    from .codex_hook_launch_runtime import run_isolated_hook_process
    from .native_runtime import native_runtime_status

    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or MCP_CONFIG_FEATURE not in status.capabilities.features
    ):
        raise McpConfigUnavailableError("mcp_config_unavailable")
    runtime = status.identity.path
    completed = run_isolated_hook_process(
        (str(runtime), MCP_CONFIG_COMMAND, "--stdin"),
        input_text=json.dumps({"schema": _REQUEST_SCHEMA, "servers": list(servers)}, separators=(",", ":")),
        cwd=runtime.parent,
        environment={key: value for key in _CHILD_ENVIRONMENT_KEYS if (value := os.environ.get(key))},
        timeout_seconds=_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    if (
        completed.returncode != 0
        or completed.timed_out
        or completed.output_limit_exceeded
        or completed.containment_failed
    ):
        raise RuntimeError("mcp_config_failed")
    try:
        reply = json.loads(completed.stdout)
    except ValueError as error:
        raise RuntimeError("mcp_config_failed") from error
    if not isinstance(reply, dict) or reply.get("ok") is not True or not isinstance(reply.get("result"), dict):
        raise RuntimeError("mcp_config_failed")
    return reply["result"]


__all__ = [
    "MCP_CONFIG_FEATURE",
    "McpConfigUnavailableError",
    "WorkspaceServers",
    "assess_mcp_servers",
    "servers_in_root",
    "workspace_mcp_servers",
]
