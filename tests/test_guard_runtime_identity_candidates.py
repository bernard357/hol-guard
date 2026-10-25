"""Launch-executable candidates for configured MCP servers.

Resolution must follow the search path a server would launch with, never the
ambient default, and must never start a process.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime_identity_candidates import (
    collect_runtime_candidates,
    resolve_launch_executable,
)

# Server discovery projects each entry's identity through the compiled runtime.
pytestmark = pytest.mark.usefixtures("native_hook_force")


def _executable(path: Path, body: str = "binary-not-a-script\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _server(
    name: str,
    command: str | None,
    *,
    env: dict[str, str] | None = None,
    enabled: bool = True,
    harness: str = "claude-code",
) -> GuardArtifact:
    metadata: dict[str, object] = {"env": env or {}}
    if not enabled:
        metadata["enabled"] = False
    return GuardArtifact(
        artifact_id=f"{harness}:{name}",
        name=name,
        harness=harness,
        artifact_type="mcp_server",
        source_scope="project",
        config_path="config.json",
        command=command,
        args=("--serve",),
        transport="stdio",
        metadata=metadata,
    )


def _detection(*artifacts: GuardArtifact, harness: str = "claude-code") -> HarnessDetection:
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=True,
        config_paths=("config.json",),
        artifacts=tuple(artifacts),
    )


def test_bare_command_resolves_through_the_given_path_to_the_real_file(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    node = _executable(bin_dir / "node")
    decoy = _executable(tmp_path / "other" / "node")

    found = collect_runtime_candidates(
        [_detection(_server("files", "node"))],
        environment={"PATH": str(bin_dir)},
    )

    assert [candidate.path for candidate in found.candidates] == [str(node)]
    assert str(decoy) not in {candidate.path for candidate in found.candidates}
    assert found.candidates[0].sources == (("claude-code", "files", "launch"),)
    assert found.unresolved == ()
    assert not found.truncated


def test_server_configured_path_wins_over_the_process_path(tmp_path: Path) -> None:
    process_node = _executable(tmp_path / "process" / "node")
    server_node = _executable(tmp_path / "server" / "node")

    found = collect_runtime_candidates(
        [_detection(_server("files", "node", env={"PATH": str(tmp_path / "server")}))],
        environment={"PATH": str(tmp_path / "process")},
    )

    assert [candidate.path for candidate in found.candidates] == [str(server_node)]
    assert str(process_node) not in {candidate.path for candidate in found.candidates}


def test_unexpanded_path_placeholder_falls_back_to_the_process_path(tmp_path: Path) -> None:
    node = _executable(tmp_path / "process" / "node")

    found = collect_runtime_candidates(
        [_detection(_server("files", "node", env={"PATH": "${PATH}:/opt/extra"}))],
        environment={"PATH": str(tmp_path / "process")},
    )

    assert [candidate.path for candidate in found.candidates] == [str(node)]


def test_launcher_script_adds_its_shebang_interpreter(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    interpreter = _executable(bin_dir / "python3")
    launcher = _executable(bin_dir / "serve", "#!/usr/bin/env python3\nprint('x')\n")

    found = collect_runtime_candidates(
        [_detection(_server("api", "serve"))],
        environment={"PATH": str(bin_dir)},
    )

    roles = {candidate.path: candidate.sources[0][2] for candidate in found.candidates}
    assert roles == {str(launcher): "launch", str(interpreter): "interpreter"}


def test_absolute_and_workspace_relative_commands(tmp_path: Path) -> None:
    absolute = _executable(tmp_path / "abs" / "runner")
    local = _executable(tmp_path / "workspace" / "tools" / "serve")

    assert resolve_launch_executable(str(absolute), search_path=None) == str(absolute)
    assert resolve_launch_executable("./tools/serve", search_path=None, workspace_dir=tmp_path / "workspace") == str(
        local
    )
    assert resolve_launch_executable("./tools/serve", search_path=None) is None
    assert resolve_launch_executable("   ", search_path=os.defpath) is None


def test_missing_commands_are_reported_without_a_path(tmp_path: Path) -> None:
    found = collect_runtime_candidates(
        [_detection(_server("ghost", "no-such-tool"), _server("shared", None))],
        environment={"PATH": str(tmp_path)},
    )

    assert found.candidates == ()
    assert [(item.server, item.command) for item in found.unresolved] == [("ghost", "no-such-tool")]


def test_disabled_servers_are_skipped(tmp_path: Path) -> None:
    _executable(tmp_path / "bin" / "node")

    found = collect_runtime_candidates(
        [_detection(_server("off", "node", enabled=False))],
        environment={"PATH": str(tmp_path / "bin")},
    )

    assert found.candidates == ()
    assert found.unresolved == ()


def test_servers_sharing_an_executable_share_one_candidate(tmp_path: Path) -> None:
    node = _executable(tmp_path / "bin" / "node")

    found = collect_runtime_candidates(
        [
            _detection(_server("one", "node"), _server("two", "node")),
            _detection(_server("three", "node", harness="cursor"), harness="cursor"),
        ],
        environment={"PATH": str(tmp_path / "bin")},
    )

    assert len(found.candidates) == 1
    assert found.candidates[0].path == str(node)
    assert {source[:2] for source in found.candidates[0].sources} == {
        ("claude-code", "one"),
        ("claude-code", "two"),
        ("cursor", "three"),
    }


def test_candidate_count_is_capped_and_reported(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    artifacts = []
    for index in range(5):
        _executable(bin_dir / f"tool{index}")
        artifacts.append(_server(f"s{index}", f"tool{index}"))

    found = collect_runtime_candidates([_detection(*artifacts)], environment={"PATH": str(bin_dir)}, limit=3)

    assert len(found.candidates) == 3
    assert found.truncated


def test_collecting_candidates_never_runs_the_executable(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    _executable(tmp_path / "bin" / "node", f"#!/bin/sh\ntouch {marker}\n")

    collect_runtime_candidates(
        [_detection(_server("files", "node"))],
        environment={"PATH": str(tmp_path / "bin")},
    )

    assert not marker.exists()
