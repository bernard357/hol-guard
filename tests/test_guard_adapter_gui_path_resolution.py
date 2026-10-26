"""Command lookup when Guard runs with the bare PATH a GUI launcher provides."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import _command_available, _resolve_command

pytestmark = pytest.mark.skipif(os.name == "nt", reason="launchd and desktop PATH defaults are POSIX-only")

LAUNCHD_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def _install(directory: Path, name: str, *, mode: int = 0o755) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o755)
    executable = directory / name
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(mode)
    return executable


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    return home_dir


def test_launchd_path_finds_cli_in_user_install_directory(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = _install(home / ".bun" / "bin", "guardtestcli")
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _command_available("guardtestcli") is True
    assert _resolve_command("guardtestcli") == str(executable)


def test_launchd_path_finds_cli_in_its_own_installer_directory(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = _install(home / ".guardtestcli" / "bin", "guardtestcli")
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _resolve_command("guardtestcli") == str(executable)


def test_launchd_path_prefers_newest_nvm_node(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    versions = home / ".nvm" / "versions" / "node"
    _install(versions / "v9.11.2" / "bin", "guardtestcli")
    newest = _install(versions / "v25.2.1" / "bin", "guardtestcli")
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _resolve_command("guardtestcli") == str(newest)


def test_terminal_path_is_not_widened(home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install(home / ".bun" / "bin", "guardtestcli")
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", f"{empty}{os.pathsep}{LAUNCHD_PATH}")

    assert _command_available("guardtestcli") is False
    assert _resolve_command("guardtestcli") is None


def test_writable_install_directory_is_ignored(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = _install(home / ".bun" / "bin", "guardtestcli")
    executable.parent.chmod(executable.parent.stat().st_mode | stat.S_IWOTH)
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _command_available("guardtestcli") is False


def test_non_executable_file_is_ignored(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install(home / ".local" / "bin", "guardtestcli", mode=0o644)
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _command_available("guardtestcli") is False


def test_world_writable_entrypoint_in_private_directory_is_found(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = _install(home / ".bun" / "bin", "guardtestcli", mode=0o777)
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _resolve_command("guardtestcli") == str(executable)
