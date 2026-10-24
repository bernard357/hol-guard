"""End-to-end coverage for ``hol-guard plugin`` through the native runtime.

Detection, checks and emitter output are pinned by the Rust golden fixtures in
``rust/crates/guard-plugin-kit/tests/fixtures``; these tests cover the
argument handling, rendering and exit codes of the Python shim.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner import cli as guard_cli
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.plugin_kit import cli as plugin_kit_cli


def _run(argv: list[str]) -> tuple[int, str, str]:
    output = io.StringIO()
    error = io.StringIO()
    original_argv = guard_cli.sys.argv
    try:
        guard_cli.sys.argv = ["hol-guard"]
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            exit_code = guard_cli.main(argv)
    finally:
        guard_cli.sys.argv = original_argv
    return exit_code, output.getvalue(), error.getvalue()


def _write_plugin(root: Path) -> None:
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(
        json.dumps(
            {
                "name": "notes-kit",
                "version": "1.0.0",
                "description": "Search and edit notes.",
                "license": "MIT",
                "repository": "https://github.com/acme/notes-kit",
            }
        ),
        encoding="utf-8",
    )
    (root / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"notes": {"command": "npx", "args": ["-y", "@acme/notes-mcp"]}}}),
        encoding="utf-8",
    )
    skill = root / "skills" / "notes"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: notes\ndescription: Use when the user asks about their notes.\n---\nBody.\n",
        encoding="utf-8",
    )


def test_check_reports_runtimes_and_passes(tmp_path: Path) -> None:
    _write_plugin(tmp_path)
    exit_code, output, error = _run(["plugin", "check", str(tmp_path), "--json"])
    assert (exit_code, error) == (0, "")
    payload = json.loads(output)
    assert payload["passed"] is True
    supported = [item["runtime"] for item in payload["runtimes"] if item["supported"]]
    assert {"claude-code", "codex", "cursor", "vscode", "opencode", "agent-skills"} <= set(supported)


def test_check_fails_with_exit_one_and_names_the_problem(tmp_path: Path) -> None:
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text('{"name": "Bad Name"}', encoding="utf-8")
    exit_code, output, _error = _run(["plugin", "check", str(tmp_path)])
    assert exit_code == 1
    assert "name_not_kebab" in output
    assert "description_missing" in output
    assert "Check failed" in output


def test_package_writes_each_runtime_then_refuses_to_overwrite(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_plugin(source)
    out = tmp_path / "out"
    exit_code, output, error = _run(["plugin", "package", str(source), "--out", str(out)])
    assert (exit_code, error) == (0, ""), output
    assert (out / "codex" / ".codex-plugin" / "plugin.json").is_file()
    assert (out / "cursor" / ".cursor" / "mcp.json").is_file()
    assert (out / "hol.provenance.json").is_file()
    exit_code, _output, error = _run(["plugin", "package", str(source), "--out", str(out)])
    assert exit_code == 2
    assert "--force" in error


def test_package_limits_to_requested_runtimes_and_rejects_unknown(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_plugin(source)
    out = tmp_path / "out"
    exit_code, _output, _error = _run(
        ["plugin", "package", str(source), "--out", str(out), "--runtimes", "codex,vscode"]
    )
    assert exit_code == 0
    assert sorted(path.name for path in out.iterdir()) == ["codex", "hol.provenance.json", "vscode"]
    exit_code, _output, error = _run(["plugin", "package", str(source), "--runtimes", "windsurf"])
    assert exit_code == 2
    assert "Unknown runtime" in error


def test_init_scaffolds_then_links_print_install_commands(tmp_path: Path) -> None:
    exit_code, output, error = _run(["plugin", "init", str(tmp_path), "--name", "hello-kit"])
    assert (exit_code, error) == (0, "")
    assert "skills/hello-kit/SKILL.md" in output
    exit_code, _output, error = _run(["plugin", "init", str(tmp_path), "--name", "hello-kit"])
    assert exit_code == 2
    assert "never overwrites" in error

    _write_plugin(tmp_path / "published")
    exit_code, output, _error = _run(["plugin", "links", str(tmp_path / "published")])
    assert exit_code == 0
    assert "npx skills add acme/notes-kit" in output
    assert "https://hol.org/plugins/connect?repo=acme/notes-kit" in output


def test_plugin_fails_closed_without_native_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unavailable = SimpleNamespace(available=False, compatible=False, identity=None, capabilities=None)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **_kwargs: unavailable)
    exit_code, output, error = _run(["plugin", "check", str(tmp_path)])
    assert (exit_code, output) == (2, "")
    assert "requires the Guard native runtime" in error


def test_unknown_native_errors_are_printed_as_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(plugin_kit_cli, "_native_request", lambda _request: {"ok": False, "error": "new_code"})
    exit_code, _output, error = _run(["plugin", "links"])
    assert exit_code == 2
    assert "new_code" in error
