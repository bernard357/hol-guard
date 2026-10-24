"""``hol-guard telemetry plugins``: consent, the device key and the weekly report.

Counts are opt-in, so the regression cases here pin that nothing is fetched
or sent before ``on``, that a report names only public HOL listings, and that
it carries nothing that identifies the machine.
"""

from __future__ import annotations

import contextlib
import io
import json
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner import cli as guard_cli
from codex_plugin_scanner.guard import config as guard_config
from codex_plugin_scanner.guard.plugin_telemetry import cli as telemetry_cli
from codex_plugin_scanner.guard.plugin_telemetry import report as telemetry_report
from codex_plugin_scanner.guard.plugin_telemetry.state import SECRET_FILE, read_state

INDEX = [
    {"slug": "acme/notes-kit", "repository": "https://github.com/acme/notes-kit"},
    {"slug": "acme/other", "repository": "https://github.com/acme/other"},
]


@pytest.fixture
def guard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "guard-home"
    monkeypatch.setattr(guard_config, "resolve_guard_home", lambda override=None: home)
    monkeypatch.setattr(telemetry_cli, "resolve_guard_home", lambda override=None: home)
    return home


@pytest.fixture
def user_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "user"
    listed = home / ".claude" / "plugins" / "cache" / "acme" / "notes-kit" / "1.2.0" / ".claude-plugin"
    listed.mkdir(parents=True)
    (listed / "plugin.json").write_text(
        json.dumps({"name": "notes-kit", "version": "1.2.0", "repository": "https://github.com/acme/notes-kit.git"}),
        encoding="utf-8",
    )
    private = home / ".claude" / "plugins" / "cache" / "corp" / "internal-tool" / "0.1.0" / ".claude-plugin"
    private.mkdir(parents=True)
    (private / "plugin.json").write_text(
        json.dumps(
            {"name": "internal-tool", "version": "0.1.0", "repository": "https://github.com/corp/internal-tool"}
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setattr(telemetry_report.Path, "home", staticmethod(lambda: home))
    return home


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


def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("telemetry reached the network")

    monkeypatch.setattr(telemetry_report, "fetch_index", refuse)
    monkeypatch.setattr(telemetry_report, "post_report", refuse)


def test_counts_are_off_until_turned_on_and_nothing_is_sent(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _no_network(monkeypatch)
    exit_code, output, _error = _run(["telemetry", "plugins", "status"])
    assert exit_code == 0
    assert "off" in output
    assert telemetry_report.send_if_due(guard_home) is None
    exit_code, _output, error = _run(["telemetry", "plugins", "send"])
    assert exit_code == 2
    assert "telemetry plugins on" in error
    assert not (guard_home / SECRET_FILE).exists()


def test_on_creates_an_owner_only_key_and_off_deletes_it(guard_home: Path) -> None:
    exit_code, output, _error = _run(["telemetry", "plugins", "on"])
    assert exit_code == 0
    assert "never leave the machine" in output
    secret = guard_home / SECRET_FILE
    assert secret.is_file()
    if sys.platform != "win32":
        assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    assert read_state(guard_home).enabled
    exit_code, _output, _error = _run(["telemetry", "plugins", "off"])
    assert exit_code == 0
    assert not secret.exists()
    assert not read_state(guard_home).enabled


def test_report_names_only_listed_plugins_and_nothing_about_the_machine(
    guard_home: Path, user_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(telemetry_report, "fetch_index", lambda: INDEX)
    sent: list[dict[str, object]] = []
    monkeypatch.setattr(telemetry_report, "post_report", lambda report: sent.append(dict(report)) or 1)
    assert _run(["telemetry", "plugins", "on"])[0] == 0

    now = datetime(2026, 10, 21, tzinfo=timezone.utc)
    result = telemetry_report.send_if_due(guard_home, now=now)
    assert result is not None
    assert (result["week"], result["installed"], result["listed"]) == ("2026-W43", 2, 1)
    assert telemetry_report.send_if_due(guard_home, now=now) is None, "one report per week"

    (report,) = sent
    assert set(report) == {"schema", "week", "guardVersion", "entries"}
    (entry,) = report["entries"]
    assert set(entry) == {"slug", "runtime", "version", "key"}
    assert (entry["slug"], entry["runtime"], entry["version"]) == ("acme/notes-kit", "claude-code", "1.2.0")
    assert len(entry["key"]) == 64
    text = json.dumps(report)
    for private in ("internal-tool", "corp", str(user_home), str(guard_home)):
        assert private not in text


def test_dry_run_prints_the_report_without_opt_in_or_sending(
    guard_home: Path, user_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(telemetry_report, "fetch_index", lambda: INDEX)
    monkeypatch.setattr(telemetry_report, "post_report", lambda _report: pytest.fail("dry run sent a report"))
    exit_code, output, error = _run(["telemetry", "plugins", "send", "--dry-run", "--json"])
    assert (exit_code, error) == (0, "")
    report = json.loads(output)
    assert [entry["slug"] for entry in report["entries"]] == ["acme/notes-kit"]
    assert not (guard_home / SECRET_FILE).exists()
    assert not read_state(guard_home).enabled
