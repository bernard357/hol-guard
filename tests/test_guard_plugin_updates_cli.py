"""``hol-guard plugin updates``: newer checked releases of installed plugins.

The check compares versions on the device, so the cases here pin that only
the two public indexes are downloaded, that unlisted plugins never produce a
prompt, that security fixes are marked urgent, and that a dismissal hides a
prompt only until a newer release is checked.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

from codex_plugin_scanner import cli as guard_cli
from codex_plugin_scanner.guard.plugin_telemetry import report as telemetry_report
from codex_plugin_scanner.guard.plugin_telemetry import updates as plugin_updates

INDEX = [
    {"slug": "acme/notes-kit", "repository": "https://github.com/acme/notes-kit"},
    {"slug": "acme/other", "repository": "https://github.com/acme/other"},
]
RELEASES_URL = "https://hol.org/plugins/acme/notes-kit/releases"


def _releases(*versions: tuple[str, str, bool]) -> list[dict[str, object]]:
    return [
        {
            "slug": "acme/notes-kit",
            "releasesUrl": RELEASES_URL,
            "releases": [
                {"version": version, "maxSeverity": severity, "fixesSecurity": fixes}
                for version, severity, fixes in versions
            ],
        }
    ]


@pytest.fixture
def guard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "guard-home"
    monkeypatch.setattr(plugin_updates, "resolve_guard_home", lambda override=None: home)
    return home


@pytest.fixture
def user_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "user"
    for owner, name, version in (("acme", "notes-kit", "1.2.0"), ("corp", "internal-tool", "0.1.0")):
        manifest = home / ".claude" / "plugins" / "cache" / owner / name / version / ".claude-plugin"
        manifest.mkdir(parents=True)
        (manifest / "plugin.json").write_text(
            json.dumps({"name": name, "version": version, "repository": f"https://github.com/{owner}/{name}"}),
            encoding="utf-8",
        )
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setattr(telemetry_report.Path, "home", staticmethod(lambda: home))
    monkeypatch.setattr(plugin_updates, "fetch_index", lambda: INDEX)
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


def test_prompts_for_a_newer_checked_release_of_listed_plugins_only(
    guard_home: Path, user_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        plugin_updates, "fetch_release_index", lambda: _releases(("1.3.0", "low", False), ("1.2.0", "none", False))
    )
    exit_code, output, error = _run(["plugin", "updates", "--json"])
    assert (exit_code, error) == (0, "")
    result = json.loads(output)
    assert result == {
        "dismissed": 0,
        "updates": [
            {
                "installedVersion": "1.2.0",
                "latestVersion": "1.3.0",
                "reason": None,
                "releasesUrl": RELEASES_URL,
                "runtime": "claude-code",
                "slug": "acme/notes-kit",
                "urgent": False,
            }
        ],
    }
    assert "internal-tool" not in output


def test_marks_a_security_fix_urgent(guard_home: Path, user_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        plugin_updates, "fetch_release_index", lambda: _releases(("1.2.1", "none", True), ("1.2.0", "high", False))
    )
    exit_code, output, _error = _run(["plugin", "updates"])
    assert exit_code == 0
    assert "acme/notes-kit (claude-code): 1.2.0 -> 1.2.1" in output
    assert "Urgent: a newer release fixes a high or critical finding." in output


def test_dismissal_hides_a_prompt_until_a_newer_release(
    guard_home: Path, user_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    releases = _releases(("1.3.0", "none", False))
    monkeypatch.setattr(plugin_updates, "fetch_release_index", lambda: releases)
    assert _run(["plugin", "updates", "dismiss", "acme/notes-kit", "--version", "1.3.0"])[0] == 0
    exit_code, output, _error = _run(["plugin", "updates"])
    assert exit_code == 0
    assert "No newer checked releases" in output
    assert "1 dismissed" in output

    releases[0]["releases"] = [{"version": "1.4.0", "maxSeverity": "none", "fixesSecurity": False}]
    output = _run(["plugin", "updates", "--json"])[1]
    assert [update["latestVersion"] for update in json.loads(output)["updates"]] == ["1.4.0"]

    assert _run(["plugin", "updates", "reset"])[0] == 0
    assert plugin_updates.read_dismissals(guard_home) == []


def test_release_index_keeps_only_the_expected_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "schema": 1,
        "entries": [
            {
                "slug": "acme/notes-kit",
                "releasesUrl": RELEASES_URL,
                "releases": [{"version": "1.0.0", "maxSeverity": "low", "fixesSecurity": False, "extra": "x"}, 7],
            },
            {"slug": 3},
        ],
    }

    requested: list[str] = []

    def fake_urlopen(request: object, timeout: float) -> io.BytesIO:
        requested.append(getattr(request, "full_url", ""))
        return io.BytesIO(json.dumps(payload).encode("utf-8"))

    monkeypatch.setattr(plugin_updates, "managed_urlopen", fake_urlopen)
    assert plugin_updates.fetch_release_index() == [
        {
            "slug": "acme/notes-kit",
            "releasesUrl": RELEASES_URL,
            "releases": [{"version": "1.0.0", "maxSeverity": "low", "fixesSecurity": False}],
        }
    ]
    assert requested == [plugin_updates.RELEASE_INDEX_URL]


def test_large_indexes_are_filtered_to_installed_plugins_before_the_native_check(
    guard_home: Path, user_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    padding = [
        {"slug": f"pad/plugin-{number}", "repository": f"https://github.com/pad/plugin-{number}-{'x' * 40}"}
        for number in range(70_000)
    ]
    assert len(json.dumps(padding)) > 6 * 1024 * 1024
    monkeypatch.setattr(plugin_updates, "fetch_index", lambda: [*padding, *INDEX])
    padded_releases = [
        {"slug": entry["slug"], "releasesUrl": RELEASES_URL, "releases": []} for entry in padding[:5_000]
    ]
    monkeypatch.setattr(
        plugin_updates, "fetch_release_index", lambda: [*padded_releases, *_releases(("1.3.0", "none", False))]
    )
    exit_code, output, _error = _run(["plugin", "updates", "--json"])
    assert exit_code == 0
    assert [update["slug"] for update in json.loads(output)["updates"]] == ["acme/notes-kit"]
