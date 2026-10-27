"""Focused regression tests for signed Codex approval handoffs."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_resume as resume
from tests.guard_signed_approval_fixtures import write_synthetic_daemon_auth_token


def test_pending_approval_prints_the_authenticated_browser_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    write_synthetic_daemon_auth_token(guard_home)
    approval_url = "http://127.0.0.1:5475/requests/req-1"
    opened_urls: list[str] = []
    monkeypatch.setattr(resume, "open_browser_url", lambda url: opened_urls.append(url) or True)

    resume._open_pending_approval(approval_url, state_path=guard_home / "daemon-state.json")

    captured = capsys.readouterr()
    assert len(opened_urls) == 1
    assert opened_urls[0].startswith(f"{approval_url}#guard-token=")
    assert captured.err == f"HOL Guard is waiting for approval in your browser: {opened_urls[0]}\n"


def test_pending_approval_does_not_open_unsigned_url_when_auth_token_load_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    approval_url = "http://127.0.0.1:5475/requests/req-1"
    opened_urls: list[str] = []

    def raise_auth_error(_guard_home: Path) -> str:
        raise OSError("synthetic auth loader failure")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.approval_hook_copy.load_guard_daemon_auth_token",
        raise_auth_error,
    )
    monkeypatch.setattr(resume, "open_browser_url", lambda url: opened_urls.append(url) or True)

    resume._open_pending_approval(approval_url, state_path=tmp_path / "daemon-state.json")

    captured = capsys.readouterr()
    assert opened_urls == []
    assert "could not create a signed approval link" in captured.err.lower()
    assert approval_url not in captured.err
