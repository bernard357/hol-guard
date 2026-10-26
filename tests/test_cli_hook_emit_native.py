"""``hol-guard hook`` prints what the resident read from the daemon answer."""

from __future__ import annotations

import io
import json

import pytest

from codex_plugin_scanner.guard.cli import commands_hook_native_authority as cli


def test_bridge_harness_prints_the_resident_rendering(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, object], str]] = []

    def rendered(harness, response, *, event_name, guard_home=None):
        del guard_home
        calls.append((harness, dict(response), event_name))
        return {"stdout": '{"decision":"deny"}', "stderr": "", "exit_code": 2}

    monkeypatch.setattr(cli, "native_cli_hook_emit", rendered)
    stream = io.StringIO()
    code = cli.emit_hook_review("grok", {"policy_action": "block"}, event_name="PreToolUse", output_stream=stream)
    assert code == 2
    assert stream.getvalue() == '{"decision":"deny"}\n'
    assert calls == [("grok", {"policy_action": "block"}, "PreToolUse")]


@pytest.mark.parametrize("answer", (None, {"stdout": 1, "stderr": "", "exit_code": 0}, {"exit_code": True}))
def test_bridge_harness_fails_closed_without_a_rendering(monkeypatch: pytest.MonkeyPatch, answer) -> None:
    monkeypatch.setattr(cli, "native_cli_hook_emit", lambda *_args, **_kwargs: answer)
    stream = io.StringIO()
    code = cli.emit_hook_review("kimi", {"policy_action": "allow"}, event_name="PreToolUse", output_stream=stream)
    payload = json.loads(stream.getvalue())
    assert code == 2
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize(("answer", "expected"), (({"policy_action": "allow"}, 0), (None, 2), ({}, 2)))
def test_other_harness_exits_with_the_named_policy_action(
    monkeypatch: pytest.MonkeyPatch, answer, expected: int
) -> None:
    monkeypatch.setattr(cli, "native_cli_hook_emit", lambda *_args, **_kwargs: answer)
    stream = io.StringIO()
    code = cli.emit_hook_review("cursor", {"policy_action": "allow"}, event_name="PreToolUse", output_stream=stream)
    assert json.loads(stream.getvalue()) == {"policy_action": "allow"}
    assert code == expected


def test_claude_code_never_asks_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(*_args, **_kwargs):
        raise AssertionError("claude-code reads its JSON only on exit 0")

    monkeypatch.setattr(cli, "native_cli_hook_emit", unexpected)
    stream = io.StringIO()
    assert cli.emit_hook_review("claude-code", {"decision": "block"}, event_name="Stop", output_stream=stream) == 0
