"""The JSON document route takes its process status from the resident.

The directive decides both the document and the status it exits with. A
replayed decision relaxes ``exit_code`` to 0 so the fallback envelope
acknowledges without re-blocking; the document answers before that branch, so
it carries ``json_exit_code`` — the status the harness itself expects.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import Any

import pytest

from codex_plugin_scanner.guard.cli import commands_support_hook_payload as payload


def _args(harness: str = "claude-code") -> argparse.Namespace:
    return argparse.Namespace(harness=harness, json=True)


def _document(exit_code: Callable[[], int], **overrides: Any) -> tuple[dict[str, object] | None, int] | None:
    return payload._native_hook_json_document(
        _args(overrides.pop("harness", "claude-code")),
        event_name="PreToolUse",
        policy_action="block",
        exit_code=exit_code,
        reason="HOL Guard blocked this action",
        envelope={},
        **overrides,
    )


class TestTheRouteReportsTheStatusItWasGiven:
    def test_a_rendered_document_exits_with_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(payload, "_render_cli", lambda *_a, **_k: ("document", {"decision": "deny"}))
        assert _document(lambda: 1) == ({"decision": "deny"}, 1)

    def test_a_silent_contract_exits_with_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(payload, "_render_cli", lambda *_a, **_k: ("silence", None))
        assert _document(lambda: 1) == (None, 1)

    def test_a_fixed_deny_exits_with_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(payload, "_render_cli", lambda *_a, **_k: None)
        document, code = _document(lambda: 2)  # type: ignore[misc]
        assert document is not None
        assert code == 2

    def test_a_fallback_asks_for_no_status(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(payload, "_render_cli", lambda *_a, **_k: ("fallback", None))

        def unused() -> int:
            raise AssertionError("the fallback branch does not own the response")

        assert _document(unused) is None

    def test_the_python_exit_table_is_gone_from_this_route(self) -> None:
        assert not hasattr(payload, "native_hook_verdict_exit_code")
