"""A failed combined review-evidence ask falls back to the two separate asks."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_exact_action as exact


def _evidence(tmp_path: Path) -> tuple[str | None, str | None, str | None]:
    return exact.native_review_evidence(
        harness="codex",
        tool_name="Bash",
        payload={"tool_name": "Bash", "tool_input": {"command": "make build"}, "cwd": str(tmp_path)},
        native_result={"reason": "review"},
        native_receipt=None,
        workspace=tmp_path,
        home_dir=tmp_path,
        guard_home=tmp_path / "guard-home",
    )


def test_a_failed_combined_ask_keeps_the_answers_the_separate_asks_give(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[str] = []

    def answer(query: Mapping[str, object], _guard_home: Path | None) -> dict[str, Any]:
        asked.append(str(query["kind"]))
        raise exact.NativeExactActionError("native_exact_action_unavailable")

    monkeypatch.setattr(exact, "_answer", answer)
    monkeypatch.setattr(exact, "native_review_binding", lambda *_a, **_k: "binding")
    monkeypatch.setattr(exact, "native_exact_action", lambda **_k: ("token", None))

    assert _evidence(tmp_path) == ("binding", "token", None)
    assert asked == ["review_evidence"]


def test_each_separate_ask_still_fails_closed_on_its_own(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def answer(_query: Mapping[str, object], _guard_home: Path | None) -> dict[str, Any]:
        raise exact.NativeExactActionError("native_exact_action_unavailable")

    monkeypatch.setattr(exact, "_answer", answer)
    monkeypatch.setattr(exact, "native_review_binding", lambda *_a, **_k: "binding")
    monkeypatch.setattr(exact, "native_exact_action", lambda **_k: (None, exact.UNPROVEN_LAUNCH))

    assert _evidence(tmp_path) == ("binding", None, exact.UNPROVEN_LAUNCH)
