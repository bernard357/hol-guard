"""Guard CLI helper definitions."""

# ruff: noqa: F403

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


from ._commands_shared import *
from .commands_parser_helpers import *

# The copy for a render the resident could not answer. Every piece of Claude
# approval text below says Guard is holding the request, so an unreachable
# resident never leaves a prompt reading as though Guard allowed the action.
_CLAUDE_COPY_UNAVAILABLE = (
    "HOL Guard is holding this Claude request for review. The HOL Guard runtime could not render "
    "the full notice, so nothing in this prompt should be read as HOL Guard allowing the action."
)


def _claude_approval_copy(
    which: str,
    *,
    payload: dict[str, object] | None = None,
    notice: dict[str, object] | None = None,
    reason: str = "",
) -> object | None:
    from ..native_hook_render import native_claude_approval_copy

    return native_claude_approval_copy(which, payload=payload, notice=notice, reason=reason)


def _claude_approval_text(
    which: str,
    *,
    payload: dict[str, object] | None = None,
    notice: dict[str, object] | None = None,
    reason: str = "",
) -> str:
    rendered = _claude_approval_copy(which, payload=payload, notice=notice, reason=reason)
    return rendered if isinstance(rendered, str) else _CLAUDE_COPY_UNAVAILABLE


def _claude_guard_approval_question_message(notice: dict[str, object] | None) -> str:
    return _claude_approval_text("approval_question_message", notice=notice)


def _claude_permission_notice_prefers_ask_user_question(notice: dict[str, object]) -> bool:
    # A render the resident cannot answer falls back to the Guard approval
    # question, which denies Claude's own dialog; the deferring branch is the
    # one that would hand the decision back to Claude.
    rendered = _claude_approval_copy("notice_prefers_ask_user_question", notice=notice)
    return rendered if isinstance(rendered, bool) else True


def _claude_permission_request_system_message(
    *,
    payload: dict[str, object],
    native_reason: str,
) -> str:
    return _claude_approval_text("permission_request_system_message", payload=payload, reason=native_reason)


def _claude_permission_prompt_system_message(
    *,
    payload: dict[str, object],
    notice: dict[str, object] | None,
) -> str:
    return _claude_approval_text("permission_prompt_system_message", payload=payload, notice=notice)


def _claude_permission_prompt_additional_context(notice: dict[str, object] | None) -> str:
    return _claude_approval_text("permission_prompt_additional_context", notice=notice)


__all__ = [
    "_claude_guard_approval_question_message",
    "_claude_permission_notice_prefers_ask_user_question",
    "_claude_permission_prompt_additional_context",
    "_claude_permission_prompt_system_message",
    "_claude_permission_request_system_message",
]
