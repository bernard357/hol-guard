"""The daemon's Claude review queue asks the resident for its notice in the same write."""

from __future__ import annotations

import time
from typing import Any

from codex_plugin_scanner.guard.daemon import hook_native_review_approval
from codex_plugin_scanner.guard.store_approval_facade import StoreApprovalsMixin


class _Request:
    config_path = "/work/space"
    source_scope = "project"

    def to_dict(self) -> dict[str, object]:
        return {"request_id": "req-1"}


class _Store(StoreApprovalsMixin):
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _native_store_call(self, method: str, args: dict[str, Any]) -> str:
        self.calls.append((method, dict(args)))
        return "req-1"


class _KeyedStore:
    def __init__(self, material: object) -> None:
        self.material = material
        self.created: list[bool] = []

    def _policy_integrity_secret_material(self, *, create: bool) -> object:
        self.created.append(create)
        if isinstance(self.material, Exception):
            raise self.material
        return self.material


def test_a_claude_review_queues_with_its_notice_in_one_store_write() -> None:
    store = _Store()
    review = {"harness": "claude-code"}
    notice = {"review": review, "integrity_key_b64": "a2V5", "integrity_key_id": "kid"}
    assert store.add_approval_request(_Request(), "now", claude_review=notice) == "req-1"  # type: ignore[arg-type]
    # The key rides in the top-level args the request digest leaves out,
    # never inside the digested ``claude_review`` facts.
    assert store.calls == [
        (
            "add_claude_approval_request",
            {
                "request": {"request_id": "req-1"},
                "now": "now",
                "prompt_shown": None,
                "claude_review": review,
                "integrity_key_b64": "a2V5",
                "integrity_key_id": "kid",
            },
        )
    ]


def test_other_reviews_keep_the_plain_queue_write() -> None:
    store = _Store()
    store.add_approval_request(_Request(), "now")  # type: ignore[arg-type]
    assert store.calls == [
        ("add_approval_request", {"request": {"request_id": "req-1"}, "now": "now", "prompt_shown": None})
    ]


def test_the_notice_carries_the_review_facts_and_the_integrity_key() -> None:
    store = _KeyedStore((b"\x09" * 32, "bound-key"))
    review = hook_native_review_approval._claude_review_notice(
        store,
        "claude-code",
        {
            "session_id": "sess-1",
            "tool_name": "Bash",
            "cwd": "/work/space",
            "tool_input": {"command": "rm -rf build", "description": "x" * 4096},
        },
        {"reason": "Deletes files."},
        "rb-1",
        _Request(),  # type: ignore[arg-type]
        None,
    )
    assert store.created == [True]
    assert review == {
        "review": {
            "harness": "claude-code",
            # Only what the notice reads: the full hook payload stays out.
            "hook_payload": {"session_id": "sess-1", "tool_name": "Bash", "tool_input": {"command": "rm -rf build"}},
            "reason": "Deletes files.",
            "review_binding": "rb-1",
            "config_path": "/work/space",
            "source_scope": "project",
        },
        "integrity_key_b64": "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk",
        "integrity_key_id": "bound-key",
    }


def test_a_review_without_an_integrity_key_queues_without_a_notice() -> None:
    for store in (_KeyedStore((None, None)), _KeyedStore(OSError("locked")), object()):
        review = hook_native_review_approval._claude_review_notice(
            store,
            "claude-code",
            {},
            {},
            None,
            _Request(),  # type: ignore[arg-type]
            None,
        )
        assert review is None


def test_a_spent_hook_deadline_skips_the_notice_key_read() -> None:
    store = _KeyedStore((b"\x09" * 32, "bound-key"))
    review = hook_native_review_approval._claude_review_notice(
        store,
        "claude-code",
        {"session_id": "sess-1", "tool_name": "Bash"},
        {},
        None,
        _Request(),  # type: ignore[arg-type]
        time.monotonic(),
    )
    assert review is None
    assert store.created == []


def test_a_refused_combined_write_still_queues_the_review() -> None:
    calls: list[dict[str, object]] = []

    def persist(_request: object, _now: str, **kwargs: object) -> str:
        calls.append(kwargs)
        if kwargs:
            raise RuntimeError("native_guard_store_request_too_large")
        return "req-1"

    notice = {"review": {}, "integrity_key_b64": "a2V5", "integrity_key_id": "kid"}
    assert hook_native_review_approval._persist_review(persist, _Request(), "now", notice)  # type: ignore[arg-type] == "req-1"
    assert calls == [{"claude_review": notice}, {}]
