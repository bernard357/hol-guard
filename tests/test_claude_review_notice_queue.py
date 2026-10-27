"""The daemon's Claude review queue asks the resident for its notice in the same write."""

from __future__ import annotations

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
    review = {"harness": "claude-code", "integrity_key_id": "kid"}
    assert store.add_approval_request(_Request(), "now", claude_review=review) == "req-1"  # type: ignore[arg-type]
    assert store.calls == [
        (
            "add_claude_approval_request",
            {"request": {"request_id": "req-1"}, "now": "now", "prompt_shown": None, "claude_review": review},
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
        {"session_id": "sess-1", "tool_name": "Bash"},
        {"reason": "Deletes files."},
        "rb-1",
        _Request(),  # type: ignore[arg-type]
    )
    assert store.created == [True]
    assert review == {
        "harness": "claude-code",
        "hook_payload": {"session_id": "sess-1", "tool_name": "Bash"},
        "reason": "Deletes files.",
        "review_binding": "rb-1",
        "config_path": "/work/space",
        "source_scope": "project",
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
        )
        assert review is None
