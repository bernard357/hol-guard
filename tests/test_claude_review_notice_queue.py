"""The daemon queues a paused native review, and its Claude notice, in one resident store call."""

from __future__ import annotations

import logging
import time
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_review_approval
from codex_plugin_scanner.guard.store_approval_facade import StoreApprovalsMixin

_QUERY = {"envelope": {"harness": "claude-code"}, "request_id": "req-1"}


class _Request:
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


class _RowStore(StoreApprovalsMixin):
    """A resident reply to a queue write that asks for the stored row back."""

    def __init__(self, reply: object) -> None:
        self.reply = reply
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.reads: list[str] = []

    def _native_store_call(self, method: str, args: dict[str, Any]) -> object:
        self.calls.append((method, dict(args)))
        return self.reply

    def get_approval_request(self, request_id: str, *, derive_scope: bool = True) -> dict[str, object]:
        self.reads.append(request_id)
        return {"request_id": request_id, "read": "separately"}


def test_a_claude_review_queues_with_its_notice_in_one_store_write() -> None:
    store = _RowStore({"request_id": "req-1", "row": {"request_id": "req-1"}})
    key = {"integrity_key_b64": "a2V5", "integrity_key_id": "kid"}
    hint = {"kind": "extension"}
    assert store.queue_native_review(_QUERY, "now", extension_allow_hint=hint, claude_key=key) == {
        "request_id": "req-1"
    }
    # The key rides in the top-level args the request digest leaves out; the
    # resident builds the notice's facts from the query itself.
    ((method, args),) = store.calls
    assert method == "queue_native_review"
    args.pop("cwd")
    assert args == {
        "review": _QUERY,
        "extension_allow_hint": hint,
        "now": "now",
        "silent": False,
        "claude_notice": True,
        "integrity_key_b64": "a2V5",
        "integrity_key_id": "kid",
        "return_row": True,
    }


def test_other_reviews_keep_the_plain_queue_write() -> None:
    store = _Store()
    store.add_approval_request(_Request(), "now")  # type: ignore[arg-type]
    assert store.calls == [
        ("add_approval_request", {"request": {"request_id": "req-1"}, "now": "now", "prompt_shown": None})
    ]


def test_the_notice_key_is_read_for_the_store_call() -> None:
    store = _KeyedStore((b"\x09" * 32, "bound-key"))
    assert hook_native_review_approval._claude_notice_key(store, None) == {
        "integrity_key_b64": "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk",
        "integrity_key_id": "bound-key",
    }
    assert store.created == [True]


def test_a_review_without_an_integrity_key_queues_without_a_notice() -> None:
    for store in (_KeyedStore((None, None)), _KeyedStore(OSError("locked")), object()):
        assert hook_native_review_approval._claude_notice_key(store, None) is None


def test_a_spent_hook_deadline_skips_the_notice_key_read() -> None:
    store = _KeyedStore((b"\x09" * 32, "bound-key"))
    assert hook_native_review_approval._claude_notice_key(store, time.monotonic()) is None
    assert store.created == []


def test_a_review_is_queued_and_read_back_in_one_store_call() -> None:
    row = {"request_id": "req-1", "harness": "codex"}
    store = _RowStore({"request_id": "req-1", "row": row})
    assert store.queue_native_review(_QUERY, "now") == row
    assert store.reads == []
    ((method, args),) = store.calls
    assert method == "queue_native_review"
    assert (args["claude_notice"], args["return_row"]) == (False, True)
    assert "integrity_key_b64" not in args
    assert "cwd" in args


def test_a_silent_review_reads_back_in_its_daemon_write() -> None:
    store = _RowStore({"request_id": "req-1", "event_error": None, "row": {"request_id": "req-1"}})
    assert store.queue_native_review(_QUERY, "now", silent=True) == {"request_id": "req-1"}
    ((method, args),) = store.calls
    assert method == "queue_native_review"
    assert (args["silent"], args["return_row"]) == (True, True)
    assert store.reads == []


def test_a_row_the_write_did_not_read_back_is_read_separately() -> None:
    store = _RowStore({"request_id": "req-1", "row_error": "native_guard_store_invalid"})
    assert store.queue_native_review(_QUERY, "now") == {"request_id": "req-1", "read": "separately"}
    assert store.reads == ["req-1"]


class _UnreadableRowStore(_RowStore):
    def get_approval_request(self, request_id: str, *, derive_scope: bool = True) -> dict[str, object]:
        self.reads.append(request_id)
        raise ValueError("approval scope unavailable")


def test_a_failed_read_back_never_queues_the_review_again() -> None:
    # The write committed; a failed separate read answers no row rather than
    # an error a caller could take for a failed write.
    store = _UnreadableRowStore({"request_id": "req-1", "row_error": "native_guard_store_invalid"})
    key = {"integrity_key_b64": "a2V5", "integrity_key_id": "kid"}
    assert store.queue_native_review(_QUERY, "now", claude_key=key) is None
    assert [method for method, _ in store.calls] == ["queue_native_review"]
    assert store.reads == ["req-1"]


def test_an_unseeded_codex_live_wait_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    wait = {"process": {"pid": 1, "startToken": "t"}, "timeout_seconds": 120, "workspace": None}
    store = _RowStore({"request_id": "req-1", "live_wait": "native_guard_store_invalid", "row": {}})
    with caplog.at_level(logging.WARNING):
        store.queue_native_review(_QUERY, "now", codex_live_wait=wait)
    assert "Codex live wait not resumable for req-1" in caplog.text
    assert store.calls[0][1]["codex_live_wait_facts"] == wait
    # A seeded wait, and a bridge that is no longer waiting, are expected.
    for live_wait in ("seeded", "not_live"):
        store = _RowStore({"request_id": "req-1", "live_wait": live_wait, "row": {}})
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            store.queue_native_review(_QUERY, "now", codex_live_wait=wait)
        assert "Codex live wait" not in caplog.text, live_wait


def test_a_queue_write_without_a_request_id_is_refused() -> None:
    from codex_plugin_scanner.guard.native_signal_projection import NativeSignalProjectionUnavailableError

    for reply in (None, "", "req-1", {"row": {}}):
        store = _RowStore(reply)
        with pytest.raises(NativeSignalProjectionUnavailableError):
            store.queue_native_review(_QUERY, "now")
