"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

import logging

# ruff: noqa: F403,F405
from .native_approval_queue_identity import UNAVAILABLE as APPROVAL_QUEUE_IDENTITY_UNAVAILABLE
from .native_approval_queue_identity import ApprovalQueueIdentityUnavailableError
from .native_consumer_artifact_project import NativeConsumerProjectError
from .native_guard_store import NativeGuardStoreUnavailable
from .native_signal_projection import NativeSignalProjectionUnavailableError
from .store_base import *

_LOGGER = logging.getLogger(__name__)


class StoreApprovalsMixin:
    def settle_native_review_reuse(self, **identity: object) -> object:
        return self._native_store_call("settle_native_review_reuse", identity)

    def consume_native_review_approval(
        self,
        *,
        harness: str,
        artifact_id: str,
        artifact_name: str,
        artifact_hash: str,
        launch_target: str,
        workspace: str | None,
        now: str,
    ) -> bool:
        # The resident owns the identity grammar, the latest-decision rule, the
        # five-minute window and the single spend; an unavailable resident
        # raises a sqlite error, which the caller treats as no reuse.
        return bool(
            self._native_store_call(
                "consume_native_review_approval",
                {
                    "harness": harness,
                    "artifact_id": artifact_id,
                    "artifact_name": artifact_name,
                    "artifact_hash": artifact_hash,
                    "launch_target": launch_target,
                    "workspace": workspace,
                    "now": now,
                },
            )
        )

    def add_approval_request(
        self,
        request: GuardApprovalRequest,
        now: str,
        *,
        prompt_shown: bool | None = None,
        claude_review: dict[str, object] | None = None,
    ) -> str:
        # The resident backfills legacy queue rows, derives the canonical
        # surfaces and queue identity, deduplicates and binds the outbox event
        # in one transaction. With ``prompt_shown`` set, a newly queued request
        # also gets its ``approval.created`` (and, when prompted,
        # ``ask_once_shown``) event there. With ``claude_review`` set, the
        # resident also builds and signs the Claude permission notice for a
        # newly queued request, best effort. Its silence keeps the projection
        # owner's error.
        args: dict[str, object] = {"request": request.to_dict(), "now": now, "prompt_shown": prompt_shown}
        if claude_review is not None:
            args["claude_review"] = claude_review["review"]
            args["integrity_key_b64"] = claude_review["integrity_key_b64"]
            args["integrity_key_id"] = claude_review["integrity_key_id"]
        return self._queue_approval_request(
            "add_approval_request" if claude_review is None else "add_claude_approval_request", args
        )

    def add_silent_native_review_approval_request(self, request: GuardApprovalRequest, now: str) -> str:
        # A review the agent never sees: the resident queues it and writes its
        # ``approval.created`` event, without marking a prompt as shown, in the
        # same transaction. The event stays best effort: the resident names
        # the failure code when it could not write it.
        queued = self._native_queue_call(
            "add_silent_native_review_approval_request",
            {"request": request.to_dict(), "now": now, "daemon": True},
        )
        if not isinstance(queued, dict) or not isinstance(queued.get("request_id"), str) or not queued["request_id"]:
            raise NativeSignalProjectionUnavailableError("native_guard_store_approval_request_invalid")
        request_id: str = queued["request_id"]
        event_error = queued.get("event_error")
        if event_error is not None:
            _LOGGER.warning("Silent review inbox row saved without approval.created (%s)", event_error)
        return request_id

    def _queue_approval_request(self, method: str, args: dict[str, object]) -> str:
        request_id = self._native_queue_call(method, args)
        if not isinstance(request_id, str) or not request_id:
            raise NativeSignalProjectionUnavailableError("native_guard_store_approval_request_invalid")
        return request_id

    def _native_queue_call(self, method: str, args: dict[str, object]) -> object:
        try:
            return self._native_store_call(method, args)
        except NativeGuardStoreUnavailable as error:
            raise NativeSignalProjectionUnavailableError(error.reason) from error
        except ValueError as error:
            if str(error) == APPROVAL_QUEUE_IDENTITY_UNAVAILABLE:
                raise ApprovalQueueIdentityUnavailableError(reason="rejected") from error
            raise

    def queue_blocked_approvals(self, args: dict[str, object]) -> tuple[list[dict[str, object]], Exception | None]:
        # The resident writes one request per reviewable item, each under its
        # own savepoint, and answers the queued notices plus the error that
        # stopped the loop; the earlier requests stay queued.
        try:
            reply = self._native_store_call("queue_blocked_approvals", args)
        except NativeGuardStoreUnavailable as error:
            raise NativeSignalProjectionUnavailableError(error.reason) from error
        queued = reply.get("queued") if isinstance(reply, dict) else None
        if not isinstance(queued, list):
            raise NativeSignalProjectionUnavailableError("native_guard_store_approval_request_invalid")
        error = reply.get("error")
        if not isinstance(error, dict):
            return queued, None
        kind, message = error.get("type"), str(error.get("message"))
        if kind == "value" and message == APPROVAL_QUEUE_IDENTITY_UNAVAILABLE:
            return queued, ApprovalQueueIdentityUnavailableError(reason="rejected")
        failures: dict[object, type[Exception]] = {
            "value": ValueError,
            "consumer": NativeConsumerProjectError,
            "integrity": sqlite3.IntegrityError,
            "os": OSError,
        }
        return queued, failures.get(kind, RuntimeError)(message)

    def resolve_harness_native_approval_request(
        self,
        request_id: str,
        *,
        reason: str | None,
        resolved_at: str,
        expected_harness: str,
        expected_artifact_id: str | None = None,
        expected_artifact_hash: str | None = None,
    ) -> bool:
        """Close an inbox request after a verified harness-native Accept.

        Cursor (and similar) native prompts are the user's approval. Requiring
        the local approval-gate password/MFA a second time left the request
        inbox pending after Accept. This path is artifact-scoped allow-only.
        """

        return self._native_approval_read(
            "resolve_harness_native_approval_request",
            {
                "request_id": request_id,
                "reason": reason,
                "resolved_at": resolved_at,
                "expected_harness": expected_harness,
                "expected_artifact_id": expected_artifact_id,
                "expected_artifact_hash": expected_artifact_hash,
            },
        )

    def resolve_approval_request(
        self,
        request_id: str,
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> None:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        self._native_approval_read(
            "resolve_approval_request",
            {
                "request_id": request_id,
                "resolution_action": resolution_action,
                "resolution_scope": resolution_scope,
                "reason": reason,
                "resolved_at": resolved_at,
            },
        )

    def resolve_one_request_only(
        self,
        request_id: str,
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> bool:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        return self._native_approval_read(
            "resolve_one_request_only",
            {
                "request_id": request_id,
                "resolution_action": resolution_action,
                "resolution_scope": resolution_scope,
                "reason": reason,
                "resolved_at": resolved_at,
            },
        )

    def resolve_matching_duplicate_requests(
        self,
        *,
        queue_group_id: str | None,
        request_id: str,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> list[str]:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        return self._native_approval_read(
            "resolve_matching_duplicate_requests",
            {
                "queue_group_id": queue_group_id,
                "request_id": request_id,
                "resolution_action": resolution_action,
                "resolution_scope": resolution_scope,
                "reason": reason,
                "resolved_at": resolved_at,
            },
        )

    def resolve_request_with_queue_result(
        self,
        request_id: str,
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> dict[str, object]:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        return self._native_approval_read(
            "resolve_request_with_queue_result",
            {
                "request_id": request_id,
                "resolution_action": resolution_action,
                "resolution_scope": resolution_scope,
                "reason": reason,
                "resolved_at": resolved_at,
            },
        )

    def resolve_matching_approval_requests(
        self,
        *,
        harness: str | None,
        scope: str,
        artifact_id: str | None,
        workspace: str | None,
        publisher: str | None,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
        approval_gate_grant: ApprovalGateGrant | None = None,
        artifact_hash: str | None = None,
    ) -> list[str]:
        require_request_resolution(
            self.guard_home,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            approval_gate_grant=approval_gate_grant,
            now=resolved_at,
        )
        return self._native_approval_read(
            "resolve_matching_approval_requests",
            {
                "harness": harness,
                "scope": scope,
                "artifact_id": artifact_id,
                "artifact_hash": artifact_hash,
                "workspace": workspace,
                "publisher": publisher,
                "resolution_action": resolution_action,
                "resolution_scope": resolution_scope,
                "reason": reason,
                "resolved_at": resolved_at,
            },
        )
