"""Answer a ``hol-guard hook`` call through the daemon's native review path."""

from __future__ import annotations

import argparse
import logging
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any, TextIO

from ..adapters.base import HarnessContext
from ..adapters.bounded_cli_hook_daemon import _daemon_response_to_native, _policy_action_from_daemon
from ..config import GuardConfig
from ..daemon.diagnostics import DaemonDiagnostics
from ..daemon.hook_availability_policy import availability_harness_response
from ..daemon.hook_request_parsing import runtime_hook_event_name
from ..daemon.hook_worker import HookWorker
from ..daemon.runtime_hook_deadline import RuntimeHookDeadline
from ..hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY, collect_hook_execution_environment
from ..native_hook_evidence_writer import NativeHookEvidenceWriter
from ..store import GuardStore
from .commands_support_runtime_resolution import _canonical_harness_name
from .native_hook_exit_code import native_hook_verdict_exit_code
from .render import emit_guard_payload

_DIAGNOSTIC_DRAIN_TIMEOUT_SECONDS = 0.25

# Harnesses whose bounded hook bridge prints this command's output to the
# harness as is. Their daemon route renders the review into the harness's own
# wire format, so the CLI renders it the same way.
_BRIDGE_RENDERED_HARNESSES = frozenset({"cline", "copilot", "devin", "grok", "hermes", "kimi", "openclaw", "zcode"})


def _record_native_hook_exception(guard_home: Path, *, harness: str, event_name: str) -> None:
    """Write the swallowed hook exception to Guard's own log.

    The fail-closed response deliberately carries no detail: it travels the
    harness wire and would leak local paths. Without this the operator sees a
    deny with no stderr, no reason beyond the generic message, and nothing in
    any log to explain it. Diagnostics never change the returned verdict, so
    every failure here is suppressed. Call this from inside the ``except``
    block, where ``sys.exc_info()`` still holds the exception.
    """

    with suppress(Exception):
        diagnostics = DaemonDiagnostics(guard_home, start_worker=False, rotate=False)
        try:
            diagnostics.record_exception(
                "native_hook_worker_exception",
                detail=f"harness={harness} event={event_name}",
            )
        finally:
            diagnostics.close(timeout_seconds=_DIAGNOSTIC_DRAIN_TIMEOUT_SECONDS)


def try_native_hook_authority(
    *,
    payload: dict[str, object],
    harness: str,
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    store: GuardStore,
    deadline: float | None = None,
    claim_saved_approval: bool = True,
    claimed_saved_allow_hash: str | None = None,
    claimed_approval_request_id: str | None = None,
) -> dict[str, Any]:
    """Review one hook with the same fail-closed worker the daemon uses.

    Any failure answers with the harness's fail-safe availability response.
    """
    worker: HookWorker | None = None
    try:
        # Short-lived CLI hooks publish and await the resident-ACKed policy
        # snapshot themselves; with no Python fallback, a missing snapshot must
        # not silently downgrade a hook to a fail-safe allow.
        worker = HookWorker(
            store=store,
            activity_writer=NativeHookEvidenceWriter(store=store),
        )
        return worker.review_http_payload(
            payload=payload,
            params={},
            default_harness=harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
            claim_saved_approval=claim_saved_approval,
            claimed_saved_allow_hash=claimed_saved_allow_hash,
            claimed_approval_request_id=claimed_approval_request_id,
        )
    except Exception as error:
        _record_native_hook_exception(
            guard_home,
            harness=harness,
            event_name=runtime_hook_event_name(payload),
        )
        _log_worker_exception(error, harness=harness)
        return availability_harness_response(
            harness=harness,
            event_name=runtime_hook_event_name(payload),
            reason_code="native_hook_worker_exception",
            reason="HOL Guard could not complete the native hook decision safely.",
        )
    finally:
        if worker is not None:
            close = getattr(worker, "close", None)
            if callable(close):
                close()
        # The writer belongs to the resident, not to this process, so a
        # one-shot hook never stops it: the records it handed over are
        # persisted after this process exits, and stopping the writer here
        # would drain and drop one the next hook would have to rebuild.


def _log_worker_exception(error: BaseException, *, harness: str) -> None:
    """Point the operator at the Guard log before denying.

    The harness wire document is a fixed deny that deliberately carries no
    detail. The full exception and traceback go to Guard's own log through
    ``_record_native_hook_exception``; this line only names the failure class
    so the operator knows where to look. Hook stderr can reach the harness, so
    no exception message, traceback, path or payload-derived value is logged
    here, and a failing log handler never changes the returned verdict.
    """

    with suppress(Exception):
        logging.getLogger(__name__).warning(
            "HOL Guard native hook authority failed for %s (%s); details are in the Guard daemon log",
            harness,
            type(error).__name__,
        )


def _payload_workspace(payload: dict[str, object]) -> Path | None:
    """The workspace the hook named, as spelled; the native edge settles it."""

    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd.strip() and Path(cwd).is_absolute():
        return Path(cwd)
    return None


def emit_hook_review(
    harness: str,
    response: dict[str, Any],
    *,
    event_name: str,
    output_stream: TextIO | None = None,
) -> int:
    """Write a reviewed hook's answer and return the harness's exit code."""

    canonical = _canonical_harness_name(harness)
    if canonical in _BRIDGE_RENDERED_HARNESSES:
        stdout, stderr, exit_code = _daemon_response_to_native(response, harness=canonical, event_name=event_name)
        stream = output_stream or sys.stdout
        if stdout:
            _ = stream.write(stdout + "\n")
        if stderr:
            print(stderr, file=sys.stderr)
        return exit_code
    # Every other caller reads the daemon's response document; a hook caller
    # need not pass --json to receive a parseable one.
    emit_guard_payload("hook", response, True, output_stream)
    policy_action = _policy_action_from_daemon(response, event_name=event_name)
    return native_hook_verdict_exit_code(canonical, policy_action, event_name=event_name)


def route_native_hook(
    args: argparse.Namespace,
    *,
    config: GuardConfig | None,
    context: HarnessContext,
    payload: dict[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    output_stream: TextIO | None = None,
    _claim_saved_approval: bool = True,
    _claimed_saved_allow_hash: str | None = None,
    _claimed_trusted_request_override: bool = False,
    _claimed_approval_request_id: str | None = None,
) -> int:
    """Review a hook through the daemon's review path and emit its result.

    Every hook result is native or fail-safe; there is no Python semantic
    fallback, and the answer is the one the daemon gives the same request.
    """

    del config, _claimed_trusted_request_override
    event_name = runtime_hook_event_name(payload)
    try:
        payload = dict(payload)
        # This process runs in the shell the command is about to run in, so its
        # environment is the caller context the daemon would get from a bridge.
        if HOOK_EXECUTION_ENVIRONMENT_KEY not in payload:
            payload[HOOK_EXECUTION_ENVIRONMENT_KEY] = collect_hook_execution_environment()
        response = try_native_hook_authority(
            payload=payload,
            harness=args.harness,
            home_dir=context.home_dir,
            guard_home=context.guard_home,
            workspace=runtime_workspace or _payload_workspace(payload),
            store=store,
            deadline=RuntimeHookDeadline.cli_edge_kwargs(payload).get("deadline"),
            claim_saved_approval=_claim_saved_approval,
            claimed_saved_allow_hash=_claimed_saved_allow_hash,
            claimed_approval_request_id=_claimed_approval_request_id,
        )
        if not isinstance(response, dict):
            response = availability_harness_response(
                harness=args.harness,
                event_name=event_name,
                reason_code="native_hook_worker_unavailable",
                reason="HOL Guard could not complete the native hook decision safely.",
            )
        return emit_hook_review(args.harness, response, event_name=event_name, output_stream=output_stream)
    except Exception as error:
        _record_native_hook_exception(context.guard_home, harness=args.harness, event_name=event_name)
        _log_worker_exception(error, harness=args.harness)
        response = availability_harness_response(
            harness=args.harness,
            event_name=event_name,
            reason_code="native_hook_worker_exception",
            reason="HOL Guard could not complete the native hook decision safely.",
        )
        return emit_hook_review(args.harness, response, event_name=event_name, output_stream=output_stream)
