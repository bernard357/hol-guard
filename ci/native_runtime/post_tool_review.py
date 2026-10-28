"""Direct PostToolUse review through the native resident, for tests and benchmarks.

Production hooks reach the resident through the daemon's edge request. This
client sends one bare PostToolUse envelope so tests and the release-gate
benchmark can exercise the resident without a daemon.
"""

from __future__ import annotations

import json
import math
import time
from collections.abc import Mapping

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_request
from codex_plugin_scanner.guard.native_response_decoder import native_error, response_from_payload
from codex_plugin_scanner.guard.native_route_receipt import record_native_hook_result
from codex_plugin_scanner.guard.native_runtime_resilience import (
    native_record_integrity_failure,
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)
from codex_plugin_scanner.guard.native_runtime_values import _INTEGRITY_FAILURE_REASONS, _identity_key
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest, HookReviewResponse

_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
# The response decoder no longer re-checks the receipt; only a resident that
# checks its own answer may be trusted with a PostToolUse review.
_SELF_CHECK_FEATURE = "edge-self-check-v1"


def _capture_native_deadline(request: HookReviewRequest) -> tuple[float, int]:
    """Capture one absolute native deadline and its bounded envelope budget."""
    now = time.monotonic()
    requested = request.deadline_monotonic
    deadline = requested if requested is not None and math.isfinite(requested) else now + 0.75
    budget_ms = max(1, min(9_000, int((deadline - now) * 1_000)))
    return deadline, budget_ms


def review_post_tool_native(
    request: HookReviewRequest,
    *,
    observe_mode: bool,
    policy_snapshot: Mapping[str, object] | None,
) -> HookReviewResponse | None:
    """Review PostToolUse through the native Rust client and resident.

    Native failure returns ``None`` so the caller fails closed without Python
    re-evaluation or a semantic one-shot fallback.
    """
    del observe_mode
    status = native_runtime.native_runtime_status()
    identity_key = _identity_key(status)
    if not status.available or not status.compatible or status.identity is None:
        if status.reason in _INTEGRITY_FAILURE_REASONS:
            native_record_integrity_failure(
                identity_key,
                request.guard_home,
                reason=status.reason,
            )
        return record_native_hook_result("native_fail_safe", None)

    deadline_monotonic, deadline_budget_ms = _capture_native_deadline(request)
    if policy_snapshot is None:
        return record_native_hook_result("native_fail_safe", None)
    generation = policy_snapshot.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
        return record_native_hook_result("native_fail_safe", None)
    envelope = {
        "schema": "guard-hook-envelope.v2",
        "request_id": request.request_id,
        "harness": request.harness,
        "event": request.event_name,
        "raw_payload": request.payload,
        "deadline_budget_ms": deadline_budget_ms,
        "policy_generation": generation,
        # The resident already authenticated and cached the full snapshot at
        # push/startup. Bind each request to that snapshot without copying
        # policy rules or re-running their integrity checks on the hot path.
        "policy_snapshot": {
            "generation": generation,
            "policy_digest": policy_snapshot.get("policy_digest"),
            "runtime_identity": policy_snapshot.get("runtime_identity"),
        },
        "source": {
            "cwd": str(request.cwd) if request.cwd is not None else None,
            "home_dir": str(request.home_dir),
            "guard_home": str(request.guard_home),
            "source_ref_external_allowed": request.source_ref_external_allowed,
        },
    }
    input_text = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)
    if len(encoded := input_text.encode("utf-8")) > _MAX_REQUEST_BYTES:
        return record_native_hook_result("native_fail_safe", None)
    resident_output = None
    resident_supported = status.capabilities is not None and {
        _RESIDENT_PROTOCOL_FEATURE,
        _SELF_CHECK_FEATURE,
    } <= set(status.capabilities.features)
    if resident_supported:
        resident_output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=request.guard_home,
            environment=native_runtime._isolated_environment(),
            payload=encoded,
            deadline_monotonic=deadline_monotonic,
        )
    if resident_output is not None:
        try:
            resident_payload = json.loads(resident_output)
        except (UnicodeDecodeError, json.JSONDecodeError):
            resident_payload = None
        resident_error = native_error(resident_payload)
        if resident_error == "native_overloaded":
            native_record_overload(status.identity.sha256, request.guard_home)
            return record_native_hook_result("native_fail_safe", None)
        response = response_from_payload(resident_payload)
        if response is not None:
            native_record_resident_success(status.identity.sha256, request.guard_home)
            return record_native_hook_result("native_resident", response)
        failure_reason = resident_error or "native_resident_invalid_response"
    else:
        failure_reason = "native_resident_unavailable" if resident_supported else "native_resident_protocol_unsupported"

    native_record_resident_failure(
        status.identity.sha256,
        request.guard_home,
        reason=failure_reason,
    )
    return record_native_hook_result("native_fail_safe", None)
