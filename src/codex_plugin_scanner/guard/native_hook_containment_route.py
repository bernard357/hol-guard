"""Containment routing, answered by the native runtime.

Both hook paths ask the resident whether a native PreToolUse answer is
rewritten into Guard's contained execution sink, so the CLI fallback and the
daemon route a call identically. ``native_containment_route`` sends the
native result's actions, reason and action type and returns ``none``,
``sink`` or ``grant``. ``native_containment_sink`` sends the rendered receipt,
the harness, the host and the shape of the call, and returns the profile the
sink runs it under, or why the receipt stands. ``native_containment_rewrite``
sends the same facts with the call itself and the argv that starts Guard's
CLI; the resident writes the private request snapshot and returns the allow
that runs the call in the sink.

The transport only gathers those facts; the routing table, the host table and
the harness table are the resident's. A reply that is not a bound, strictly
decoded ``ok`` with a well-formed answer raises ``NativeHookDecisionError`` and
the caller answers with the host outage response, so a route is never guessed.
"""

from __future__ import annotations

import dataclasses
import functools
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NamedTuple

from .native_execution import _resident_request
from .native_hook_decision import (
    _INVALID,
    _MAX_REQUEST_BYTES,
    _OPERATION,
    _UNAVAILABLE,
    NativeHookDecisionError,
)
from .native_resident_decision import resident_decide

HOOK_DECISION_CONTAINMENT_ROUTE_FEATURE = "hook-decision-containment-route-v1"
HOOK_DECISION_CONTAINMENT_REWRITE_FEATURE = "hook-decision-containment-rewrite-v1"
_ROUTED_REASON = "native_contained_execution_routed"
_ROUTES = frozenset({"none", "sink", "grant"})
_KEPT_BECAUSE = frozenset(
    {
        "receipt_only",
        "harness_not_routed",
        "not_sandbox_required",
        "observe_mode",
        "profile_mismatch",
        "platform_has_no_sink",
        "not_shell_call",
    }
)
_RECEIPT_ONLY_FIELD = "guard_containment_receipt_only"


class ContainmentSink(NamedTuple):
    """The profile the sink runs a call under, or why its receipt stands."""

    profile: str | None
    kept_because: str | None


class ContainmentRewrite(NamedTuple):
    """The sink's answer for a receipt and, when it takes the call, the allow that runs it there."""

    profile: str | None
    kept_because: str | None
    response: dict[str, object] | None


def host_platform() -> str:
    """The host as the resident names it."""

    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "win32":
        return "windows"
    return "other"


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _ask(
    kind: str,
    inputs: Mapping[str, object],
    guard_home: Path | None,
    validate: Any,
    deadline: float | None,
    feature: str = HOOK_DECISION_CONTAINMENT_ROUTE_FEATURE,
) -> dict[str, Any]:
    # ``deadline`` is the hook's ``time.monotonic()`` deadline. The query never
    # waits past it, and a spent deadline is an outage without asking, so a
    # slow resident cannot hold the hook past what the harness allows.
    timeout = _OPERATION.timeout_seconds
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
        if timeout <= 0:
            raise NativeHookDecisionError(_UNAVAILABLE)
    return resident_decide(
        dataclasses.replace(_OPERATION, feature=feature, timeout_seconds=timeout),
        functools.partial(_resident_request, max_request_bytes=_MAX_REQUEST_BYTES),
        {"kind": kind, "inputs": dict(inputs)},
        guard_home,
        validate,
    )


def native_containment_route(
    result: Mapping[str, object],
    *,
    event_name: object,
    recording_only: bool,
    guard_home: Path | None,
    deadline: float | None = None,
) -> str:
    """Which containment step a native PreToolUse ``result`` takes: ``none``, ``sink`` or ``grant``."""

    action = result.get("action")
    action_type = action.get("action_type") if isinstance(action, Mapping) else None
    inputs = {
        "event_name": _text(event_name),
        "recording_only": bool(recording_only),
        "minimum_action": _text(result.get("minimum_action")),
        "policy_action": _text(result.get("policy_action")),
        "reason_code": _text(result.get("reason_code")),
        "action_type": action_type,
    }

    def validate(payload: dict[str, Any]) -> None:
        route = payload.get("route")
        if set(payload) != {"kind", "route"} or not isinstance(route, str) or route not in _ROUTES:
            raise NativeHookDecisionError(_INVALID)

    return str(_ask("containment_route", inputs, guard_home, validate, deadline)["route"])


def edge_containment_route(
    edge: Mapping[str, object],
    result: Mapping[str, object],
    *,
    event_name: object,
    recording_only: bool,
    guard_home: Path | None,
    deadline: float | None = None,
) -> str:
    """The route the resident stamped on its edge answer, or its ``containment_route`` answer.

    The resident computes the route when it produces a PreToolUse edge, so a
    hook routes the call without a second round trip. An edge that does not
    carry one is asked about; Python never picks a route itself.
    """

    stamped = edge.get("containment_route")
    if isinstance(stamped, str) and stamped in _ROUTES:
        return stamped
    return native_containment_route(
        result, event_name=event_name, recording_only=recording_only, guard_home=guard_home, deadline=deadline
    )


def native_containment_sink(
    response: Mapping[str, object],
    *,
    harness: str,
    bridge: bool,
    payload: Mapping[str, object],
    guard_home: Path | None,
    deadline: float | None = None,
) -> ContainmentSink:
    """Whether the rendered receipt ``response`` for ``payload`` is rewritten into the sink."""

    tool_input = _tool_input(payload)
    inputs = {
        **_receipt_facts(response, harness=harness, bridge=bridge, payload=payload),
        "command_is_text": isinstance(tool_input, dict) and isinstance(tool_input.get("command"), str),
    }

    def validate(answer: dict[str, Any]) -> None:
        if set(answer) != {"kind", "profile", "kept_because"}:
            raise NativeHookDecisionError(_INVALID)
        _validate_sink(answer, inputs)

    answer = _ask("containment_sink", inputs, guard_home, validate, deadline)
    return ContainmentSink(answer["profile"], answer["kept_because"])


def native_containment_rewrite(
    response: Mapping[str, object],
    *,
    harness: str,
    bridge: bool,
    payload: Mapping[str, object],
    workspace: Path | None,
    guard_home: Path,
    home_dir: Path,
    sink_command: Sequence[str],
    deadline: float | None = None,
) -> ContainmentRewrite:
    """The resident's rewrite of the rendered receipt ``response`` into the sink.

    When the sink takes the call, the resident writes its private request
    snapshot and returns the allow whose ``updatedInput`` runs
    ``sink_command guard execute-contained-test`` on it. A call it cannot
    snapshot or quote keeps its receipt (``response`` is ``None``).
    """

    tool_input = _tool_input(payload)
    inputs = {
        **_receipt_facts(response, harness=harness, bridge=bridge, payload=payload),
        "tool_input": tool_input,
        "workspace": str(workspace) if workspace is not None else None,
        "session_id": payload.get("session_id", payload.get("sessionId")),
        "tool_call_id": payload.get("tool_call_id", payload.get("toolCallId", payload.get("tool_use_id"))),
        "guard_home": str(guard_home),
        "home": str(home_dir),
        "sink_command": list(sink_command),
    }
    if not all(isinstance(argument, str) for argument in sink_command):
        raise NativeHookDecisionError(_INVALID)

    def validate(answer: dict[str, Any]) -> None:
        if set(answer) != {"kind", "profile", "kept_because", "response"}:
            raise NativeHookDecisionError(_INVALID)
        _validate_sink(answer, inputs)
        routed = answer["response"]
        if routed is not None and (answer["profile"] is None or not _routed_shape(routed, tool_input)):
            raise NativeHookDecisionError(_INVALID)

    answer = _ask(
        "containment_rewrite", inputs, guard_home, validate, deadline, HOOK_DECISION_CONTAINMENT_REWRITE_FEATURE
    )
    return ContainmentRewrite(answer["profile"], answer["kept_because"], answer["response"])


def _tool_input(payload: Mapping[str, object]) -> object:
    return payload.get("tool_input", payload.get("toolInput"))


def _receipt_facts(
    response: Mapping[str, object], *, harness: str, bridge: bool, payload: Mapping[str, object]
) -> dict[str, object]:
    if not isinstance(harness, str):
        raise NativeHookDecisionError(_INVALID)
    return {
        "harness": harness,
        "platform": host_platform(),
        "bridge": bool(bridge),
        "receipt_only": payload.get(_RECEIPT_ONLY_FIELD) is True,
        "event_name": _text(payload.get("hook_event_name", payload.get("hookEventName"))),
        "tool_name": _text(payload.get("tool_name", payload.get("toolName"))),
        "decision": _text(response.get("decision")),
        "policy_action": _text(response.get("policy_action")),
        "reason_code": _text(response.get("reason_code")),
        "required_execution_profile": _text(response.get("required_execution_profile")),
        "observe_mode": response.get("observe_mode") is True,
    }


def _validate_sink(answer: Mapping[str, Any], inputs: Mapping[str, object]) -> None:
    profile, kept_because = answer["profile"], answer["kept_because"]
    if profile is None:
        if not isinstance(kept_because, str) or kept_because not in _KEPT_BECAUSE:
            raise NativeHookDecisionError(_INVALID)
    elif kept_because is not None or profile != inputs["required_execution_profile"]:
        # The sink runs the profile the receipt names, never another.
        raise NativeHookDecisionError(_INVALID)


def _routed_shape(routed: object, original: object) -> bool:
    """The allow runs only a new command line; every other field is the call's own."""

    if not isinstance(routed, dict) or not isinstance(original, dict):
        return False
    output = routed.get("hookSpecificOutput")
    if (
        set(routed) != {"policy_action", "reason_code", "hookSpecificOutput"}
        or routed["policy_action"] != "allow"
        or routed["reason_code"] != _ROUTED_REASON
        or not isinstance(output, dict)
        or set(output) != {"hookEventName", "permissionDecision", "updatedInput"}
        or output["hookEventName"] != "PreToolUse"
        or output["permissionDecision"] != "allow"
    ):
        return False
    updated = output["updatedInput"]
    if not isinstance(updated, dict) or not isinstance(updated.get("command"), str):
        return False
    return {**updated, "command": None} == {**original, "command": None}


__all__ = [
    "HOOK_DECISION_CONTAINMENT_REWRITE_FEATURE",
    "HOOK_DECISION_CONTAINMENT_ROUTE_FEATURE",
    "ContainmentRewrite",
    "ContainmentSink",
    "edge_containment_route",
    "host_platform",
    "native_containment_rewrite",
    "native_containment_route",
    "native_containment_sink",
]
