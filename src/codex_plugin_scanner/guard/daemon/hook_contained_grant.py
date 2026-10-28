"""Route an outside-roots review the local CLI grant covers into the workspace sandbox.

Rust reviews a command the workspace sandbox cannot run because its program
lives outside the sandbox's executable roots. When this device allowed that
CLI, the grant does not lift the review to ``allow``: the command runs in the
sandbox widened by the grant (``workspace-contained-grant-v1``). The sink asks
the store for the grant again itself, so nothing here is trusted beyond the
routing. A blocked or undecided CLI, or a call the sink cannot take, keeps the
review.

The sandbox requirement itself is the resident's: it answers the grant step
with the review fields the command is routed to, and this module copies them.
A resident that cannot be reached sends no route, so the review stands.

Whether a result is eligible at all is the resident's ``containment_route``
answer (``grant``); callers ask it first. Whether the sink takes the rendered
receipt is its ``containment_sink`` answer.

A resident edge that answered the grant itself marks its answer
(``containment_rewrite``); only an unmarked edge is asked here.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ..native_hook_containment_route import edge_routed_shape, native_containment_rewrite
from ..native_hook_decision import NativeHookDecisionError
from .hook_fail_closed import render_pre_tool
from .hook_native_exact_action import launch_cwd, launch_path
from .hook_request_parsing import pre_tool_command

if TYPE_CHECKING:
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)
OUTSIDE_ROOTS_REASON = "native_workspace_containment_executable_outside_roots"
# The edge's grant answers: its response is the routed allow or the granted
# receipt, and ``declined`` keeps the review.
_EDGE_GRANT_ANSWERS = frozenset({"routed", "kept"})
_EDGE_GRANT_DECLINED = "declined"
_EDGE_REWRITE_INVALID = "native_containment_rewrite_invalid"


def granted_containment_result(
    store: GuardStore,
    result: Mapping[str, object],
    *,
    payload: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
) -> dict[str, object] | None:
    """The sandbox requirement an allowed grant turns an outside-roots review into.

    ``result`` is one the resident routed to the grant: an outside-roots review
    the saved-approval path could also override. A Guard control or package
    action never gets here, whatever the grant.
    """
    command = pre_tool_command(payload)
    cwd = launch_cwd(payload, workspace)
    if command is None or cwd is None:
        return None
    from ..local_cli_hook import ALLOW_CONTAINED_WITH_GRANT, local_cli_contained_grant

    try:
        decision = local_cli_contained_grant(
            store,
            command=command,
            cwd=cwd,
            home_dir=home_dir,
            current_action="review",
            reason_code=OUTSIDE_ROOTS_REASON,
            path=launch_path(payload),
        )
    except Exception:
        _LOGGER.warning("local CLI grant lookup failed", exc_info=True)
        return None
    if decision is None or decision[0] != ALLOW_CONTAINED_WITH_GRANT or decision[1] is None:
        return None
    route = decision[2]
    if route is None:
        return None
    return {**result, **route}


def granted_containment_response(
    store: GuardStore,
    result: Mapping[str, object],
    *,
    harness: str,
    payload: Mapping[str, object],
    guard_home: Path,
    home_dir: Path,
    workspace: Path | None,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """The contained-sink rewrite for a granted outside-roots review, or ``None`` to keep it.

    A receipt-only call is the sink re-authorizing, so it gets the sandbox
    receipt itself; any other call is answered only when the sink takes it.
    No resident answer raises ``NativeHookDecisionError``.
    """
    granted = granted_containment_result(store, result, payload=payload, workspace=workspace, home_dir=home_dir)
    if granted is None:
        return None
    from ..adapters.zcode_contained_tests import contained_sink_command_prefix

    receipt = render_pre_tool(harness, granted, guard_home=guard_home, deadline=deadline)
    rewrite = native_containment_rewrite(
        receipt,
        harness=harness,
        bridge=False,
        payload=payload,
        workspace=workspace,
        guard_home=guard_home,
        home_dir=home_dir,
        sink_command=contained_sink_command_prefix(),
        deadline=deadline,
    )
    if rewrite.kept_because == "receipt_only":
        return receipt
    return rewrite.response


def edge_granted_containment_response(
    edge: Mapping[str, object],
    store: GuardStore,
    result: Mapping[str, object],
    *,
    harness: str,
    payload: Mapping[str, object],
    guard_home: Path,
    home_dir: Path,
    workspace: Path | None,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """The edge's grant answer when it marked one, else ``granted_containment_response``.

    The decoder accepts a grant mark only on a grant route, so a marked edge
    already ran the grant step, the receipt render and the rewrite this would.
    """
    answer = edge.get("containment_rewrite")
    if answer in _EDGE_GRANT_ANSWERS:
        response = edge.get("harness_response")
        if not isinstance(response, Mapping):
            raise ValueError("native_hook_edge_invalid_response")
        # A routed allow is held to the shape the resident's answer is.
        if answer == "routed" and not edge_routed_shape(response, payload):
            raise NativeHookDecisionError(_EDGE_REWRITE_INVALID)
        return {str(key): value for key, value in response.items()}
    if answer == _EDGE_GRANT_DECLINED:
        return None
    return granted_containment_response(
        store,
        result,
        harness=harness,
        payload=payload,
        guard_home=guard_home,
        home_dir=home_dir,
        workspace=workspace,
        deadline=deadline,
    )


__all__ = ["edge_granted_containment_response", "granted_containment_response", "granted_containment_result"]
