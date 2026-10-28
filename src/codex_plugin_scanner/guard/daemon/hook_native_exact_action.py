"""Exact-action identity and review binding answered by the native runtime.

A persistent "Always" decision needs an identity that survives new sessions
while changing whenever the code that would run, the files it reads, the git
configuration it would consult or the Rust rules that judged it change. The
short-lived retry binding of one native review needs the Rust request digest.
The resident (``native_exact_action``) owns every one of those proofs, and
reads the hook payload, native verdict and receipt they are proved from.

Python transports only the facts it holds: the ambient environment and the
extension-control digest. There is no Python fallback: when the resident
cannot answer, no persistent token is available. The separate delivery
contract decides whether a once retry is executable.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY
from ..native_daemon_route import EXACT_ACTION_ASK_SLOTS, _decide
from ..native_resident_decision import ResidentOperation
from ..runtime.extension_control_runtime import current_extension_control_binding_digest
from .hook_native_review_binding import native_review_policy_binding

# The hook-review ask; residents advertise it beside v4 and v5.
NATIVE_EXACT_ACTION_FEATURE = "native-exact-action-v6"
UNPROVEN_LAUNCH = "unproven_launch"
_LOGGER = logging.getLogger(__name__)
_TIMEOUT_SECONDS = 6.0
_BUDGET_MS = 4000
# A hook review carries the whole hook payload, which the hook bridges cap at
# 1 MB; the resident accepts it up to 4 MiB.
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
# Native action types for changes to Guard itself; the resident judges them, and
# the saved-decision path still skips them without asking.
GUARD_CONTROL_ACTION_TYPES = frozenset(
    {"guard_control", "guard-control", "guard_control_operation", "guard-control-operation"}
)
_ONCE_ONLY_REASONS = frozenset(
    {
        "no_command_identity",
        "mutable_launcher",
        "compound_command",
        "guard_control",
        "package_action",
        "non_overridable",
        "unproven_launch",
        "sensitive_path",
        "broad_scope",
        "destructive_command",
        "git_helper_config",
        "node_package_manifest_unproven",
        "node_package_entrypoint_unproven",
        "node_package_exports_unproven",
        "node_package_native_addon_unproven",
        "node_runtime_package_mutation_unproven",
        "runner_code_closure_unproven",
        "python_runtime_module_unproven",
        "python_runtime_bootstrap_unproven",
        "script_execution_binding_unavailable",
    }
)


class NativeExactActionError(RuntimeError):
    """No authoritative answer; ``code`` says why, for diagnostics only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_OPERATION = ResidentOperation(
    operation="native_exact_action",
    feature=NATIVE_EXACT_ACTION_FEATURE,
    prefix="native_exact_action",
    request_schema="guard-native-exact-action-request.v1",
    request_id_prefix="native-exact-action",
    result_schema="guard-native-exact-action-result.v1",
    timeout_seconds=_TIMEOUT_SECONDS,
    error=NativeExactActionError,
)


def launch_cwd(payload: Mapping[str, object], workspace: Path | None) -> Path | None:
    """The absolute, existing directory a hook action would launch in."""

    raw = payload.get("cwd")
    candidate = Path(raw) if isinstance(raw, str) and raw.strip() else workspace
    if candidate is None or not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved if os.path.isdir(resolved) else None


def launch_path(payload: Mapping[str, object]) -> str | None:
    """The ``PATH`` the hook stamped from the agent's own environment, if any."""

    stamped = payload.get(HOOK_EXECUTION_ENVIRONMENT_KEY)
    path = stamped.get("path") if isinstance(stamped, Mapping) else None
    return path if isinstance(path, str) and path and "\0" not in path else None


def native_review_evidence(
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
    guard_home: Path | None = None,
) -> tuple[bool, str | None, str | None, str | None]:
    """Whether the review's policy binding holds, its retry binding, exact-action token and once-only reason.

    The resident reads the hook payload, the native verdict and its receipt
    into both the retry-binding and the exact-action query, checks the
    receipt's policy binding once, and answers each half exactly as its own
    query would. When it cannot answer, the receipt check still decides
    whether the review may be offered, and the review stays once-only.
    """

    try:
        reply = _decide(
            _hook_review_query(
                harness=harness,
                payload=payload,
                native_result=native_result,
                native_receipt=native_receipt,
                workspace=workspace,
                home_dir=home_dir,
            ),
            guard_home,
            {
                "policy_binding_valid": bool,
                "binding": (str, type(None)),
                "token": (str, type(None)),
                "once_only_reason": (str, type(None)),
            },
            _validate_exact_action,
            operation=_OPERATION,
            max_request_bytes=_MAX_REQUEST_BYTES,
            slots=EXACT_ACTION_ASK_SLOTS,
        )
    except (NativeExactActionError, OSError, RuntimeError, TypeError, ValueError) as error:
        # Only the error class is logged: the query holds environment and command text.
        _LOGGER.warning("native review-evidence ask failed closed: %s", type(error).__name__)
        return _policy_binding_valid(harness, native_result, native_receipt), None, None, UNPROVEN_LAUNCH
    token, reason = reply["token"], reply["once_only_reason"]
    if (token is None) == (reason is None):
        token, reason = None, UNPROVEN_LAUNCH
    return reply["policy_binding_valid"], reply["binding"], token, reason


def _hook_review_query(
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
) -> dict[str, object]:
    return {
        "kind": "hook_review",
        "harness": harness,
        "payload": dict(payload),
        "result": dict(native_result),
        "receipt": dict(native_receipt) if isinstance(native_receipt, Mapping) else None,
        "workspace": _text(workspace),
        "home_dir": _text(home_dir),
        "environment": {key: value for key, value in os.environ.items() if isinstance(value, str)},
        "extension_control_digest": current_extension_control_binding_digest(),
        "budget_ms": _BUDGET_MS,
    }


def _policy_binding_valid(
    harness: str, native_result: Mapping[str, object], native_receipt: Mapping[str, object] | None
) -> bool:
    try:
        native_review_policy_binding(harness=harness, native_result=native_result, verified_receipt=native_receipt)
    except ValueError:
        return False
    return True


def _text(value: object) -> str | None:
    return str(value) if value is not None else None


def _validate_exact_action(payload: dict[str, Any]) -> None:
    reason = payload["once_only_reason"]
    if reason is not None and reason not in _ONCE_ONLY_REASONS:
        raise NativeExactActionError(_OPERATION.invalid)


__all__ = [
    "GUARD_CONTROL_ACTION_TYPES",
    "NATIVE_EXACT_ACTION_FEATURE",
    "UNPROVEN_LAUNCH",
    "NativeExactActionError",
    "launch_cwd",
    "launch_path",
    "native_review_evidence",
]
