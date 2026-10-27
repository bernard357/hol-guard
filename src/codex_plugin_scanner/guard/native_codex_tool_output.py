"""Resident bridge for the ``codex_tool_output`` op.

The runtime forwards one command (or several post-tool commands) plus observed
facts (process directory, home, account home, groups, a bounded environment
snapshot and the resolved ``git`` executable) to the resident. Rust owns every
verdict: read-only source inspection, secret-like source names, git pathspec
identities, local-content reads, focused pytest and git metadata. This module
never inspects command text, paths or Git state; any transport failure,
malformed result, or missing capability returns a denying answer carrying a
typed error code. There is no Python fallback.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import shutil
import sys
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

from . import native_git_execution_safety as _git_safety
from .native_path_anchor import anchor_to_process_directory
from .native_resident_decision import BoundCall, ResidentCallError, bound_resident_call

# The largest envelope a post-tool review will frame, which is more than
# ``CODEX_POST_TOOL_OUTPUT_MAX_BYTES``: that bound counts the op's own canonical
# request and this counts the envelope around it. Held under the transport's
# frame limit so a request past it is refused for its size rather than as a
# malformed frame.
_MAX_POST_TOOL_REQUEST_BYTES = 6 * 1024 * 1024 - 64 * 1024
# The resident derives the post-tool command texts from the payload itself.
_POST_TOOL_COMMANDS_FEATURE = "codex-post-tool-commands-v1"
_POST_TOOL_PAYLOAD_KINDS = frozenset({"post_tool_output", "post_tool_read_only_payload"})
_REQUEST_SCHEMA = "guard-codex-tool-output-request.v1"
_RESULT_SCHEMA = "guard-codex-tool-output-result.v1"
_DEFAULT_TIMEOUT_SECONDS = 8.0
_CALL = BoundCall(
    operation="codex_tool_output",
    feature="codex-tool-output-v1",
    prefix="native_codex_tool_output",
    result_schema=_RESULT_SCHEMA,
    max_request_bytes=256 * 1024,
    timeout_seconds=_DEFAULT_TIMEOUT_SECONDS,
    check_circuit=True,
)
_LARGE_CALL = replace(_CALL, max_request_bytes=_MAX_POST_TOOL_REQUEST_BYTES)
_UNAVAILABLE = "native_codex_tool_output_unavailable"
_UNSUPPORTED_PLATFORM = "native_codex_tool_output_unsupported_platform"
# The bridge's own codes for a request it never sends: one that cannot be
# encoded is invalid, and one over the limit reads as an unavailable runtime.
_LOCAL_REFUSALS = {
    "native_codex_tool_output_component_unencodable": "native_codex_tool_output_invalid",
    "native_codex_tool_output_request_too_large": _UNAVAILABLE,
}
_EXTRA_SNAPSHOT_NAMES = frozenset({"RIPGREP_CONFIG_PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMP", "TEMP", "TMPDIR"})

_request_counter = 0


@dataclass(frozen=True)
class ToolOutputAnswer:
    """The resident's verdict, or a denial with a typed error code."""

    allowed: bool
    value: str | None = None
    error_code: str | None = None


def _deny(code: str) -> ToolOutputAnswer:
    return ToolOutputAnswer(False, None, code)


def _platform_is_supported() -> bool:
    # The review models POSIX shell text and POSIX paths; Windows drive and UNC
    # roots are not represented, so Windows is refused instead of guessed at.
    return sys.platform != "win32"


def _environment_snapshot() -> dict[str, str]:
    snapshot = _git_safety._environment_snapshot()
    snapshot.update({key: value for key, value in os.environ.items() if key in _EXTRA_SNAPSHOT_NAMES})
    return snapshot


def _anchored(path: str | os.PathLike[str] | None) -> str | None:
    return None if path is None else anchor_to_process_directory(path)


def _packed_body(body: dict[str, object]) -> dict[str, object]:
    raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    packed = base64.b64encode(gzip.compress(raw, compresslevel=1, mtime=0)).decode("ascii")
    return {"packed_json_gzip_v1": packed, "decoded_bytes": len(raw)}


def codex_tool_output_native(
    kind: str,
    *,
    command: str | None = None,
    commands: Iterable[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    home_dir: str | os.PathLike[str] | None = None,
    exec_context: bool = False,
    body: dict[str, object] | None = None,
    prompt_text: str | None = None,
    config_path: str | os.PathLike[str] | None = None,
    deadline_ms: int = 0,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> ToolOutputAnswer:
    """Ask the resident for one Codex tool-output verdict."""

    global _request_counter
    if not _platform_is_supported():
        return _deny(_UNSUPPORTED_PLATFORM)
    try:
        action: dict[str, object] = {"kind": kind}
        if kind in _POST_TOOL_PAYLOAD_KINDS:
            action["body"] = _packed_body(body or {})
        elif kind == "post_tool_read_only":
            action.update({"commands": list(commands or ()), "cwd": _anchored(cwd), "home_dir": _anchored(home_dir)})
        elif kind in {"read_only_inspection", "secret_like_source_name"}:
            action.update({"command": command, "cwd": _anchored(cwd), "home_dir": _anchored(home_dir)})
            if kind == "secret_like_source_name":
                action["exec_context"] = exec_context
        elif kind == "prompt_credential_file":
            action.update(
                {
                    "prompt_text": prompt_text or "",
                    "cwd": _anchored(cwd),
                    "config_path": str(config_path or ""),
                    "deadline_ms": int(deadline_ms),
                }
            )
        elif kind == "prompt_attachment":
            action.update(
                {
                    "prompt_text": prompt_text or "",
                    "home_dir": str(home_dir or ""),
                    "config_path": str(config_path or ""),
                    "deadline_ms": int(deadline_ms),
                }
            )
        elif kind in {"git_pathspec_identity", "local_content_tail", "git_metadata"}:
            action.update({"command": command, "cwd": _anchored(cwd)})
        else:
            action["command"] = command
        facts: dict[str, object] = {
            "process_cwd": os.getcwd(),
            "home": str(Path.home()),
            "account_home": _git_safety._account_home_directory(),
            "groups": _git_safety._process_groups(),
            "environment": _environment_snapshot(),
            "git_executable": shutil.which("git"),
        }
    except (OSError, RuntimeError):
        return _deny(_UNAVAILABLE)
    except (TypeError, ValueError):
        # Lone surrogates or NaN in the hook payload cannot be encoded.
        return _deny("native_codex_tool_output_invalid")
    _request_counter += 1
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"cto-{os.getpid()}-{_request_counter}",
        "action": action,
        "facts": facts,
    }
    # A harness accepts up to a megabyte of hook input, so a prompt review
    # carries whatever the user pasted. Holding a prompt to the ordinary
    # request limit turned a long one into a blocking "native runtime
    # unavailable" artifact, which is a review the user did not need.
    large = kind in _POST_TOOL_PAYLOAD_KINDS or kind in {"prompt_credential_file", "prompt_attachment"}
    try:
        reply = bound_resident_call(
            _LARGE_CALL if large else _CALL,
            request,
            timeout_seconds=timeout_seconds,
            extra_features=(_POST_TOOL_COMMANDS_FEATURE,) if kind in _POST_TOOL_PAYLOAD_KINDS else (),
        )
    except ResidentCallError as error:
        return _deny(_LOCAL_REFUSALS.get(str(error), str(error)))
    envelope = reply.envelope
    if not isinstance(envelope.get("allowed"), bool):
        return _deny(str(reply.fail()))
    reply.healthy()
    if envelope.get("status") != "ok" or envelope.get("code") != "ok":
        code = envelope.get("code")
        return _deny(code if isinstance(code, str) else "native_codex_tool_output_invalid")
    result_value = envelope.get("value")
    return ToolOutputAnswer(bool(envelope["allowed"]), result_value if isinstance(result_value, str) else None)
