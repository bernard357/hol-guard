"""Project the native pre-tool command model into the Python value type.

The Rust runtime parses the command, owns its structure and binds the model to
the request: ``native_pretool`` refuses a reply whose normalized text is not
the request's. Python only presents that model; it does not re-derive
executables, wrappers or environment names. Command PreToolUse authority lives
in the Rust runtime and native_pretool transport.
"""

from __future__ import annotations

from typing import Any

from .runtime.command_model import CanonicalCommand, _canonical_from_wire

_IDENTITY_PREFIX = "command-security-v2:"
_HEX_DIGITS = frozenset("0123456789abcdef")
_REQUEST_SHAPE = {"dialect": "posix", "transport": "shell_string", "extraction_provenance": "guard-shell"}


def _valid_identity(identity: object) -> bool:
    if not isinstance(identity, str) or not identity.startswith(_IDENTITY_PREFIX):
        return False
    digest = identity.removeprefix(_IDENTITY_PREFIX)
    return len(digest) == 64 and set(digest) <= _HEX_DIGITS


def _canonical_command_from_native(
    command: str,
    payload: dict[str, Any],
) -> CanonicalCommand | None:
    """Present an exact native model as ``CanonicalCommand``, or None when it is malformed."""
    if any(payload.get(name) != value for name, value in _REQUEST_SHAPE.items()):
        return None
    if payload.get("confidence") not in {"exact", "uncertain"}:
        return None
    identity = payload.get("security_identity")
    if identity is not None and not _valid_identity(identity):
        return None
    value = {
        **payload,
        "raw_text": command.strip(),
        "redirects": [],
        "embedded_commands": [],
        # Older exact payloads omit the identity; keep their lazy API.
        "security_identity": identity or "",
    }
    try:
        canonical = _canonical_from_wire(value)
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    if payload.get("path_overridden") is not canonical.path_overridden:
        return None
    if identity is None:
        object.__setattr__(canonical, "_bound_identity", None)
    return canonical
