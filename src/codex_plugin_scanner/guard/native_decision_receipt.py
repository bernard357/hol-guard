"""Thin transport to the native runtime's hook decision receipt check."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from .native_context import _resolve_digest_home, native_context_digest


def _native_receipt_valid(receipt: Mapping[str, object], edge: Mapping[str, object] | None) -> bool:
    result = native_context_digest(
        "native_decision_receipt_validation",
        {"receipt": dict(receipt), "edge": dict(edge) if edge is not None else None},
        guard_home=_resolve_digest_home(None),
    )
    return isinstance(result, dict) and result.get("native_decision_receipt_valid") is True


def validate_native_decision_receipt(value: object) -> dict[str, object] | None:
    """Copy one Rust receipt the native runtime accepts; anything else is ``None``."""

    if not isinstance(value, Mapping):
        return None
    receipt = dict(cast(Mapping[str, object], value))
    return receipt if _native_receipt_valid(receipt, None) else None


def receipt_matches_edge(payload: Mapping[str, object], receipt: object) -> bool:
    """Whether the native runtime accepts the receipt as a record of this edge result."""

    edge = {
        key: payload[key]
        for key in ("harness", "event_name", "payload_kind", "request_id", "result")
        if payload.get(key) is not None
    }
    return isinstance(receipt, Mapping) and _native_receipt_valid(cast(Mapping[str, object], receipt), edge)


__all__ = [
    "receipt_matches_edge",
    "validate_native_decision_receipt",
]
