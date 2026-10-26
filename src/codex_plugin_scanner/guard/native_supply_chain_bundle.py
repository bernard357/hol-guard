"""Resident bridge for the ``supply_chain_bundle_verify`` op.

Rust owns whether a signed supply-chain bundle holds: the canonical payload
hash, rollback against the version already cached, freshness, the keyring the
signing key must anchor to, that key's rotation state, and the RSA-PSS
signature. This module ships the response as it was fetched or cached together
with the caller's trusted keyring, binds the reply by ``request_id`` plus
``request_sha256`` and re-raises the refusal class the resident named. Nothing
is re-decided here, so a resident that cannot answer leaves the bundle
unverified rather than accepted.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload
from .runtime.supply_chain_bundle_base import (
    SupplyChainBundleError,
    SupplyChainBundleExpiredError,
    SupplyChainBundleKeyringError,
    SupplyChainBundleMalformedError,
    SupplyChainBundlePayloadHashError,
    SupplyChainBundleRollbackError,
    SupplyChainBundleSignatureError,
)

SUPPLY_CHAIN_BUNDLE_VERIFY_FEATURE = "supply-chain-bundle-verify-v1"
_REQUEST_SCHEMA = "guard-supply-chain-bundle-verify-request.v1"
_RESULT_SCHEMA = "guard-supply-chain-bundle-verify-result.v1"
_TIMEOUT_SECONDS = 15.0
_MAX_REQUEST_BYTES = 6 * 1024 * 1024

_REFUSAL_CLASSES: dict[str, type[SupplyChainBundleError]] = {
    "signature": SupplyChainBundleSignatureError,
    "expired": SupplyChainBundleExpiredError,
    "rollback": SupplyChainBundleRollbackError,
    "malformed": SupplyChainBundleMalformedError,
    "payload_hash": SupplyChainBundlePayloadHashError,
    "keyring": SupplyChainBundleKeyringError,
}


class SupplyChainBundleUnavailableError(SupplyChainBundleError):
    """The verifier could not be reached, so the bundle is not verified.

    A ``SupplyChainBundleError``, because every caller already treats a failed
    verification that way and an unreachable verifier must not read as a pass.
    """

    def __init__(self) -> None:
        super().__init__("Supply-chain bundle verification is unavailable")


def native_verify_supply_chain_bundle_response(
    response: Mapping[str, object],
    *,
    trusted_keys: Sequence[Mapping[str, object]] | None = None,
    cached_bundle_version: str | None = None,
    now: float | None = None,
    guard_home: Path | None = None,
) -> None:
    """Return when the resident verified the bundle; raise when it did not.

    ``response`` is the bundle response in its wire form, unaltered, because
    the resident recomputes the canonical payload over it. ``trusted_keys``
    carries the saved keyring in the same wire form; ``None`` accepts the
    keyring the response advertises, which only a caller that has not saved
    one yet should send.
    """

    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise SupplyChainBundleUnavailableError
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"supply-chain-bundle-verify-{uuid4().hex}",
        "response": dict(response),
        "trusted_keys": [dict(key) for key in trusted_keys] if trusted_keys is not None else None,
        "cached_bundle_version": cached_bundle_version,
        "now": now,
    }
    try:
        reply = _resident_request(
            operation="supply_chain_bundle_verify",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=SUPPLY_CHAIN_BUNDLE_VERIFY_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise SupplyChainBundleUnavailableError from None
    answer = _payload(reply, wire, home)
    if not isinstance(answer, dict):
        raise SupplyChainBundleUnavailableError
    outcome = answer.get("outcome")
    if outcome == "refused":
        kind = answer.get("kind")
        message = answer.get("message")
        error_class = _REFUSAL_CLASSES.get(kind if isinstance(kind, str) else "", SupplyChainBundleError)
        raise error_class(message if isinstance(message, str) else "Supply-chain bundle is refused")
    if outcome != "verified":
        raise SupplyChainBundleUnavailableError
