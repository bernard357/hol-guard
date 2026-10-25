"""Sync context for runtime advisories carried in the cached supply-chain bundle.

Hands the native assessment the stored bundle response, the recorded sync
keyring and the last synced bundle version. The native runtime verifies the
bundle before any advisory reaches matching; nothing here trusts or parses
the advisory section itself. Reads the local store only, never Cloud.
"""

from __future__ import annotations

import time
from typing import Any

BUNDLE_SCOPE_MISMATCH = "runtime_advisory_bundle_scope_mismatch"
NOT_CONNECTED = "runtime_advisory_bundle_not_connected"
NOT_CACHED = "runtime_advisory_bundle_not_cached"


def cached_advisory_bundle(store: Any, *, now: float | None = None) -> tuple[dict[str, object] | None, str | None]:
    """Return the native ``cached_bundle`` input, or ``None`` with the reason there is none."""

    workspace_id = store.get_cloud_workspace_id()
    if not isinstance(workspace_id, str) or not workspace_id:
        return None, NOT_CONNECTED
    entitlement = store.get_sync_payload("supply_chain_bundle_entitlement")
    synced_version: str | None = None
    if isinstance(entitlement, dict):
        # A recorded sync for another workspace cannot vouch for this cache.
        if entitlement.get("workspace_id") != workspace_id:
            return None, BUNDLE_SCOPE_MISMATCH
        version = entitlement.get("bundle_version")
        synced_version = version if isinstance(version, str) and version else None
    cached = store.get_cached_supply_chain_bundle(workspace_id)
    if not isinstance(cached, dict):
        return None, NOT_CACHED
    response = {key: value for key, value in cached.items() if key != "cached_at"}
    keyring = store.get_sync_payload("supply_chain_bundle_keyring")
    return {
        "response": response,
        "workspace_id": workspace_id,
        "sync_keyring": keyring,
        "synced_bundle_version": synced_version,
        "now": time.time() if now is None else now,
    }, None


__all__ = ["BUNDLE_SCOPE_MISMATCH", "NOT_CACHED", "NOT_CONNECTED", "cached_advisory_bundle"]
